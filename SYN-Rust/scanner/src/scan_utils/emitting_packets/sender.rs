use crate::scan_utils::shared::helper::{
    self, find_fitting_ethernet_ifindex, find_interface_index_by_name,
};
use crate::scan_utils::shared::types_and_config::{
    DONE, EmissionConfig, FINISH, ReceiverChan, ScanErr, ScannerErrWithMsg,
};
use nix::libc::{self};
use nix::sys::socket::SockaddrLike;
use nix::sys::socket::{
    AddressFamily, LinkAddr, MsgFlags, MultiHeaders, SockFlag, SockProtocol, SockType, sendmmsg,
    sendto, socket,
};
use pnet::util::MacAddr;
use std::io::IoSlice;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{self, Instant};
// use tokio::sync::oneshot::Receiver as OneshotReceiver;

#[derive(Debug)]
pub struct PacketSender {
    config: Arc<EmissionConfig>,
    count_packets: Arc<AtomicUsize>,
}

struct Cleanup {
    pub tx_sender_done: Sender<String>,
}

// TODO if Ok send DONE if Err send FINISH
impl Drop for Cleanup {
    fn drop(&mut self) {
        // send message to start timeout for capturing packets
        if let Err(e) = self
            .tx_sender_done
            .blocking_send(DONE.to_string())
            .map_err(|e| ScannerErrWithMsg {
                err: ScanErr::Sending,
                msg: format!("Error sending assembling done Signal {:?}", e),
            })
        {
            eprintln!("{:?}: {}", e.err, e.msg);
        };
    }
}

pub const ASSEMBLING_FINSIH_EXPECTED_MSG: &str = "Sending stopped - assembling finish expected";

impl PacketSender {
    pub async fn start_sending(
        receiver_list: ReceiverChan,
        emission_config: Arc<EmissionConfig>,
        tx_notify_capturer: Sender<String>,
        mut tx_sockets: Option<Vec<xdp_socket::socket::Socket<true>>>,
    ) -> Result<(), ScannerErrWithMsg> {
        // initialize packet sender
        let count_packets = Arc::new(AtomicUsize::new(0));
        let packet_sender = Arc::new(Self {
            config: emission_config.clone(),
            count_packets: count_packets.clone(),
        });
        let mut handles = Vec::new();
        let mut sync_handles = Vec::new();

        let (mut tx_sending_done_channels, rx_sending_done_channels) =
            helper::create_done_channels(emission_config.num_nic_queues);
        let (tx_stop_logging, rx_stop_logging) = tokio::sync::mpsc::channel(10);

        // SENDING SPEED TEST
        let count_packets_clone = count_packets.clone();
        let scan_rate = emission_config.scan_rate;
        let handle = tokio::spawn(async move {
            PacketSender::log_sending_speed(rx_stop_logging, count_packets_clone, scan_rate);
        });
        handles.push(handle);

        let packet_sender_clone = packet_sender.clone();
        let handle = tokio::spawn(async move {
            packet_sender_clone
                .start_sending_done_listener(
                    rx_sending_done_channels,
                    tx_stop_logging,
                    tx_notify_capturer,
                )
                .await;
        });
        handles.push(handle);

        let core_ids = core_affinity::get_core_ids().ok_or(ScannerErrWithMsg {
            err: ScanErr::Config,
            msg: "Could not retrieve core IDs for thread pinning".to_string(),
        })?;

        if emission_config.xdp {
            eprintln!("waiting for socket initialization...");
            std::thread::sleep(Duration::from_micros(3000));
        }

        match receiver_list {
            ReceiverChan::PacketList(packet_receiver_channels) => {
                for (current_nic_queue, rx_packets_to_send) in
                    packet_receiver_channels.into_iter().enumerate()
                {
                    let tx_sender_done = tx_sending_done_channels.remove(0);
                    let core_id = *core_ids.get(current_nic_queue % core_ids.len()).ok_or(
                        ScannerErrWithMsg {
                            err: ScanErr::Config,
                            msg: "Core ID List is empty".to_string(),
                        },
                    )?;

                    let packet_sender_clone = packet_sender.clone();
                    let socket_opt = if let Some(sockets) = &mut tx_sockets {
                        if !sockets.is_empty() {
                            Some(sockets.remove(0))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let handle = thread::spawn(move || {
                        core_affinity::set_for_current(core_id);
                        // thread_priority::set_current_thread_priority(ThreadPriority::Max)
                        // .expect("Failed to set thread priority");
                        let _cleanup = Cleanup { tx_sender_done };
                        match socket_opt {
                            Some(sock) => {
                                if let Err(e) =
                                    packet_sender_clone.send_xdp_singles(rx_packets_to_send, sock)
                                {
                                    eprintln!("{:?}: {}", e.err, e.msg);
                                };
                            }
                            None => {
                                if let Err(e) =
                                    packet_sender_clone.send_afp_singles(rx_packets_to_send)
                                {
                                    eprintln!("{:?}: {}", e.err, e.msg);
                                };
                            }
                        }
                    });
                    sync_handles.push(handle);
                }
            }
            ReceiverChan::BatchList(batch_receiver_channels) => {
                for (current_nic_queue, rx_batches_to_send) in
                    batch_receiver_channels.into_iter().enumerate()
                {
                    let tx_sender_done = tx_sending_done_channels.remove(0);
                    let core_id = *core_ids.get(current_nic_queue % core_ids.len()).ok_or(
                        ScannerErrWithMsg {
                            err: ScanErr::Config,
                            msg: "Core ID List is empty".to_string(),
                        },
                    )?;
                    let packet_sender_clone = packet_sender.clone();
                    let socket_opt = if let Some(sockets) = &mut tx_sockets {
                        if !sockets.is_empty() {
                            Some(sockets.remove(0))
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    let handle = thread::spawn(move || {
                        core_affinity::set_for_current(core_id);
                        // thread_priority::set_current_thread_priority(ThreadPriority::Max)
                        //     .expect("Failed to set thread priority");
                        let _cleanup = Cleanup { tx_sender_done };
                        match socket_opt {
                            Some(sock) => {
                                if let Err(e) =
                                    packet_sender_clone.send_xdp_batches(rx_batches_to_send, sock)
                                {
                                    eprintln!("{:?}: {}", e.err, e.msg);
                                };
                            }
                            None => {
                                if let Err(e) =
                                    packet_sender_clone.send_afp_batches(rx_batches_to_send)
                                {
                                    eprintln!("{:?}: {}", e.err, e.msg);
                                }
                            }
                        }
                    });
                    sync_handles.push(handle);
                }
            }
            _ => unreachable!("ReceiverChan must be PacketList or BatchList for sender threads!"),
        }

        // sleep before sending done signal in cleanup, so receiver has time to collect packets
        thread::sleep(Duration::from_millis(
            emission_config.parsing_timeout_millis,
        ));

        Ok(())
    }

    fn create_dummy_packet(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 64];
        let mut eth_packet =
            pnet::packet::ethernet::MutableEthernetPacket::new(&mut buffer).unwrap();

        eth_packet.set_destination(self.config.dst_mac);
        eth_packet.set_source(self.config.src_mac);
        eth_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

        buffer
    }

    fn flush_xdp(&self, sock: &mut xdp_socket::socket::TxSocket) -> Result<(), ScannerErrWithMsg> {
        let packet = self.create_dummy_packet();
        let mut sent = 0;

        while sent < 5000 {
            match sock.seek_and_peek(packet.len()) {
                Ok(b) => {
                    b.copy_from_slice(&packet);
                    if let Err(e) = sock.commit() {
                        eprintln!("Flush xdp commit error: {:?}", e);
                    }
                    if let Err(e) = sock.kick() {
                        eprintln!("Flush xdp kick error: {:?}", e);
                    }
                    sent += 1;
                }
                Err(_) => {
                    if let Err(e) = sock.kick() {
                        eprintln!("Flush xdp kick error: {:?}", e);
                    }
                    std::thread::yield_now();
                }
            }
        }
        std::thread::sleep(Duration::from_micros(1000));
        std::thread::yield_now();
        std::thread::sleep(Duration::from_micros(1000));
        std::thread::yield_now();

        Ok(())
    }

    fn send_xdp_batches(
        self: Arc<Self>,
        mut batches_to_send: Receiver<Vec<Vec<u8>>>,
        mut sock: xdp_socket::socket::TxSocket,
    ) -> Result<(), ScannerErrWithMsg> {
        let mut batch_buf: Vec<Vec<Vec<u8>>> = Vec::with_capacity(32);

        loop {
            let count = batches_to_send.blocking_recv_many(&mut batch_buf, 32);
            if count == 0 {
                if self.config.xdp && !self.config.zero_copy {
                    self.flush_xdp(&mut sock)?;
                    eprintln!("{}. Flushing socket", ASSEMBLING_FINSIH_EXPECTED_MSG);
                } else {
                    eprintln!("{}", ASSEMBLING_FINSIH_EXPECTED_MSG);
                }
                return Ok(());
            }

            for batch in &batch_buf {
                let total = batch.len();
                let mut sent = 0usize;
                let mut congestion_retries = 0;

                while sent < total {
                    let remaining = total - sent;
                    let available = sock.seek_n(remaining).unwrap_or_default();

                    if available == 0 {
                        if let Err(e) = sock.kick() {
                            return Err(ScannerErrWithMsg {
                                err: ScanErr::Sending,
                                msg: format!("Kick error: {:?}", e),
                            });
                        }

                        if congestion_retries < 1 {
                            std::thread::sleep(Duration::from_micros(25));
                        } else {
                            let micros = std::cmp::min((congestion_retries) * 50, 1000) as u64;
                            std::thread::sleep(Duration::from_micros(micros));
                        }

                        congestion_retries += 1;
                        continue;
                    }

                    // Erfolg: Reset Backoff Counter
                    congestion_retries = 0;

                    for i in 0..available {
                        let pkt = &batch[sent + i];
                        match sock.peek_at(i, pkt.len()) {
                            Ok(b) => b.copy_from_slice(pkt),
                            Err(e) => {
                                return Err(ScannerErrWithMsg {
                                    err: ScanErr::Sending,
                                    msg: format!("Error in peek_at: {:?}", e),
                                });
                            }
                        }
                    }

                    if let Err(e) = sock.commit_n(available) {
                        return Err(ScannerErrWithMsg {
                            err: ScanErr::Sending,
                            msg: format!("Error in commit_n: {:?}", e),
                        });
                    }

                    sent += available;
                }

                if let Err(e) = sock.kick() {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Sending,
                        msg: format!("Error in kick: {:?}", e),
                    });
                }

                self.count_packets.fetch_add(sent, Ordering::Relaxed);
            }
            batch_buf.clear();
        }
    }

    fn send_afp_batches(
        self: Arc<Self>,
        mut batches_to_send: Receiver<Vec<Vec<u8>>>,
    ) -> Result<(), ScannerErrWithMsg> {
        let fd = Self::create_afp_socket()?;
        let link_addr = Self::initialize_sock_addr(
            self.config.dst_mac.octets(),
            self.config.interface.clone(),
        )?;

        let mut batch_buf: Vec<Vec<Vec<u8>>> = Vec::with_capacity(32);
        let addr_vec = vec![Some(link_addr); self.config.batch_size];

        loop {
            let count = batches_to_send.blocking_recv_many(&mut batch_buf, 32);
            if count == 0 {
                eprintln!("{}", ASSEMBLING_FINSIH_EXPECTED_MSG);
                return Ok(());
            }

            for batch in &batch_buf {
                let total_packets_in_batch = batch.len();

                let slices_vec: Vec<Vec<IoSlice>> = batch
                    .iter()
                    .map(|pkt| vec![IoSlice::new(pkt.as_slice())])
                    .collect();

                let mut packets_sent_so_far = 0;
                let mut congestion_retries = 0;

                while packets_sent_so_far < total_packets_in_batch {
                    let remaining = total_packets_in_batch - packets_sent_so_far;
                    let current_slices = &slices_vec[packets_sent_so_far..];
                    let current_addrs = &addr_vec[0..remaining];
                    let mut headers = MultiHeaders::<LinkAddr>::preallocate(remaining, None);

                    match sendmmsg(
                        fd.as_raw_fd(),
                        &mut headers,
                        current_slices,
                        current_addrs,
                        [],
                        MsgFlags::empty(),
                    ) {
                        Ok(res) => {
                            packets_sent_so_far += res.count();
                            congestion_retries = 0;
                        }
                        Err(e) => {
                            if e == nix::errno::Errno::ENOBUFS || e == nix::errno::Errno::EAGAIN {
                                if congestion_retries < 1 {
                                    std::thread::sleep(Duration::from_micros(25));
                                } else {
                                    let micros =
                                        std::cmp::min((congestion_retries) * 50, 1000) as u64;
                                    std::thread::sleep(Duration::from_micros(micros));
                                }
                                congestion_retries += 1;
                            } else {
                                return Err(ScannerErrWithMsg {
                                    err: ScanErr::Sending,
                                    msg: format!("Error sending tcp batch {:?}", e),
                                });
                            }
                        }
                    }
                }

                self.count_packets
                    .fetch_add(total_packets_in_batch, Ordering::Relaxed);
            }
            batch_buf.clear();
        }
    }

    fn send_xdp_singles(
        self: Arc<Self>,
        mut packets_to_send: Receiver<Vec<u8>>,
        mut sock: xdp_socket::socket::TxSocket,
    ) -> Result<(), ScannerErrWithMsg> {
        let mut packet_buf: Vec<Vec<u8>> = Vec::with_capacity(64);

        loop {
            let count = packets_to_send.blocking_recv_many(&mut packet_buf, 64);
            if count == 0 {
                return {
                    if self.config.xdp && !self.config.zero_copy {
                        self.flush_xdp(&mut sock)?;
                        eprintln!("{}. Flushing socket", ASSEMBLING_FINSIH_EXPECTED_MSG);
                    } else {
                        eprintln!("{}", ASSEMBLING_FINSIH_EXPECTED_MSG);
                    }
                    Ok(())
                };
            }

            for packet in &packet_buf {
                // TEST
                // eprintln!("Sending packet: |{:?}|", packet);
                let mut congestion_retries = 0;
                loop {
                    let packet_len = packet.len();
                    match sock.seek_and_peek(packet_len) {
                        Ok(b) => {
                            b.copy_from_slice(packet);
                            break;
                        }
                        Err(_e) => {
                            if let Err(e) = sock.kick() {
                                return Err(ScannerErrWithMsg {
                                    err: ScanErr::Sending,
                                    msg: format!("Kick error: {:?}", e),
                                });
                            }

                            if congestion_retries < 3 {
                                std::thread::yield_now();
                            } else {
                                let micros =
                                    std::cmp::min((congestion_retries - 2) * 10, 500) as u64;
                                std::thread::sleep(Duration::from_micros(micros));
                            }
                            congestion_retries += 1;
                        }
                    };
                }
                if let Err(e) = sock.commit() {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Sending,
                        msg: format!("Error in commit: {:?}", e),
                    });
                }
                // FIXME sock.kick() mglw. nur alle n Pakete aufrufen
                if let Err(e) = sock.kick() {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Sending,
                        msg: format!("Error in kick: {:?}", e),
                    });
                }
            }
            packet_buf.clear();
            self.count_packets.fetch_add(count, Ordering::Relaxed);
        }
    }

    fn send_afp_singles(
        self: Arc<Self>,
        mut packets_to_send: Receiver<Vec<u8>>,
    ) -> Result<(), ScannerErrWithMsg> {
        let fd = Self::create_afp_socket()?;
        let link_addr = Self::initialize_sock_addr(
            self.config.dst_mac.octets(),
            self.config.interface.clone(),
        )?;
        let mut packet_buf: Vec<Vec<u8>> = Vec::with_capacity(64);

        loop {
            let count = packets_to_send.blocking_recv_many(&mut packet_buf, 64);
            if count == 0 {
                return {
                    eprintln!("{}", ASSEMBLING_FINSIH_EXPECTED_MSG);
                    Ok(())
                };
            }
            for packet in &packet_buf {
                // TEST
                // eprintln!("Sending packet: |{:?}|", packet);
                let mut congestion_retries = 0;
                loop {
                    match sendto(fd.as_raw_fd(), packet, &link_addr, MsgFlags::empty()) {
                        Ok(_) => break,
                        Err(e) => {
                            if e == nix::errno::Errno::ENOBUFS || e == nix::errno::Errno::EAGAIN {
                                if congestion_retries < 3 {
                                    std::thread::yield_now();
                                } else {
                                    let micros =
                                        std::cmp::min((congestion_retries - 2) * 20, 1000) as u64;
                                    std::thread::sleep(Duration::from_micros(micros));
                                }
                                congestion_retries += 1;
                            } else {
                                return Err(ScannerErrWithMsg {
                                    err: ScanErr::Sending,
                                    msg: format!("Error sending tcp packet {:?}", e),
                                });
                            }
                        }
                    }
                }
            }
            packet_buf.clear();
            // TEST
            self.count_packets.fetch_add(count, Ordering::Relaxed);
        }
    }

    fn create_afp_socket() -> Result<OwnedFd, ScannerErrWithMsg> {
        let fd = match socket(
            AddressFamily::Packet, // AF_PACKET
            SockType::Raw,
            SockFlag::empty(),
            SockProtocol::EthAll,
        ) {
            Ok(fd) => fd,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Socket,
                    msg: format!("Error creating file description {:?}", e),
                });
            }
        };

        unsafe {
            let raw_fd = fd.as_raw_fd();

            // NOTICE if this sockopt is set, you can't see sent packets in tcpdump/wireshark anymore
            let val: i32 = 1;
            let ret = libc::setsockopt(
                raw_fd,
                libc::SOL_PACKET,
                libc::PACKET_QDISC_BYPASS, // Umgeht Traffic Control
                &val as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                eprintln!("Warning: Could not set PACKET_QDISC_BYPASS");
            }

            // Send Buffer erhöhen (32MB), um ENOBUFS zu reduzieren
            let sndbuf_size: i32 = 32 * 1024 * 1024;
            let ret_sndbuf = libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf_size as *const i32 as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret_sndbuf < 0 {
                eprintln!("Warning: Could not set SO_SNDBUF");
            }
        }

        Ok(fd)
    }

    fn initialize_sock_addr(
        dst_mac: [u8; 6],
        interface: String,
    ) -> Result<LinkAddr, ScannerErrWithMsg> {
        // TODO wenn kein interface angegeben automatisch suchen
        let ifindex = match find_interface_index_by_name(&interface) {
            Some(res) => res,
            None => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Socket,
                    msg: String::from("Error finding ethernet interface index"),
                });
            }
        };

        let sock_addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::ETH_P_ALL as u16,
            sll_ifindex: ifindex as i32, // Interface-Index
            sll_hatype: 0, // hardware type: 0 = undefined because interface is defined trough ifindex
            sll_pkttype: 0, // packet type: 0 = PACKET_HOST
            sll_halen: 6,  // length of mac address
            sll_addr: [
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 0, 0,
            ], // destination mac address
        };

        // unsafe, because of libc usage, functionallity currently not supported by pure rust crates
        unsafe { LinkAddr::from_raw(&sock_addr as *const _ as *const libc::sockaddr, None) }
            .ok_or_else(|| ScannerErrWithMsg {
                err: ScanErr::Socket,
                msg: String::from("Failed to create LinkAddr"),
            })
    }

    // Hilfsfunktion für das Logging: 3x alle 3s, dann 1x nach 10s, dann wiederholen.
    fn log_sending_speed(
        mut done: Receiver<String>,
        count_packets: Arc<AtomicUsize>,
        _scan_rate: u64,
    ) {
        std::thread::spawn(move || {
            let mut start = std::time::Instant::now();
            let mut last_sent = 0;

            let mut next_log_target = 3;
            let mut interval_stage = 0; // 0, 1, 2 = 3s intervals; 3 = 10s interval

            loop {
                std::thread::sleep(Duration::from_secs(1));

                if let Ok(_) = done.try_recv() {
                    let total_sent = count_packets.load(Ordering::Relaxed);
                    let elapsed_millis = start.elapsed().as_millis();
                    eprintln!(
                        "Insgesamt {} Pakete in {} ms gesendet",
                        total_sent, elapsed_millis
                    );
                    return;
                }

                let total_sent = count_packets.load(Ordering::Relaxed);
                if total_sent == 0 {
                    start = std::time::Instant::now();
                    continue;
                }

                let elapsed = start.elapsed();
                let secs = elapsed.as_secs();

                if secs >= next_log_target {
                    let diff = total_sent - last_sent;
                    let current_interval = if interval_stage < 3 { 3 } else { 10 };

                    eprintln!("Nach {}s gesendet: {} Pakete", current_interval, diff);
                    last_sent = total_sent;

                    // Calculate next target
                    if interval_stage < 2 {
                        next_log_target += 3;
                        interval_stage += 1;
                    } else if interval_stage == 2 {
                        next_log_target += 10;
                        interval_stage = 3;
                    } else {
                        next_log_target += 3;
                        interval_stage = 0;
                    }

                    // Catch up logic (in case of long sleep)
                    while next_log_target <= secs {
                        if interval_stage < 2 {
                            next_log_target += 3;
                            interval_stage += 1;
                        } else if interval_stage == 2 {
                            next_log_target += 10;
                            interval_stage = 3;
                        } else {
                            next_log_target += 3;
                            interval_stage = 0;
                        }
                    }
                }
            }
        });
    }

    async fn start_sending_done_listener(
        &self,
        sending_done_receiver: Vec<Receiver<String>>,
        tx_stop_logging: Sender<String>,
        tx_notify_capturer: Sender<String>,
    ) {
        for mut rx in sending_done_receiver {
            let _ = rx.recv().await;
        }
        let _ = tx_stop_logging.send(DONE.to_string()).await;

        // sleep before sending done signal in cleanup, so receiver has time to collect packets
        tokio::time::sleep(Duration::from_millis(self.config.parsing_timeout_millis)).await;

        let _ = tx_notify_capturer.send(DONE.to_string()).await;
    }
}
