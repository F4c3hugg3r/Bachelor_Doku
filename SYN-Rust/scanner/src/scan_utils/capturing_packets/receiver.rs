use std::{
    fmt::Write as FmtWrite,
    io::Write,
    ops::{Add, Sub},
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aya::maps::RingBuf;
use core_affinity::CoreId;
use etherparse::{
    NetHeaders::{Ipv4, Ipv6},
    PacketHeaders,
};
use pcap::{Capture, Device};
use tokio::{
    io::unix::AsyncFd,
    sync::mpsc::{Receiver, Sender},
};
use xdp_common::PacketLog;
use zerocopy::FromBytes;

use crate::scan_utils::{
    capturing_packets::deduplicator::Deduplicator,
    shared::types_and_config::{CONTINUE, CaptureConfig, ScanErr, ScannerErrWithMsg, Target},
};

pub struct PacketReceiver {
    config: Arc<CaptureConfig>,
    // rst_sender: Sender<[u8; 4]>,
    deduplicator: Deduplicator,
    duplicate_count: u64,
    done: Arc<AtomicBool>,
    sending_done_receiver: Receiver<String>,
    output_buffer: String,
    output_sender: Sender<String>,
}

const BATCH_SIZE: usize = 65536;

struct Cleanup {
    pub done: Arc<AtomicBool>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
    }
}

impl PacketReceiver {
    pub async fn start_receiving(
        capture_config: Arc<CaptureConfig>,
        sending_done_receiver: Receiver<String>,
        events: RingBuf<aya::maps::MapData>,
    ) -> Result<(), ScannerErrWithMsg> {
        let cleanup = Cleanup {
            done: Arc::new(AtomicBool::new(false)),
        };
        let mut handles = Vec::new();

        let deduplicator = Deduplicator::new(1 << 21);

        let (tx_sending_done_channels, mut rx_sending_done_channels) =
            crate::scan_utils::shared::helper::create_done_channels(1);

        let handle = tokio::spawn(async move {
            PacketReceiver::start_sending_done_broadcaster(
                sending_done_receiver,
                tx_sending_done_channels,
            )
            .await;
        });
        handles.push(handle);

        let (tx_writer, rx_writer) = tokio::sync::mpsc::channel::<String>(2048);

        // Spawn Writer Task
        let writer_handle = tokio::spawn(async move {
            PacketReceiver::run_writer(rx_writer).await;
        });
        handles.push(writer_handle);

        let mut receiver = Self {
            config: capture_config.clone(),
            deduplicator,
            duplicate_count: 0,
            sending_done_receiver: rx_sending_done_channels.remove(0),
            done: cleanup.done.clone(),
            output_buffer: String::with_capacity(BATCH_SIZE),
            output_sender: tx_writer,
        };

        let handle = tokio::spawn(async move {
            receiver.receive_packets_events_loop(events).await;
            receiver.flush_buffer().await;
        });
        handles.push(handle);

        for handle in handles {
            if let Err(e) = handle.await {
                eprintln!("{:?}", e);
            };
        }
        Ok(())
    }

    async fn receive_packets_events_loop(&mut self, mut ring_buf: RingBuf<aya::maps::MapData>) {
        let mut lost = 0;
        let mut read = 0;

        let fd = ring_buf.as_raw_fd();
        let async_fd = AsyncFd::new(fd).unwrap();
        let mut flush_interval = tokio::time::interval(Duration::from_millis(200));

        loop {
            tokio::select! {
                _ = self.sending_done_receiver.recv() => {
                    self.done.store(true, Ordering::Relaxed);
                    break;
                }
                _ = flush_interval.tick() => {
                    self.flush_buffer().await;
                }
                guard = async_fd.readable() => {
                    match guard {
                        Ok(mut guard) => {
                            while let Some(item) = ring_buf.next() {
                                if item.len() < std::mem::size_of::<PacketLog>() {
                                    lost += 1;
                                    continue;
                                }

                                if let Ok(log) = PacketLog::read_from_bytes(&item) {
                                    self.evaluate_log(&log).await;
                                    read += 1;
                                } else {
                                    lost += 1;
                                }
                            }
                            guard.clear_ready();
                        }
                        Err(e) => {
                            eprintln!("AsyncFd error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
        self.flush_buffer().await;
        eprintln!(
            "Answers lost: {}, Answers read: {}, Duplicates: {}",
            lost, read, self.duplicate_count
        );
        self.done.store(true, Ordering::Relaxed);
    }

    async fn flush_buffer(&mut self) {
        if self.output_buffer.is_empty() {
            return;
        }

        let payload = std::mem::replace(&mut self.output_buffer, String::with_capacity(BATCH_SIZE));

        if let Err(e) = self.output_sender.send(payload).await {
            eprintln!("Error sending to writer task: {}", e);
        }
    }

    async fn run_writer(mut rx: Receiver<String>) {
        let stdout = std::io::stdout();

        while let Some(chunk) = rx.recv().await {
            let mut handle = stdout.lock();
            if let Err(e) = handle.write_all(chunk.as_bytes()) {
                eprintln!("Error writing to stdout: {}", e);
            }
            let _ = handle.flush();
        }
    }

    async fn evaluate_log(&mut self, log: &PacketLog) {
        let src_ip = if log.version == 4 {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                log.src_addr[0],
                log.src_addr[1],
                log.src_addr[2],
                log.src_addr[3],
            ))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(log.src_addr))
        };

        let src_port = log.port;

        if self.config.deduplicate {
            // Check duplicates and insert if not present
            let is_duplicate = match src_ip {
                std::net::IpAddr::V4(ip) => {
                    self.deduplicator.check_and_insert((ip.octets(), src_port))
                }
                std::net::IpAddr::V6(ip) => {
                    self.deduplicator.check_and_insert((ip.octets(), src_port))
                }
            };

            if is_duplicate {
                self.duplicate_count = self.duplicate_count.saturating_add(1);
                return;
            }
        }

        // CSV Output: ip,port
        let port_val = u16::from_be_bytes(src_port);
        let _ = writeln!(self.output_buffer, "{},{}", src_ip, port_val);

        if self.output_buffer.len() >= BATCH_SIZE {
            self.flush_buffer().await;
        }
    }

    async fn start_sending_done_broadcaster(
        mut sending_done_receiver: Receiver<String>,
        tx_sending_done_channels: Vec<Sender<String>>,
    ) {
        if let Some(msg) = sending_done_receiver.recv().await {
            for tx in tx_sending_done_channels {
                let _ = tx.send(msg.clone()).await;
            }
        }
    }

    // LEGACY CODE
    // fn receive_packets_pcap(
    //     &mut self,
    //     tx_wait_for_capture: Sender<String>,
    //     done: Arc<AtomicBool>,
    // ) -> Result<(), ScannerErrWithMsg> {
    //     let timeout = std::time::Duration::from_millis(self.config.parsing_timeout_millis);
    //     // let device = Device::lookup()
    //     //     .map_err(|e| ScannerErrWithMsg {
    //     //         err: ScanErr::Capturing,
    //     //         msg: format!("Device lookup failed: {:?}", e),
    //     //     })?
    //     //     .ok_or(ScannerErrWithMsg {
    //     //         err: ScanErr::Capturing,
    //     //         msg: "No device available".to_string(),
    //     //     })?;

    //     let device_list = Device::list().map_err(|e| ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: format!("Device lookup failed: {:?}", e),
    //         })?;
    //     let device = device_list.iter().find(|d| d.name == self.config.interface)
    //     .ok_or(ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: "No device available".to_string(),
    //         })?;

    //     eprintln!("Using device {}", device.name);

    //     // Capture vorbereiten
    //     let mut cap = Capture::from_device(device.clone())
    //         .map_err(|e| ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: format!("Capturing from device not possible: {:?}", e),
    //         })?
    //         .timeout(5)
    //         .open()
    //         .map_err(|e| ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: format!("Device couldn't be opened: {:?}", e),
    //         })?;

    //     // set BPF
    //     let bpf_filter = self.create_bpf()?;
    //     cap.filter(&bpf_filter, true)
    //         .map_err(|e| ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: format!("BPF couldn't be set: {:?}, filter: {}", e, bpf_filter),
    //         })?;

    //     // set nonblock
    //     let mut cap = cap.setnonblock().map_err(|e| ScannerErrWithMsg {
    //         err: ScanErr::Capturing,
    //         msg: format!("Failed to set nonblocking mode: {:?}", e),
    //     })?;

    //     // CAPTURING TEST
    //     eprintln!("Starting to capture");

    //     // notify scanjob
    //     let _ = tx_wait_for_capture.blocking_send(CONTINUE.to_string());

    //     // TODO stop / continue / finish logik hinzufügen
    //     loop {
    //         crossbeam::select! {
    //             recv(self.sending_done_receiver) -> _ => {
    //                 eprintln!("Capturing on timeout");
    //                 break;
    //             }
    //             default => {
    //                 match cap.next_packet() {
    //                     Ok(packet) => {
    //                         if let Err(e) = self.evaluate_packet_without_ebpf(packet.data) {
    //                             eprintln!("error while evaluating packet: {:?}", e);
    //                         };
    //                     }
    //                     Err(pcap::Error::NoMorePackets) | Err(pcap::Error::TimeoutExpired) => {
    //                         std::thread::yield_now();
    //                     }
    //                     Err(e) => {
    //                         eprintln!("error while capturing packet: {:?}", e);
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     // Phase 2: Nach assembler_finished: noch bis Timeout capturen
    //     let timer = crossbeam::channel::after(timeout);
    //     loop {
    //         crossbeam::select! {
    //             recv(timer) -> _ => {
    //                 eprintln!("Timeout finished, stopping capture");
    //                 break;
    //             }
    //             default => {
    //                 match cap.next_packet() {
    //                     Ok(packet) => {
    //                         if let Err(e) = self.evaluate_packet_without_ebpf(packet.data) {
    //                             eprintln!("error while evaluating packet: {:?}", e);
    //                         };
    //                     }
    //                     Err(pcap::Error::NoMorePackets) | Err(pcap::Error::TimeoutExpired) => {
    //                         std::thread::yield_now();
    //                     }
    //                     Err(e) => {
    //                         eprintln!("error while capturing packet: {:?}", e);
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     // CAPTURING TEST
    //     let stats = cap.stats().unwrap();
    //     eprintln!(
    //         "Packets dropped: {}, Packets received: {}",
    //         stats.dropped, stats.received
    //     );
    //     done.store(true, std::sync::atomic::Ordering::SeqCst);

    //     Ok(())
    // }

    // fn create_bpf(&self) -> Result<String, ScannerErrWithMsg> {
    //     let ip_filters: Vec<String> = if self.config.ipv6 {
    //         self.config
    //             .src_ips
    //             .iter()
    //             .filter_map(|ip| {
    //                 let arr: Option<[u8; 16]> = ip.as_slice().try_into().ok();
    //                 arr.map(|a| format!("dst host {}", std::net::Ipv6Addr::from(a)))
    //             })
    //             .collect()
    //     } else {
    //         self.config
    //             .src_ips
    //             .iter()
    //             .filter_map(|ip| {
    //                 let arr: Option<[u8; 4]> = ip.as_slice().try_into().ok();
    //                 arr.map(|a| format!("dst host {}", std::net::Ipv4Addr::from(a)))
    //             })
    //             .collect()
    //     };

    //     let port_filters: Vec<String> = self
    //         .config
    //         .src_ports
    //         .iter()
    //         .map(|port| format!("dst port {}", port))
    //         .collect();

    //     if ip_filters.is_empty() || port_filters.is_empty() {
    //         return Err(ScannerErrWithMsg {
    //             err: ScanErr::Capturing,
    //             msg: "error parsing ip addresses or ports for bpf".to_string(),
    //         });
    //     }

    //     let mut filter_parts = Vec::new();
    //     if self.config.ipv6 {
    //         filter_parts.push("ip6 and tcp".to_string());
    //     } else {
    //         filter_parts.push(
    //             "ip and tcp and (tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
    //                 .to_string(),
    //         );
    //     }
    //     // old ipv4 Filter
    //     // filter_parts.push("tcp and (tcp[13] & 18 == 18)".to_string());

    //     if !ip_filters.is_empty() {
    //         filter_parts.push(format!("({})", ip_filters.join(" or ")));
    //     }
    //     if !port_filters.is_empty() {
    //         filter_parts.push(format!("({})", port_filters.join(" or ")));
    //     }

    //     // Test
    //     let res = Ok(filter_parts.join(" and "));

    //     if let Ok(string) = &res {
    //         if string.chars().count() > 150 {
    //             eprintln!("bpf filter {}...", &string[..150]);
    //         }
    //         eprintln!("bpf filter {}", string);
    //     }
    //     res
    // }

    // // FIXME integrate new hashing function
    // fn evaluate_packet_without_ebpf(&self, packet_data: &[u8]) -> Result<(), ScannerErrWithMsg> {
    //     let data = packet_data;
    //     match PacketHeaders::from_ethernet_slice(data) {
    //         Ok(parsed) => {
    //             // CAPTURING TEST
    //             eprintln!("Captured some response");

    //             let net_header = parsed.net.ok_or(ScannerErrWithMsg {
    //                 err: ScanErr::Capturing,
    //                 msg: "error parsing ip header".to_string(),
    //             })?;

    //             match net_header {
    //                 Ipv4(header, _) => {
    //                     // compare hash and seq number
    //                     let tcp_header = parsed
    //                         .transport
    //                         .ok_or(ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: "error parsing transport header".to_string(),
    //                         })?
    //                         .tcp()
    //                         .ok_or(ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: "error parsing tcp header".to_string(),
    //                         })?;

    //                     // check duplicates
    //                     let src_ip = header.source;
    //                     let src_port = tcp_header.source_port.to_be_bytes();
    //                     if self.duplicate_buckets.browse_ipv4(&(src_ip, src_port)) {
    //                         // CAPTURING TEST
    //                         eprintln!("found duplicate");
    //                         return Ok(());
    //                     }

    //                     // CAPTURING TEST
    //                     // eprintln!("No duplicate");

    //                     // legacy code is now done by ebpf
    //                     // let ack_num = tcp_header.acknowledgment_number;
    //                     // let dst_port = tcp_header.destination_port.to_be_bytes();
    //                     // let dst_ip = header.destination;

    //                     // let comp_seq_num =
    //                     //     create_sequence_number(&dst_ip, &dst_port, &src_ip, &src_port);
    //                     // if comp_seq_num != ack_num.sub(1) {
    //                     //     // CAPTURING TEST
    //                     //     // eprintln!(
    //                     //     //     "Ack-1 {} != SeqNum {}, aborting",
    //                     //     //     ack_num.sub(1),
    //                     //     //     comp_seq_num
    //                     //     // );
    //                     //     return Ok(());
    //                     // }

    //                     // safe IP into duplicate map
    //                     Arc::clone(&self.duplicate_buckets).insert_ipv4((src_ip, src_port));

    //                     // initiate RST - macht der Kernel von allein
    //                     // if self.config.reset
    //                     //     && let Err(e) = self.rst_sender.send(src_ip)
    //                     // {
    //                     //     return Err(ScannerErrWithMsg {
    //                     //         err: ScanErr::Capturing,
    //                     //         msg: format!("error sending ip for RST: {:?}", e),
    //                     //     });
    //                     // }

    //                     // print target
    //                     let target = Target {
    //                         port: u16::from_be_bytes(src_port),
    //                         ip: &src_ip,
    //                     };
    //                     let target_json =
    //                         serde_json::to_string(&target).map_err(|e| ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: format!("error parsing to json: {:?}", e),
    //                         })?;
    //                     print!("{},", target_json);

    //                     // CAPTURING TEST
    //                     eprintln!("captured valid response: {}", target_json);
    //                 }
    //                 Ipv6(header, _) => {
    //                     // compare hash and seq number
    //                     let tcp_header = parsed
    //                         .transport
    //                         .ok_or(ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: "error parsing transport header".to_string(),
    //                         })?
    //                         .tcp()
    //                         .ok_or(ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: "error parsing tcp header".to_string(),
    //                         })?;

    //                     // check duplicates
    //                     let src_ip = header.source;
    //                     let src_port = tcp_header.source_port.to_be_bytes();
    //                     if self.duplicate_buckets.browse_ipv6(&(src_ip, src_port)) {
    //                         // CAPTURING TEST
    //                         eprintln!("found duplicate");
    //                         return Ok(());
    //                     }

    //                     // CAPTURING TEST
    //                     // eprintln!("No duplicate");

    //                     // legacy code is now done by ebpf
    //                     // let ack_num = tcp_header.acknowledgment_number;
    //                     // let dst_port = tcp_header.destination_port.to_be_bytes();
    //                     // let dst_ip = header.destination;

    //                     // let comp_seq_num =
    //                     //     create_sequence_number(&dst_ip, &dst_port, &src_ip, &src_port);
    //                     // if comp_seq_num != ack_num.sub(1) {
    //                     //     // CAPTURING TEST
    //                     //     // eprintln!(
    //                     //     //     "Ack-1 {} != SeqNum {}, aborting",
    //                     //     //     ack_num.sub(1),
    //                     //     //     comp_seq_num
    //                     //     // );
    //                     //     return Ok(());
    //                     // }

    //                     // safe IP into duplicate map
    //                     Arc::clone(&self.duplicate_buckets).insert_ipv6((src_ip, src_port));

    //                     // initiate RST - macht der Kernel von allein
    //                     // if self.config.reset
    //                     //     && let Err(e) = self.rst_sender.send(src_ip)
    //                     // {
    //                     //     return Err(ScannerErrWithMsg {
    //                     //         err: ScanErr::Capturing,
    //                     //         msg: format!("error sending ip for RST: {:?}", e),
    //                     //     });
    //                     // }

    //                     // print target
    //                     let target = Target {
    //                         port: u16::from_be_bytes(src_port),
    //                         ip: &src_ip,
    //                     };
    //                     let target_json =
    //                         serde_json::to_string(&target).map_err(|e| ScannerErrWithMsg {
    //                             err: ScanErr::Capturing,
    //                             msg: format!("error parsing to json: {:?}", e),
    //                         })?;
    //                     print!("{},", target_json);

    //                     // CAPTURING TEST
    //                     eprintln!("captured valid response: {}", target_json);
    //                 }
    //                 _ => unreachable!(
    //                     "SenderChan must be BatchList or PacketList for start_spawning_rst!"
    //                 ),
    //             }
    //         }
    //         Err(e) => {
    //             eprintln!("parse error: {:?}", e);
    //         }
    //     }
    //     Ok(())
    // }
}
