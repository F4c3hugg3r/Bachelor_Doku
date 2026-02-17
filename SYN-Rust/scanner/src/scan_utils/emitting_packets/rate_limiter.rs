use std::{
    ops::Div,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::mpsc::{Receiver, Sender},
    task::JoinHandle,
};

use crate::scan_utils::{
    emitting_packets::assembler::PacketAssembler,
    shared::{
        helper,
        types_and_config::{
            AssemblerDstIps, CONTINUE, DONE, EmissionConfig, FINISH, ReceiverChan, STOP, ScanErr,
            ScannerErrWithMsg, SenderChan, TCP_IPV4_PACKET_SIZE, TCP_IPV6_PACKET_SIZE,
        },
    },
};

#[derive(Debug)]
pub struct RateLimiter {
    config: Arc<EmissionConfig>,
    current_template: Arc<AtomicUsize>,
    current_sent_bytes: Arc<AtomicUsize>,
    current_sender: AtomicUsize,
    sender_list: SenderChan,
}

impl RateLimiter {
    pub async fn start_emitting(
        emission_config: Arc<EmissionConfig>,
        sender_list: SenderChan,
        dst_ips_receiver: ReceiverChan,
        stop_rx: Receiver<String>,
        // rst_receiver: Receiver<[u8; 4]>,
    ) {
        let dst_ports_count = emission_config.dst_ports.len();
        let current_sent_bytes = Arc::new(AtomicUsize::new(0));
        let mut rate_limiter = RateLimiter {
            config: emission_config,
            sender_list,
            current_template: Arc::new(AtomicUsize::new(0)),
            current_sent_bytes: current_sent_bytes.clone(),
            current_sender: AtomicUsize::new(0),
        };
        let mut handles = Vec::new();
        let mut abort_handles = Vec::new();

        // spawn singal broadcaster
        let (broadcaster_tx, mut broadcaster_rx) =
            helper::create_signal_channels(3 + dst_ports_count as u64);
        let abort_handle = tokio::spawn(async move {
            RateLimiter::start_signal_listener(stop_rx, broadcaster_tx).await;
        });
        abort_handles.push(abort_handle);

        // spawn ticker to reset current_sent_bytes every second
        let signal_broadcaster = broadcaster_rx.swap_remove(0);
        let abort_handle = tokio::spawn(async move {
            if let Err(e) = RateLimiter::start_ticking(current_sent_bytes, signal_broadcaster).await
            {
                eprintln!("{:?}: {}", e.err, e.msg);
            };
        });
        abort_handles.push(abort_handle);

        // not relevant if kernel is being used to send RST
        // spawn assembler from rst_receiver
        // let mut rst_handle = None;
        // if rate_limiter.config.reset {
        //     let finisher = rx_finisher.swap_remove(0);
        //     let rl_clone = rate_limiter.clone();
        //     rst_handle = Some(tokio::spawn(async move {
        //         if let Err(e) = rl_clone.start_spawning_rst(rst_receiver, finisher).await {
        //             eprintln!("{:?}: {}", e.err, e.msg);
        //         };
        //     }));
        // }

        // TEST
        eprintln!("Spawning for dst_port number 0 (from chan)");

        // spawn assembler while parsing stdin
        let finisher = broadcaster_rx.swap_remove(0);
        let dst_port: Option<usize> = if rate_limiter.config.dst_ports.len() > 1 {
            Some(0)
        } else {
            None
        };
        let result = rate_limiter
            .start_spawning_from_chan(dst_ips_receiver, finisher, dst_port)
            .await;

        match result {
            Ok((dst_ip_buf, assembler_handles)) => {
                handles.extend(assembler_handles);

                if rate_limiter.config.dst_ports.len() > 1 {
                    // spawn assembler from previously parsed ips concurrently
                    for i in 1..dst_ports_count {
                        eprintln!("Spawning for dst_port number {}", i);
                        let finisher = broadcaster_rx.swap_remove(0);
                        let dst_ip_buf_clone = dst_ip_buf.clone();
                        let assembler_handles = match rate_limiter
                            .start_spawning_from_buf(dst_ip_buf_clone, finisher, Some(i))
                            .await
                        {
                            Err(e) => {
                                eprintln!("{:?}: {}", e.err, e.msg);
                                Vec::new()
                            }
                            Ok(handles) => handles,
                        };
                        handles.extend(assembler_handles);
                    }
                }

                // EMITTING TEST
                eprintln!("Spawning done");

                for handle in handles {
                    if let Err(e) = handle.await {
                        eprintln!("{:?}", e);
                    };
                }
            }
            Err(e) => {
                eprintln!("Error during spawning from chan: {:?}: {}", e.err, e.msg);
            }
        }

        for handle in abort_handles {
            handle.abort();
        }

        // if let Some(handle) = rst_handle {
        //     let _ = handle.await;
        // }

        // EMITTING TEST
        eprintln!("Assembling done");
    }

    async fn start_spawning_from_chan(
        &mut self,
        mut dst_ips: ReceiverChan,
        mut broadcaster_rx: Receiver<String>,
        dst_port_index: Option<usize>,
    ) -> Result<(AssemblerDstIps, Vec<JoinHandle<()>>), ScannerErrWithMsg> {
        let mut dst_ip_buf = match &dst_ips {
            ReceiverChan::ParsedIpv4(_) => AssemblerDstIps::Ipv4(Vec::new()),
            ReceiverChan::ParsedIpv6(_) => AssemblerDstIps::Ipv6(Vec::new()),
            _ => unreachable!(
                "ReceiverChan must be ParsedIpv4 or ParsedIpv6 for start_spawning_from_chan!"
            ),
        };
        let mut handles = Vec::new();
        let mut stop = false;
        let mut leftover_ipv4: Vec<[u8; 4]> = Vec::new();
        let mut leftover_ipv6: Vec<[u8; 16]> = Vec::new();

        while !stop {
            let packets_to_send = self.check_current_sent_bytes(None).await?;
            let assembler_dst_ips = match &mut dst_ips {
                ReceiverChan::ParsedIpv4(rx) => {
                    let mut assembler_buf_ipv4: Vec<[u8; 4]> = Vec::with_capacity(packets_to_send);

                    // Drain leftovers first
                    let take = std::cmp::min(packets_to_send, leftover_ipv4.len());
                    assembler_buf_ipv4.extend(leftover_ipv4.drain(0..take));

                    while assembler_buf_ipv4.len() < packets_to_send {
                        tokio::select! {
                            batch = rx.recv() => {
                                match batch {
                                    Some(batch) => {
                                        for ip in batch {
                                             if ip == [0u8; 4] {
                                                stop = true;
                                                break;
                                            }
                                            if assembler_buf_ipv4.len() < packets_to_send {
                                                assembler_buf_ipv4.push(ip);
                                            } else {
                                                leftover_ipv4.push(ip);
                                            }
                                        }
                                        if stop { break; }
                                    },
                                    None => {
                                        return Err(ScannerErrWithMsg {
                                            err: ScanErr::RateLimiting,
                                            msg: "Parsing complete expected: failed to receive dst_ipv4: channel closed".to_string(),
                                        });
                                    }
                                }
                            },
                            msg = broadcaster_rx.recv() => {
                                match msg {
                                    Some(msg) if msg == STOP => {
                                            match RateLimiter::handle_broadcast_signal(&mut broadcaster_rx).await? {
                                            Some(msg) if msg == CONTINUE => continue,
                                            Some(msg) if msg == FINISH => return Ok((dst_ip_buf, handles)),
                                            _ => unreachable!(),
                                        }
                                        },
                                    Some(msg) if msg == CONTINUE=> {
                                        continue;
                                    },
                                    Some(msg) if msg == FINISH => {
                                        return Ok((dst_ip_buf, handles));
                                    },
                                    None => return Err(ScannerErrWithMsg {
                                        err: ScanErr::RateLimiting,
                                        msg: "Error stopping emitting process".to_string(),
                                    }),
                                    _ => unreachable!(
                                    "Stop signal has to be either 'stop', 'continue' or 'finish'"
                                     ),
                                };
                            }
                        }
                    }
                    if dst_port_index.is_some()
                        && let AssemblerDstIps::Ipv4(ref mut buf) = dst_ip_buf
                    {
                        buf.extend_from_slice(&assembler_buf_ipv4);
                    }
                    AssemblerDstIps::Ipv4(assembler_buf_ipv4)
                }
                ReceiverChan::ParsedIpv6(rx) => {
                    let mut assembler_buf_ipv6: Vec<[u8; 16]> = Vec::with_capacity(packets_to_send);

                    // Drain leftovers first
                    let take = std::cmp::min(packets_to_send, leftover_ipv6.len());
                    assembler_buf_ipv6.extend(leftover_ipv6.drain(0..take));

                    while assembler_buf_ipv6.len() < packets_to_send {
                        tokio::select! {
                             batch = rx.recv() => {
                                match batch {
                                    Some(batch) => {
                                         for ip in batch {
                                             if ip == [0u8; 16] {
                                                stop = true;
                                                break;
                                            }
                                            if assembler_buf_ipv6.len() < packets_to_send {
                                                assembler_buf_ipv6.push(ip);
                                            } else {
                                                leftover_ipv6.push(ip);
                                            }
                                        }
                                         if stop { break; }
                                    },
                                    None => {
                                        return Err(ScannerErrWithMsg {
                                            err: ScanErr::RateLimiting,
                                            msg: "Parsing complete expected: failed to receive dst_ipv6: channel closed".to_string(),
                                        });
                                    }
                                }
                            },
                            msg = broadcaster_rx.recv() => {
                                match msg {
                                    Some(msg) if msg == STOP => {
                                            match RateLimiter::handle_broadcast_signal(&mut broadcaster_rx).await? {
                                            Some(msg) if msg == CONTINUE => continue,
                                            Some(msg) if msg == FINISH => return Ok((dst_ip_buf, handles)),
                                            _ => unreachable!(),
                                        }
                                        },
                                    Some(msg) if msg == CONTINUE=> {
                                        continue;
                                    },
                                    Some(msg) if msg == FINISH => {
                                        return Ok((dst_ip_buf, handles));
                                    },
                                    None => return Err(ScannerErrWithMsg {
                                        err: ScanErr::RateLimiting,
                                        msg: "Error stopping emitting process".to_string(),
                                    }),
                                    _ => unreachable!(
                                    "Stop signal has to be either 'stop', 'continue' or 'finish'"
                                     ),
                                };
                            }
                        }
                    }
                    if dst_port_index.is_some()
                        && let AssemblerDstIps::Ipv6(ref mut buf) = dst_ip_buf
                    {
                        buf.extend_from_slice(&assembler_buf_ipv6);
                    }

                    AssemblerDstIps::Ipv6(assembler_buf_ipv6)
                }
                _ => unreachable!(
                    "ReceiverChan must be ParsedIpv4 or ParsedIpv6 for start_spawning_from_chan!"
                ),
            };

            let sender_chan = match &self.sender_list {
                SenderChan::BatchList(list) if self.config.send_in_batches => {
                    SenderChan::Batch(list[self.decide_current_sender()].clone())
                }
                SenderChan::PacketList(list) if !self.config.send_in_batches => {
                    SenderChan::Packet(list[self.decide_current_sender()].clone())
                }
                _ => unreachable!(
                    "SenderChan must be BatchList or PacketList for start_spawning_from_chan!"
                ),
            };
            let handle = self
                .spawn_assembler(assembler_dst_ips, sender_chan, dst_port_index)
                .await;
            handles.push(handle);
        }
        Ok((dst_ip_buf, handles))
    }

    async fn start_spawning_from_buf(
        &mut self,
        mut dst_ip_buf: AssemblerDstIps,
        mut broadcaster_rx: Receiver<String>,
        dst_port_index: Option<usize>,
    ) -> Result<Vec<JoinHandle<()>>, ScannerErrWithMsg> {
        let mut current_ind = 0;
        let mut complete = false;
        let mut handles = Vec::new();
        // TEST
        // eprintln!("starting while loop");
        while !complete {
            if broadcaster_rx.try_recv().is_ok() {
                return Ok(handles);
            }

            // TEST
            // eprintln!(
            //     "Entering retry loop: current_ind={}, complete={}, retry_buf={:?}",
            //     current_ind, complete, retry_buf
            // );
            // fill assembler buffer ips from retry buffer
            let packets_to_send = self.check_current_sent_bytes(None).await?;
            let (assembler_dst_ips, end) = match &mut dst_ip_buf {
                AssemblerDstIps::Ipv4(buf) => {
                    let end = if current_ind + packets_to_send < buf.len() {
                        current_ind + packets_to_send
                    } else {
                        complete = true;
                        buf.len()
                    };
                    let assembler_buf_ipv4 = buf[current_ind..end].to_vec();
                    (AssemblerDstIps::Ipv4(assembler_buf_ipv4), end)
                }
                AssemblerDstIps::Ipv6(buf) => {
                    let end = if current_ind + packets_to_send < buf.len() {
                        current_ind + packets_to_send
                    } else {
                        complete = true;
                        buf.len()
                    };
                    let assembler_buf_ipv6 = buf[current_ind..end].to_vec();
                    (AssemblerDstIps::Ipv6(assembler_buf_ipv6), end)
                }
            };

            let sender_chan = match &self.sender_list {
                SenderChan::BatchList(list) if self.config.send_in_batches => {
                    SenderChan::Batch(list[self.decide_current_sender()].clone())
                }
                SenderChan::PacketList(list) if !self.config.send_in_batches => {
                    SenderChan::Packet(list[self.decide_current_sender()].clone())
                }
                _ => unreachable!(
                    "SenderChan must be BatchList or PacketList for start_spawning_from_buf!"
                ),
            };
            // TEST
            // eprintln!(
            //     "Retry: packets_to_send={}, current_ind={}, retry_buf={:?}",
            //     packets_to_send, current_ind, retry_buf
            // );
            let handle = self
                .spawn_assembler(assembler_dst_ips, sender_chan, dst_port_index)
                .await;
            handles.push(handle);

            current_ind = end;
        }
        Ok(handles)
    }

    // async fn start_spawning_rst(
    //     self: Arc<Self>,
    //     rst_receiver: SyncReceiver<[u8; 4]>,
    //     mut finish: Receiver<String>,
    // ) -> Result<(), ScannerErrWithMsg> {
    //     let mut done = false;
    //     loop {
    //         // fill assembler buffer ips
    //         let packets_to_send = self.check_current_sent_bytes().await?;
    //         let mut assembler_buf_ipv4: Vec<[u8; 4]> = Vec::with_capacity(packets_to_send);
    //         for _ in 0..packets_to_send {
    //             if finish.try_recv().is_ok() {
    //                 done = true;
    //                 break;
    //             }

    //             let ip = match rst_receiver.recv() {
    //                 Ok(ip) => ip,
    //                 Err(e) => {
    //                     return Err(ScannerErrWithMsg {
    //                         err: ScanErr::RateLimiting,
    //                         msg: format!("Error receiving RST-IP {:?}", e),
    //                     });
    //                 }
    //             };
    //             assembler_buf_ipv4.push(ip);
    //         }

    //         // spawn assembler with ip buf
    //         let sender_chan = match &self.sender_list {
    //             SenderChan::BatchList(list) if self.config.send_in_batches => {
    //                 SenderChan::Batch(list[self.decide_current_sender()].clone())
    //             }
    //             SenderChan::PacketList(list) if !self.config.send_in_batches => {
    //                 SenderChan::Packet(list[self.decide_current_sender()].clone())
    //             }
    //             _ => unreachable!(
    //                 "SenderChan must be BatchList or PacketList for start_spawning_rst!"
    //             ),
    //         };
    //         let assembler_dst_ips = AssemblerDstIps::Ipv4(assembler_buf_ipv4);
    //         let handle = self.spawn_assembler(assembler_dst_ips, sender_chan).await;
    //         if done {
    //             let _ = handle.await;
    //             return Ok(());
    //         }
    //     }
    // }

    async fn handle_broadcast_signal(
        rx: &mut Receiver<String>,
    ) -> Result<Option<String>, ScannerErrWithMsg> {
        while let Some(msg) = rx.recv().await {
            match msg.as_str() {
                STOP => continue, // warte auf CONTINUE oder FINISH
                CONTINUE => return Ok(Some(CONTINUE.to_string())),
                FINISH => return Ok(Some(FINISH.to_string())),
                _ => {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::RateLimiting,
                        msg: "Stop signal has to be either 'stop', 'continue' or 'finish'"
                            .to_string(),
                    });
                }
            }
        }
        Err(ScannerErrWithMsg {
            err: ScanErr::RateLimiting,
            msg: "Error stopping emitting process".to_string(),
        })
    }

    async fn spawn_assembler(
        &self,
        dst_ips: AssemblerDstIps,
        sender_chan: SenderChan,
        dst_port_index: Option<usize>,
    ) -> JoinHandle<()> {
        let current_template = self.current_template.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            if let Err(e) = PacketAssembler::assemble_packets(
                dst_ips,
                sender_chan,
                current_template,
                config,
                dst_port_index,
            )
            .await
            {
                eprintln!(
                    "Packet Assembler couldn't be started: {:?} {}",
                    e.err, e.msg
                );
            };
        })
    }

    async fn start_ticking(
        current_sent_bytes: Arc<AtomicUsize>,
        mut broadcaster_rx: Receiver<String>,
    ) -> Result<(), ScannerErrWithMsg> {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    current_sent_bytes.store(0, std::sync::atomic::Ordering::Release);
                    // TEST
                    // eprintln!("Resetting current_sent_bytes");
                }
                msg = broadcaster_rx.recv() => {
                                return match msg {
                                    Some(msg) if msg == FINISH => {
                                        return Ok(());
                                    },
                                    Some(_) => {
                                       continue;
                                    },
                                    None => Err(ScannerErrWithMsg {
                                        err: ScanErr::RateLimiting,
                                        msg: "Error stopping emitting process".to_string(),
                                    }),
                                };
                            }
            }
        }
    }

    fn decide_current_sender(&self) -> usize {
        let num_threads = self.config.num_nic_queues;
        if num_threads <= 1 {
            return 0;
        }
        self.current_sender
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                let next = if current + 1 >= num_threads {
                    0
                } else {
                    current + 1
                };
                Some(next)
            })
            .unwrap_or(0)
    }

    /// check_current_sent_bytes checks if there is a byte buffer left for this period (second)
    /// according to the scanrate provided by the config. It then decides the next load of bytes
    /// to send, adds it to the current_sent_bytes and returns the corresponding usize of
    /// packets to send for the decided load of bytes
    ///
    /// If there is no buffer left for the period, it sleeps for 10ms before checking again
    async fn check_current_sent_bytes(
        &self,
        needed: Option<usize>,
    ) -> Result<usize, ScannerErrWithMsg> {
        let mut scanrate = (self.config.scan_rate as usize * 1_000_000) / 8;
        if self.config.retries > 0 {
            scanrate /= self.config.retries as usize + 1;
        }
        let timeout = Duration::from_millis(self.config.parsing_timeout_millis);
        let mut elapsed = Duration::ZERO;

        let packet_size = if self.config.ipv6 {
            TCP_IPV6_PACKET_SIZE
        } else {
            TCP_IPV4_PACKET_SIZE
        };

        let assembler_size_byte = if self.config.send_in_batches {
            self.config.assembler_size * self.config.batch_size * packet_size
        } else {
            self.config.assembler_size * packet_size
        };

        loop {
            // get sent bytes
            let current_sent_bytes = self
                .current_sent_bytes
                .load(std::sync::atomic::Ordering::Acquire);
            // TEST
            // eprintln!(
            //     "check_current_sent_bytes waiting: elapsed={:?}, current_sent_bytes={}, scanrate={}, needed={:?}",
            //     elapsed, current_sent_bytes, scanrate, needed
            // );

            // timeout for when nothing has to be send anymore
            if elapsed >= timeout {
                // TEST
                eprintln!(
                    "elapsed >= timeout: check_current_sent_bytes timeout: elapsed={:?}, timeout={:?}",
                    elapsed, timeout
                );
                return Err(ScannerErrWithMsg {
                    err: ScanErr::RateLimiting,
                    msg: "Error checking current bytes: timeout".to_string(),
                });
            }

            // decide spare_capacity
            if current_sent_bytes < scanrate {
                let spare_capacity_bytes = scanrate - current_sent_bytes;
                let bytes_to_send = if spare_capacity_bytes > assembler_size_byte {
                    assembler_size_byte
                } else {
                    spare_capacity_bytes
                };
                if let Some(need) = needed
                    && bytes_to_send < need
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    elapsed += Duration::from_millis(10);
                    continue;
                }

                if bytes_to_send.div(packet_size) < 1 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    elapsed += Duration::from_millis(10);
                    continue;
                }

                // add to current_sent_bytes
                self.current_sent_bytes
                    .fetch_add(bytes_to_send, std::sync::atomic::Ordering::Relaxed);
                return Ok(bytes_to_send.div(packet_size));
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
            elapsed += Duration::from_millis(10);
        }
    }

    // FIXME error loggen
    async fn start_signal_listener(
        mut signal_rx: Receiver<String>,
        signal_tx: Vec<Sender<String>>,
    ) {
        loop {
            match signal_rx.recv().await {
                Some(msg) if msg == FINISH => {
                    // TEST
                    eprintln!("signal_listener received finish signal");
                    for tx in &signal_tx {
                        let _ = tx.send(msg.clone()).await;
                    }
                    return;
                }
                Some(msg) => {
                    // TEST
                    eprintln!("signal_listener received signal {}", msg);
                    for tx in &signal_tx {
                        let _ = tx.send(msg.clone()).await;
                    }
                }
                None => {
                    // TEST
                    eprintln!("signal_listener channel closed, broadcasting finish signal");
                    for tx in &signal_tx {
                        let _ = tx.send(FINISH.to_string()).await;
                    }
                    return;
                }
            }
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::scan_utils::shared::types_and_config::HashKeys;

//     use super::*;
//     use pnet::util::MacAddr;

//     fn create_test_config(scan_rate: u64, num_queues: usize) -> Arc<EmissionConfig> {
//         Arc::new(EmissionConfig {
//             retries: 0,
//             ipv6: false,
//             protocol: 6,
//             batch_size: 1,
//             scan_rate,
//             templates: vec![vec![0u8; 60]], // Dummy template
//             send_in_batches: false,
//             assembler_size: 1,
//             parsing_timeout_millis: 100,
//             xdp: false,
//             num_nic_queues: num_queues,
//             reset: false,
//             dst_mac: MacAddr::zero(),
//             src_mac: MacAddr::zero(),
//             dst_ports: vec![80],
//             interface: "eno1".to_string(),
//             hash_keys: HashKeys { k0: None, k1: None },
//         })
//     }

//     #[test]
//     fn test_sender_rotation() {
//         let config = create_test_config(1000, 3);
//         let (tx, _rx) = tokio::sync::mpsc::channel(10);
//         let sender_list = SenderChan::Packet(tx); // Dummy, not used for rotation check logic but required for struct

//         let rate_limiter = RateLimiter {
//             config,
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)),
//             current_sender: AtomicUsize::new(0),
//             sender_list,
//         };

//         assert_eq!(rate_limiter.decide_current_sender(), 0);
//         assert_eq!(rate_limiter.decide_current_sender(), 1);
//         assert_eq!(rate_limiter.decide_current_sender(), 2);
//         assert_eq!(rate_limiter.decide_current_sender(), 0);
//     }

//     #[tokio::test]
//     async fn test_check_current_sent_bytes_allow() {
//         let config = create_test_config(1, 1); // 1 Mbit/s
//         let (tx, _rx) = tokio::sync::mpsc::channel(10);

//         let rate_limiter = RateLimiter {
//             config: config.clone(),
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)),
//             current_sender: AtomicUsize::new(0),
//             sender_list: SenderChan::Packet(tx),
//         };

//         // Packet size is 60 (IPv4 TCP)
//         // assembler_size is 1
//         // Request should succeed immediately
//         let packets = rate_limiter
//             .check_current_sent_bytes(None)
//             .await
//             .expect("Should succeed");
//         assert_eq!(packets, 1);

//         // Check that bytes were added
//         assert_eq!(rate_limiter.current_sent_bytes.load(Ordering::SeqCst), 60);
//     }

//     #[tokio::test]
//     async fn test_check_current_sent_bytes_block_and_timeout() {
//         let config = create_test_config(1, 1); // 1 Mbit/s = 125,000 Bytes/s
//         let (tx, _rx) = tokio::sync::mpsc::channel(10);

//         let rate_limiter = RateLimiter {
//             config: config.clone(),
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)), // Start at 0
//             current_sender: AtomicUsize::new(0),
//             sender_list: SenderChan::Packet(tx),
//         };

//         // Calculate limit in bytes
//         let limit_bytes = 1_000_000 / 8;

//         // Force a block by filling the budget
//         rate_limiter
//             .current_sent_bytes
//             .store(limit_bytes, Ordering::SeqCst);

//         let result_timeout = rate_limiter.check_current_sent_bytes(None).await;

//         match result_timeout {
//             Err(e) => {
//                 assert_eq!(e.err, ScanErr::RateLimiting);
//                 assert!(e.msg.contains("timeout"));
//             }
//             Ok(_) => panic!("Should have timed out"),
//         }
//     }

//     #[tokio::test]
//     async fn test_start_spawning_from_chan_integration() {
//         // Setup
//         let config = create_test_config(10000, 1); // High rate
//         let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(10);
//         let (ip_tx, ip_rx) = tokio::sync::mpsc::channel(10);
//         let (_broadcaster_tx, broadcaster_rx) = tokio::sync::mpsc::channel(10);

//         let mut rate_limiter = RateLimiter {
//             config: config.clone(),
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)),
//             current_sender: AtomicUsize::new(0),
//             sender_list: SenderChan::PacketList(vec![packet_tx]),
//         };

//         // Feed IPs
//         let ip1 = [192, 168, 1, 1];
//         let ip2 = [192, 168, 1, 2];
//         ip_tx.send(ip1).await.unwrap();
//         ip_tx.send(ip2).await.unwrap();
//         // Send stop IP to stop the loop gracefully and process pending IPs
//         ip_tx.send([0, 0, 0, 0]).await.unwrap();

//         // Run
//         let (dst_ips, handles) = rate_limiter
//             .start_spawning_from_chan(ReceiverChan::ParsedIpv4(ip_rx), broadcaster_rx, Some(0))
//             .await
//             .expect("Spawning failed");

//         // Wait for handles
//         for h in handles {
//             h.await.unwrap();
//         }

//         // Verify IPs were buffered
//         if let AssemblerDstIps::Ipv4(ips) = dst_ips {
//             assert!(ips.contains(&ip1));
//             assert!(ips.contains(&ip2));
//         } else {
//             panic!("Wrong IP type returned");
//         }

//         // Verify packets were "sent" (put into channel)
//         // We expect 2 packets
//         let mut count = 0;
//         while packet_rx.try_recv().is_ok() {
//             count += 1;
//         }
//         assert_eq!(count, 2);
//     }

//     #[tokio::test]
//     async fn test_start_spawning_from_buf_integration() {
//         let config = create_test_config(10000, 1);
//         let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(10);
//         let (_broadcaster_tx, broadcaster_rx) = tokio::sync::mpsc::channel(10);

//         let mut rate_limiter = RateLimiter {
//             config: config.clone(),
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)),
//             current_sender: AtomicUsize::new(0),
//             sender_list: SenderChan::PacketList(vec![packet_tx]),
//         };

//         let ips = vec![[192, 168, 1, 1], [192, 168, 1, 2]];
//         let dst_ip_buf = AssemblerDstIps::Ipv4(ips.clone());

//         let handles = rate_limiter
//             .start_spawning_from_buf(dst_ip_buf, broadcaster_rx, Some(0))
//             .await
//             .expect("Spawning from buf failed");

//         for h in handles {
//             h.await.unwrap();
//         }

//         let mut count = 0;
//         while packet_rx.try_recv().is_ok() {
//             count += 1;
//         }
//         assert_eq!(count, 2);
//     }

//     #[tokio::test]
//     async fn test_retry_logic() {
//         // Manually create config with retries = 1
//         let config = Arc::new(EmissionConfig {
//             retries: 1, // 1 retry means 2 sends total
//             ipv6: false,
//             protocol: 6,
//             batch_size: 1,
//             scan_rate: 10000,
//             templates: vec![vec![0u8; 60]], // Dummy template
//             send_in_batches: false,
//             assembler_size: 1,
//             parsing_timeout_millis: 100,
//             xdp: false,
//             num_nic_queues: 1,
//             reset: false,
//             dst_mac: MacAddr::zero(),
//             src_mac: MacAddr::zero(),
//             dst_ports: vec![80],
//             interface: "eno1".to_string(),
//             hash_keys: HashKeys { k0: None, k1: None },
//         });

//         let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel(10);
//         let (ip_tx, ip_rx) = tokio::sync::mpsc::channel(10);
//         let (_broadcaster_tx, broadcaster_rx) = tokio::sync::mpsc::channel(10);

//         let mut rate_limiter = RateLimiter {
//             config: config.clone(),
//             current_template: Arc::new(AtomicUsize::new(0)),
//             current_sent_bytes: Arc::new(AtomicUsize::new(0)),
//             current_sender: AtomicUsize::new(0),
//             sender_list: SenderChan::PacketList(vec![packet_tx]),
//         };

//         ip_tx.send([192, 168, 1, 1]).await.unwrap();
//         ip_tx.send([0, 0, 0, 0]).await.unwrap(); // Stop signal

//         let (_, handles) = rate_limiter
//             .start_spawning_from_chan(ReceiverChan::ParsedIpv4(ip_rx), broadcaster_rx, Some(0))
//             .await
//             .expect("Spawning failed");

//         for h in handles {
//             h.await.unwrap();
//         }

//         let mut count = 0;
//         while packet_rx.try_recv().is_ok() {
//             count += 1;
//         }
//         // 1 IP * (1 initial + 1 retry) = 2 packets
//         assert_eq!(count, 2);
//     }
// }
