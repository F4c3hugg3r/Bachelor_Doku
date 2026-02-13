use crate::Args;
use crate::scan_utils::job_controlling::finish_broadcaster::SignalBroadcaster;
use std::sync::{self, Arc};
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use tokio::io::{BufReader, Stdin};
use tokio::sync::mpsc::{Receiver, Sender, channel};

use crate::scan_utils::capturing_packets::receiver::PacketReceiver;
use crate::scan_utils::emitting_packets::rate_limiter::RateLimiter;
use crate::scan_utils::emitting_packets::sender::PacketSender;
use crate::scan_utils::job_controlling::parser_std_in::StdInParser;
use crate::scan_utils::shared::helper;
use crate::scan_utils::shared::types_and_config::{
    CONTINUE, CaptureConfig, EmissionConfig, FINISH, ReceiverChan, ScannerErrWithMsg,
};
use std::thread;
use thread_priority::ThreadPriority;

struct Cleanup {
    pub tx_signal: Sender<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let tx_signal = self.tx_signal.clone();
        tokio::spawn(async move {
            let _ = tx_signal.send(FINISH.to_string()).await;
        });
    }
}

pub struct ScanJob;

impl ScanJob {
    pub async fn start_scanjob(
        args: Args,
        emission_config: Arc<EmissionConfig>,
        capture_config: Arc<CaptureConfig>,
        parser: StdInParser<Stdin>,
        events: RingBuf<MapData>,
    ) -> (Sender<String>, Receiver<String>) {
        let (tx_signal, rx_signal) = channel(100); // extern stop
        let (tx_scanning_finished, rx_scanning_finished) = channel(10); // scanjob finished signal
        let tx_signal_clone = tx_signal.clone();

        tokio::spawn(async move {
            Self::scan(
                args,
                emission_config,
                capture_config,
                parser,
                rx_signal,
                tx_signal_clone,
                tx_scanning_finished,
                events,
            )
            .await;
        });

        (tx_signal, rx_scanning_finished)
    }

    async fn scan(
        args: Args,
        emission_config: Arc<EmissionConfig>,
        capture_config: Arc<CaptureConfig>,
        mut parser: StdInParser<Stdin>,
        rx_signal: Receiver<String>,
        tx_signal: Sender<String>,
        scanning_finished: Sender<String>,
        mut events: RingBuf<MapData>,
    ) {
        let num_nic_queues = emission_config.num_nic_queues;
        let (file_path, bytes_format) = if args.bytes_file_path.is_empty() {
            if args.string_file_path.is_empty() {
                (None, false)
            } else {
                (Some(args.string_file_path), false)
            }
        } else {
            (Some(args.bytes_file_path), true)
        };

        let mut handles = Vec::new();

        // Signals
        let (broadcast_tx, broadcast_rx) = tokio::sync::mpsc::channel(100);
        let (signal_receiver, broadcast_handle) = SignalBroadcaster::start(broadcast_rx);

        let (parsed_dst_ip_sender, parsed_dst_ip_receiver) =
            helper::create_dst_ip_channels(emission_config.ipv6);

        parser.dst_ip_sender = Some(parsed_dst_ip_sender);

        // Start parsing from stdIn: Ips
        let broadcast_tx_clone = broadcast_tx.clone();
        if emission_config.ipv6 {
            let handle = tokio::spawn(async move {
                if let Err(e) = parser.parse_dst_ipv6s(file_path, bytes_format).await {
                    eprintln!("{:?}: {}", e.err, e.msg);
                };
                tokio::spawn(async move {
                    if let Err(e) = parser
                        .listen_for_signal(broadcast_tx_clone, rx_signal)
                        .await
                    {
                        eprintln!("{:?}: {}", e.err, e.msg);
                    };
                });
            });
            handles.push(handle);
        } else {
            let handle = tokio::spawn(async move {
                if let Err(e) = parser.parse_dst_ipv4s(file_path, bytes_format).await {
                    eprintln!("{:?}: {}", e.err, e.msg);
                };
                tokio::spawn(async move {
                    if let Err(e) = parser
                        .listen_for_signal(broadcast_tx_clone, rx_signal)
                        .await
                    {
                        eprintln!("{:?}: {}", e.err, e.msg);
                    };
                });
            });
            handles.push(handle);
        }

        // Complement config with flags
        let _cleanup = Cleanup {
            tx_signal: tx_signal.clone(),
        };

        // Create channels to link the modules with
        let (sender_list, receiver_list) = helper::create_sender_receiver_lists(
            emission_config.num_nic_queues,
            emission_config.send_in_batches,
        );
        // let (tx_rst, rx_rst) = crossbeam::channel::unbounded(); // obsolete if rst isn't being sent manually
        let (tx_notify_receiver, rx_notify_receiver) = tokio::sync::mpsc::channel(10); // signal for receiver

        // sleep to ensure link reset is
        // if emission_config.xdp {
        eprintln!("waiting for link reset...");
        tokio::time::sleep(Duration::from_secs(5)).await;
        // }

        // Start capturing & Sending
        if emission_config.xdp {
            match helper::create_xdp_bi_sockets(
                num_nic_queues,
                emission_config.interface.clone(),
                emission_config.zero_copy,
            ) {
                Ok((tx, _)) => {
                    let cc_clone = capture_config.clone();
                    let async_handle = tokio::spawn(async move {
                        if let Err(e) =
                            PacketReceiver::start_receiving(cc_clone, rx_notify_receiver, events)
                                .await
                        {
                            eprintln!("{:?}: {}", e.err, e.msg);
                        };
                    });
                    handles.push(async_handle);
                    let ec_clone = emission_config.clone();
                    let async_handle = tokio::spawn(async move {
                        if let Err(e) = PacketSender::start_sending(
                            receiver_list,
                            ec_clone,
                            tx_notify_receiver,
                            Some(tx),
                        )
                        .await
                        {
                            eprintln!("{:?}: {}", e.err, e.msg);
                        };
                    });
                    handles.push(async_handle);
                }
                Err(e) => {
                    eprintln!(
                        "error sending 'capture started' signal: {:?}: {}",
                        e.err, e.msg
                    );
                }
            };
        } else {
            let cc_clone = capture_config.clone();
            let async_handle = tokio::spawn(async move {
                if let Err(e) =
                    PacketReceiver::start_receiving(cc_clone, rx_notify_receiver, events).await
                {
                    eprintln!("{:?}: {}", e.err, e.msg);
                };
            });
            handles.push(async_handle);
            let ec_clone = emission_config.clone();
            let async_handle = tokio::spawn(async move {
                if let Err(e) =
                    PacketSender::start_sending(receiver_list, ec_clone, tx_notify_receiver, None)
                        .await
                {
                    eprintln!("{:?}: {}", e.err, e.msg);
                };
            });
            handles.push(async_handle);
        };

        // // wait for capture and send sockets to be ready
        // match rx_sockets_ready.recv().await {
        //     Some(msg) if msg == FINISH => {
        //         return;
        //     }
        //     Some(msg) if msg == CONTINUE => {}
        //     None => {
        //         eprintln!("error waiting for capture start");
        //     }
        //     _ => unreachable!("wait_for_capture string must be FINISH or CONTINUE"),
        // }

        // Start emitting (assembling)
        let ec_clone = emission_config.clone();
        let handle = tokio::spawn(async move {
            RateLimiter::start_emitting(
                ec_clone,
                sender_list,
                parsed_dst_ip_receiver,
                signal_receiver.rx_rate_limiter,
            )
            .await;
        });
        handles.push(handle);

        // Wait until everything is done
        for handle in handles {
            if let Err(e) = handle.await {
                eprintln!("{:?}", e);
            };
        }

        // TEST
        if let Err(e) = tx_signal.send(FINISH.to_string()).await {
            eprintln!("error sending finish {:?}", e);
        };
        if let Err(e) = broadcast_handle.await {
            eprintln!("{:?}", e);
        };

        if let Err(e) = scanning_finished.send(FINISH.to_string()).await {
            eprintln!("error sending scanning_finished {:?}", e);
        };
    }
}
