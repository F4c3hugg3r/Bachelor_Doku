use tokio::{
    sync::mpsc::{Receiver, channel},
    task::JoinHandle,
};

use crate::scan_utils::shared::types_and_config::{
    FINISH, ScanErr, ScannerErrWithMsg, SignalReceiver, SignalSender,
};

pub struct SignalBroadcaster {
    signal_rx: Receiver<String>,
    signal_sender: SignalSender,
}

impl SignalBroadcaster {
    pub fn start(signal_rx: Receiver<String>) -> (SignalReceiver, JoinHandle<()>) {
        let (tx, rx) = channel(100);
        let signal_receiver = SignalReceiver {
            rx_rate_limiter: rx,
        };
        let signal_sender = SignalSender {
            tx_rate_limiter: tx,
        };
        let signal_broadcaster = Self {
            signal_rx,
            signal_sender,
        };

        let handle = tokio::spawn(async move {
            if let Err(e) = signal_broadcaster.start_broadcaster().await {
                eprintln!("{:?}: {}", e.err, e.msg);
            }
        });
        (signal_receiver, handle)
    }

    async fn start_broadcaster(mut self) -> Result<(), ScannerErrWithMsg> {
        loop {
            let signal = self
                .signal_rx
                .recv()
                .await
                .ok_or_else(|| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: "Error receiving signal".to_string(),
                })?;

            // TEST
            eprintln!("Broadcaster received signal: {}", signal);

            for sender in self.signal_sender.into_iter() {
                let _ = sender.send(signal.clone()).await;
            }

            if signal == FINISH {
                return Ok(());
            }
        }
    }
}
