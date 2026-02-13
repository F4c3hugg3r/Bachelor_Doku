use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::scan_utils::shared::types_and_config::{
    FINISH, GivenConfig, ScanErr, ScannerErrWithMsg, SenderChan,
};

pub struct StdInParser<R> {
    pub dst_ip_sender: Option<SenderChan>,
    pub buf_reader: BufReader<R>,
}

impl<R: AsyncRead + Unpin + Send> StdInParser<R> {
    pub async fn parse_config(&mut self) -> Result<GivenConfig, ScannerErrWithMsg> {
        let config_string = self.listen_stdin_until_newline("\n").await?;

        let mut config: GivenConfig =
            serde_json::from_str(&config_string).map_err(|e| ScannerErrWithMsg {
                err: ScanErr::Parsing,
                msg: format!("error parsing config: {:?}", e),
            })?;

        // parses the dst_mac out of the first template
        if config.templates.is_empty() || config.templates[0].len() < 12 {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Config,
                msg: "Template too short to extract MAC addresses".to_string(),
            });
        }

        config.dst_mac = match config.templates[0][0..6].try_into() {
            Ok(mac) => mac,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: format!("Failed to get dst_mac: {:?}", e),
                });
            }
        };

        // parses the src_mac out of the first template
        config.src_mac = match config.templates[0][6..12].try_into() {
            Ok(mac) => mac,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: format!("Failed to get dst_mac: {:?}", e),
                });
            }
        };

        // EMITTING TEST
        // eprintln!("config correctely parsed: {:?}", config);

        Ok(config)
    }

    /// parse_dst_ipv4s parses ipv4 addresses from the stdIn or a file until [0][0][0][0] is read or EOF (if file)
    pub async fn parse_dst_ipv4s(
        &mut self,
        file_path: Option<String>,
        bytes_format: bool,
    ) -> Result<(), ScannerErrWithMsg> {
        let sender = match &mut self.dst_ip_sender {
            Some(SenderChan::ParsedIpv4(sender)) => sender,
            _ => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: "No valid ParsedIpv4 sender in dst_ip_sender".to_string(),
                });
            }
        };

        if let Some(path) = &file_path
            && !bytes_format
        {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error opening file: {:?}", e),
                })?;
            let mut reader = BufReader::new(file);
            let mut line_buf = String::new();
            let mut ip_batch: Vec<[u8; 4]> = Vec::with_capacity(2048);

            loop {
                line_buf.clear();
                let bytes_read =
                    reader
                        .read_line(&mut line_buf)
                        .await
                        .map_err(|e| ScannerErrWithMsg {
                            err: ScanErr::Parsing,
                            msg: format!("error reading line: {:?}", e),
                        })?;

                if bytes_read == 0 {
                    break;
                }

                let line = line_buf.trim();
                if line.is_empty() {
                    continue;
                }
                let ip: std::net::Ipv4Addr = line.parse().map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error parsing ipv4 string: {:?}", e),
                })?;

                ip_batch.push(ip.octets());

                if ip_batch.len() >= 2048 {
                    let batch = std::mem::replace(&mut ip_batch, Vec::with_capacity(2048));
                    sender.send(batch).await.map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error sending ipv4 batch: {:?}", e),
                    })?;
                }
            }
            // Send remaining IPs
            if !ip_batch.is_empty() {
                sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error sending ipv4 batch: {:?}", e),
                })?;
            }

            eprintln!("Finished parsing file, sending terminator");
            if let Err(e) = sender.send(vec![[0, 0, 0, 0]]).await {
                eprintln!("Error sending terminator after EOF: {:?}", e);
            }
            return Ok(());
        }

        // Binary Parsing (Batched reading for High Performance)
        let mut file_handle: Option<tokio::fs::File> = None;
        let reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send) = if let Some(path) = &file_path
        {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error opening file: {:?}", e),
                })?;
            file_handle = Some(file);
            file_handle.as_mut().unwrap()
        } else {
            &mut self.buf_reader
        };

        const BATCH_SIZE: usize = 8192; // Read 8KB chunks (2048 IPs)
        let mut buffer = [0u8; BATCH_SIZE];
        let mut offset = 0;
        let mut ip_batch: Vec<[u8; 4]> = Vec::with_capacity(BATCH_SIZE / 4);

        loop {
            // Read into the available portion of the buffer
            let read_len =
                reader
                    .read(&mut buffer[offset..])
                    .await
                    .map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error reading ipv4 stream: {:?}", e),
                    })?;

            if read_len == 0 {
                // EOF Reached
                if !ip_batch.is_empty() {
                    sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error sending ipv4 batch: {:?}", e),
                    })?;
                }
                if file_path.is_some() {
                    // For files, implicit EOF implies done. Send terminator.
                    if let Err(e) = sender.send(vec![[0, 0, 0, 0]]).await {
                        eprintln!("Error sending terminator after EOF: {:?}", e);
                    }
                    return Ok(());
                } else {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: "Unexpected EOF on stdin without terminator".to_string(),
                    });
                }
            }

            let valid_data_len = offset + read_len;
            let mut cursor = 0;

            // Process full IP packets in the buffer
            while cursor + 4 <= valid_data_len {
                let bytes: [u8; 4] = buffer[cursor..cursor + 4].try_into().unwrap();
                cursor += 4;

                if bytes == [0, 0, 0, 0] {
                    ip_batch.push(bytes);
                    // Send accumulated batch with terminator before returning
                    if !ip_batch.is_empty() {
                        sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                            err: ScanErr::Parsing,
                            msg: format!("error sending ipv4 batch: {:?}", e),
                        })?;
                    }
                    return Ok(());
                }

                ip_batch.push(bytes);
            }

            // If we have collected IPs, send them as a batch now
            if !ip_batch.is_empty() {
                let batch = std::mem::replace(&mut ip_batch, Vec::with_capacity(BATCH_SIZE / 4));
                sender.send(batch).await.map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error sending ipv4 batch: {:?}", e),
                })?;
            }

            // Move remaining fragmented bytes to the start of the buffer
            let remaining = valid_data_len - cursor;
            if remaining > 0 {
                buffer.copy_within(cursor..valid_data_len, 0);
            }
            offset = remaining;
        }
    }

    pub async fn parse_dst_ipv6s(
        &mut self,
        file_path: Option<String>,
        bytes_format: bool,
    ) -> Result<(), ScannerErrWithMsg> {
        let sender = match &mut self.dst_ip_sender {
            Some(SenderChan::ParsedIpv6(sender)) => sender,
            _ => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: "No valid ParsedIpv6 sender in dst_ip_sender".to_string(),
                });
            }
        };

        if let Some(path) = &file_path
            && !bytes_format
        {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error opening file: {:?}", e),
                })?;
            let mut reader = BufReader::new(file);
            let mut line_buf = String::new();
            let mut ip_batch: Vec<[u8; 16]> = Vec::with_capacity(1024);

            loop {
                line_buf.clear();
                let bytes_read =
                    reader
                        .read_line(&mut line_buf)
                        .await
                        .map_err(|e| ScannerErrWithMsg {
                            err: ScanErr::Parsing,
                            msg: format!("error reading line: {:?}", e),
                        })?;

                if bytes_read == 0 {
                    break;
                }

                let line = line_buf.trim();
                if line.is_empty() {
                    continue;
                }
                let ip: std::net::Ipv6Addr = line.parse().map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error parsing ipv6 string: {:?}", e),
                })?;

                ip_batch.push(ip.octets());

                if ip_batch.len() >= 1024 {
                    let batch = std::mem::replace(&mut ip_batch, Vec::with_capacity(1024));
                    sender.send(batch).await.map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error sending ipv6 batch: {:?}", e),
                    })?;
                }
            }

            // Send remaining IPs
            if !ip_batch.is_empty() {
                sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error sending ipv6 batch: {:?}", e),
                })?;
            }

            if let Err(e) = sender.send(vec![[0; 16]]).await {
                eprintln!("[parser] Error sending terminator after EOF: {:?}", e);
            }
            return Ok(());
        }

        // Binary Parsing (Batched reading for High Performance)
        let mut file_handle: Option<tokio::fs::File> = None;
        let reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send) = if let Some(path) = &file_path
        {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error opening file: {:?}", e),
                })?;
            file_handle = Some(file);
            file_handle.as_mut().unwrap()
        } else {
            &mut self.buf_reader
        };

        const BATCH_SIZE: usize = 16 * 1024;
        let mut buffer = [0u8; BATCH_SIZE];
        let mut offset = 0;
        let mut ip_batch: Vec<[u8; 16]> = Vec::with_capacity(BATCH_SIZE / 16);

        loop {
            // Read into the available portion of the buffer
            let read_len =
                reader
                    .read(&mut buffer[offset..])
                    .await
                    .map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error reading ipv6 stream: {:?}", e),
                    })?;

            if read_len == 0 {
                // EOF Reached
                if !ip_batch.is_empty() {
                    sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: format!("error sending ipv6 batch: {:?}", e),
                    })?;
                }

                if file_path.is_some() {
                    if let Err(e) = sender.send(vec![[0; 16]]).await {
                        eprintln!("Error sending terminator after EOF: {:?}", e);
                    }
                    return Ok(());
                } else {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Parsing,
                        msg: "Unexpected EOF on stdin without terminator".to_string(),
                    });
                }
            }

            let valid_data_len = offset + read_len;
            let mut cursor = 0;

            // Process full IP packets in the buffer
            while cursor + 16 <= valid_data_len {
                let bytes: [u8; 16] = buffer[cursor..cursor + 16].try_into().unwrap();
                cursor += 16;

                if bytes == [0u8; 16] {
                    ip_batch.push(bytes);
                    // Send accumulated batch before returning
                    if !ip_batch.is_empty() {
                        sender.send(ip_batch).await.map_err(|e| ScannerErrWithMsg {
                            err: ScanErr::Parsing,
                            msg: format!("error sending ipv6 batch: {:?}", e),
                        })?;
                    }
                    return Ok(());
                }

                ip_batch.push(bytes);
            }

            // If we have collected IPs, send them as a batch now
            if !ip_batch.is_empty() {
                let batch = std::mem::replace(&mut ip_batch, Vec::with_capacity(BATCH_SIZE / 16));
                sender.send(batch).await.map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error sending ipv6 batch: {:?}", e),
                })?;
            }

            // Move remaining fragmented bytes to the start of the buffer
            let remaining = valid_data_len - cursor;
            if remaining > 0 {
                buffer.copy_within(cursor..valid_data_len, 0);
            }
            offset = remaining;
        }
    }

    pub async fn listen_for_signal(
        &mut self,
        broadcast_tx: Sender<String>,
        mut signal_rx: Receiver<String>,
    ) -> Result<(), ScannerErrWithMsg> {
        loop {
            let signal = tokio::select! {
                signal = signal_rx.recv() => {
                    signal.ok_or_else(|| ScannerErrWithMsg {
                            err: ScanErr::Config,
                            msg: "error receiving signal".to_string(),
                        })?
                    },
                signal = self.listen_stdin_until_newline("\n") => { match signal {
                    Ok(signal) => signal,
                    Err(_) => FINISH.to_string(),
                }},
            };
            // TEST
            //eprintln!("Signal arrived: {}", signal);
            broadcast_tx
                .send(signal.clone())
                .await
                .map_err(|e| ScannerErrWithMsg {
                    err: ScanErr::Parsing,
                    msg: format!("error sending signal: {:?}", e),
                })?;
            if signal == FINISH {
                return Ok(());
            }
        }
    }

    /// listen_stdin_until_newline reads from the stdIn until the delimiter is found and returns the string
    async fn listen_stdin_until_newline(
        &mut self,
        delimiter: &str,
    ) -> Result<String, ScannerErrWithMsg> {
        let mut buffer: Vec<u8> = Vec::new();

        let delimiter_byte = delimiter.as_bytes()[0];
        self.buf_reader
            .read_until(delimiter_byte, &mut buffer)
            .await
            .unwrap();

        match String::from_utf8(buffer).unwrap().strip_suffix(delimiter) {
            None => Err(ScannerErrWithMsg {
                err: ScanErr::Input,
                msg: String::from("error parsing until newline: wrong input"),
            }),
            Some(config) => Ok(String::from(config)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_utils::shared::types_and_config::SenderChan;
    use std::io::Cursor;
    use tokio::sync::mpsc;

    fn create_dummy_template() -> Vec<u8> {
        // Need at least 12 bytes for dst_mac (0..6) and src_mac (6..12)
        let mut t = vec![0u8; 60];
        // Set some values to verify extraction
        t[0] = 0xAA;
        t[1] = 0xBB;
        t[2] = 0xCC;
        t[3] = 0xDD;
        t[4] = 0xEE;
        t[5] = 0xFF; // Dst MAC
        t[6] = 0x11;
        t[7] = 0x22;
        t[8] = 0x33;
        t[9] = 0x44;
        t[10] = 0x55;
        t[11] = 0x66; // Src MAC
        t
    }

    fn create_valid_config_json() -> String {
        let template = create_dummy_template();
        let template_json = serde_json::to_string(&vec![template]).unwrap();

        // Compact JSON without newlines to avoid confusing the newline-delimited reader
        format!(
            r#"{{"ScanID":123,"IPv6":false,"Protocol":6,"ScanRate":100,"Templates":{},"Reset":false,"Retries":0,"DstPorts":[80],"SrcPorts":[12345],"SrcIPs":[[192,168,0,1]]}}"#,
            template_json
        )
    }

    #[tokio::test]
    async fn test_parse_config_valid() {
        let json = create_valid_config_json();
        // Add newline as delimiter
        let input = format!("{}\n", json);
        let cursor = Cursor::new(input.into_bytes());

        let mut parser = StdInParser {
            dst_ip_sender: None,
            buf_reader: BufReader::new(cursor),
        };

        let config = parser
            .parse_config()
            .await
            .expect("Should parse valid config");

        assert_eq!(config.scan_id, 123);
        assert_eq!(config.dst_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(config.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[tokio::test]
    async fn test_parse_config_invalid_json() {
        let input = "{ invalid json }\n";
        let cursor = Cursor::new(input.as_bytes());

        let mut parser = StdInParser {
            dst_ip_sender: None,
            buf_reader: BufReader::new(cursor),
        };

        let result = parser.parse_config().await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().err, ScanErr::Parsing);
    }

    #[tokio::test]
    async fn test_parse_config_short_template() {
        // Template too short for MAC extraction
        let template = vec![0u8; 5];
        let template_json = serde_json::to_string(&vec![template]).unwrap();
        let json = format!(
            r#"{{"ScanID":123,"IPv6":false,"Protocol":6,"ScanRate":100,"Templates":{},"Reset":false,"Retries":0,"DstPorts":[80],"SrcPorts":[12345],"SrcIPs":[[192,168,0,1]]}}"#,
            template_json
        );

        let input = format!("{}\n", json);
        let cursor = Cursor::new(input.into_bytes());

        let mut parser = StdInParser {
            dst_ip_sender: None,
            buf_reader: BufReader::new(cursor),
        };

        let result = parser.parse_config().await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().err, ScanErr::Config);
    }

    #[tokio::test]
    async fn test_parse_dst_ipv4s_from_reader_binary() {
        // 2 IPs: 192.168.1.1, 192.168.1.2, then terminator
        let mut data = Vec::new();
        data.extend_from_slice(&[192, 168, 1, 1]);
        data.extend_from_slice(&[192, 168, 1, 2]);
        data.extend_from_slice(&[0, 0, 0, 0]);

        let cursor = Cursor::new(data);
        let (tx, mut rx) = mpsc::channel(10);

        let mut parser = StdInParser {
            dst_ip_sender: Some(SenderChan::ParsedIpv4(tx)),
            buf_reader: BufReader::new(cursor),
        };

        parser
            .parse_dst_ipv4s(None, true)
            .await
            .expect("Parsing failed");

        let batch = rx.recv().await.expect("Expected batch");
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0], [192, 168, 1, 1]);
        assert_eq!(batch[1], [192, 168, 1, 2]);
        assert_eq!(batch[2], [0, 0, 0, 0]);
        // Expect no more messages (channel likely closed or empty)
        // With explicit terminator sent, and then return Ok(()), sender is dropped.
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_parse_dst_ipv6s_from_reader_binary() {
        let mut data = Vec::new();
        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let term = [0u8; 16];

        data.extend_from_slice(&ip1);
        data.extend_from_slice(&ip2);
        data.extend_from_slice(&term);

        let cursor = Cursor::new(data);
        let (tx, mut rx) = mpsc::channel(10);

        let mut parser = StdInParser {
            dst_ip_sender: Some(SenderChan::ParsedIpv6(tx)),
            buf_reader: BufReader::new(cursor),
        };

        parser
            .parse_dst_ipv6s(None, true)
            .await
            .expect("Parsing failed");

        let batch = rx.recv().await.expect("Expected batch");
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0], ip1);
        assert_eq!(batch[1], ip2);
        assert_eq!(batch[2], term);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn test_listen_for_signal() {
        let (broadcast_tx, mut broadcast_rx) = mpsc::channel(10);
        let (signal_tx, signal_rx) = mpsc::channel(10);

        // Use duplex to simulate open stream that sends nothing (blocks read)
        // This ensures listen_stdin_until_newline waits, allowing signal_rx to be processed
        let (client, _server) = tokio::io::duplex(64);

        let mut parser = StdInParser {
            dst_ip_sender: None,
            buf_reader: BufReader::new(client),
        };

        tokio::spawn(async move {
            // Give the select! a chance to poll both
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            signal_tx.send("stop".to_string()).await.unwrap();
            signal_tx.send("finish".to_string()).await.unwrap();
        });

        parser
            .listen_for_signal(broadcast_tx, signal_rx)
            .await
            .expect("Listen failed");

        assert_eq!(broadcast_rx.recv().await, Some("stop".to_string()));
        assert_eq!(broadcast_rx.recv().await, Some("finish".to_string()));
    }
}
