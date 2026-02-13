use std::sync::{Arc, atomic::AtomicUsize};

use siphasher::sip::SipHasher24;

use crate::scan_utils::shared::types_and_config::{
    HashKeys, ScanErr, ScannerErrWithMsg, TCP_IPV4_PACKET_SIZE, TCP_IPV6_PACKET_SIZE,
};
use crate::scan_utils::shared::{
    self,
    types_and_config::{AssemblerDstIps, EmissionConfig, SenderChan},
};
use std::sync::atomic::Ordering;

#[derive(Debug)]
pub struct PacketAssembler {
    dst_ips: AssemblerDstIps,
    sender_chan: SenderChan,
    // loading and writing should be Ordering::Relaxed for maximum performance
    current_template: Arc<AtomicUsize>,
    config: Arc<EmissionConfig>,
}

impl PacketAssembler {
    pub async fn assemble_packets(
        dst_ips: AssemblerDstIps,
        sender_chan: SenderChan,
        current_template: Arc<AtomicUsize>,
        config: Arc<EmissionConfig>,
        dst_port_index: Option<usize>,
    ) -> Result<(), ScannerErrWithMsg> {
        // EMITTING TEST
        // eprintln!(
        //     "assembler spawned with dst_ips_ipv4s: {:?}, send in batches: {}",
        //     dst_ips.ipv4, config.send_in_batches
        // );

        let mut packet_assembler = Self {
            dst_ips,
            sender_chan,
            current_template,
            config,
        };

        packet_assembler.assemble_and_send(dst_port_index).await?;
        Ok(())
    }

    async fn assemble_and_send(
        &mut self,
        dst_port_index: Option<usize>,
    ) -> Result<(), ScannerErrWithMsg> {
        let dst_port: Option<[u8; 2]> = if let Some(index) = dst_port_index {
            Some(self.config.dst_ports[index].to_be_bytes())
        } else {
            None
        };
        match &self.dst_ips {
            AssemblerDstIps::Ipv4(ipv4s) => match &self.sender_chan {
                SenderChan::Packet(sender) if !self.config.send_in_batches => {
                    let mut packet: Vec<u8> = Vec::with_capacity(TCP_IPV4_PACKET_SIZE);
                    for dst_ip in ipv4s {
                        let template = &self.config.templates[self.decide_current_template()];
                        Self::complement_template_tcp_ipv4(
                            &self.config.hash_keys,
                            template,
                            *dst_ip,
                            dst_port,
                            &mut packet,
                        )
                        .await?;
                        if let Err(e) = sender.send(packet).await {
                            return Err(ScannerErrWithMsg {
                                err: ScanErr::Assembling,
                                msg: format!("Failed to submit packet to sender: {:?}", e),
                            });
                        }
                        packet = Vec::with_capacity(TCP_IPV4_PACKET_SIZE);
                    }
                }
                SenderChan::Batch(sender) if self.config.send_in_batches => {
                    let batch_size = self.config.batch_size;
                    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
                    for batch_ips in ipv4s.chunks(batch_size) {
                        for dst_ip in batch_ips {
                            let template = &self.config.templates[self.decide_current_template()];
                            let mut packet: Vec<u8> = Vec::with_capacity(TCP_IPV4_PACKET_SIZE);
                            Self::complement_template_tcp_ipv4(
                                &self.config.hash_keys,
                                template,
                                *dst_ip,
                                dst_port,
                                &mut packet,
                            )
                            .await?;
                            batch.push(packet);
                        }
                        if let Err(e) = sender.send(batch).await {
                            return Err(ScannerErrWithMsg {
                                err: ScanErr::Assembling,
                                msg: format!("Failed to submit batch to sender: {:?}", e),
                            });
                        }
                        batch = Vec::with_capacity(batch_size);
                    }
                }
                _ => {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Assembling,
                        msg: "Sender channel type does not match config.send_in_batches for IPv4"
                            .to_string(),
                    });
                }
            },
            AssemblerDstIps::Ipv6(ipv6s) => match &self.sender_chan {
                SenderChan::Packet(sender) if !self.config.send_in_batches => {
                    let mut packet: Vec<u8> = Vec::with_capacity(TCP_IPV6_PACKET_SIZE);
                    for dst_ip in ipv6s {
                        let template = &self.config.templates[self.decide_current_template()];
                        Self::complement_template_tcp_ipv6(
                            &self.config.hash_keys,
                            template,
                            *dst_ip,
                            dst_port,
                            &mut packet,
                        )
                        .await?;
                        if let Err(e) = sender.send(packet).await {
                            return Err(ScannerErrWithMsg {
                                err: ScanErr::Assembling,
                                msg: format!("Failed to submit packet to sender: {:?}", e),
                            });
                        }
                        packet = Vec::with_capacity(TCP_IPV6_PACKET_SIZE);
                    }
                }
                SenderChan::Batch(sender) if self.config.send_in_batches => {
                    let batch_size = self.config.batch_size;
                    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
                    for batch_ips in ipv6s.chunks(batch_size) {
                        for dst_ip in batch_ips {
                            let template = &self.config.templates[self.decide_current_template()];
                            let mut packet: Vec<u8> = Vec::with_capacity(TCP_IPV6_PACKET_SIZE);
                            Self::complement_template_tcp_ipv6(
                                &self.config.hash_keys,
                                template,
                                *dst_ip,
                                dst_port,
                                &mut packet,
                            )
                            .await?;
                            batch.push(packet);
                        }
                        if let Err(e) = sender.send(batch).await {
                            return Err(ScannerErrWithMsg {
                                err: ScanErr::Assembling,
                                msg: format!("Failed to submit batch to sender: {:?}", e),
                            });
                        }
                        batch = Vec::with_capacity(batch_size);
                    }
                }
                _ => {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Assembling,
                        msg: "Sender channel type does not match config.send_in_batches for IPv6"
                            .to_string(),
                    });
                }
            },
        }
        Ok(())
    }

    /// NOTICE: geht davon aus, dass an den vorgesehenen Stellen für dst_ip und seq_number leere Werte
    /// eingetragen sind, ansonsten müssen die bisherigen checksum Werte zusätzlich abgezogen werden
    async fn complement_template_tcp_ipv4(
        hash_keys: &HashKeys,
        template: &[u8],
        dst_ip: [u8; 4],
        dst_port_opt: Option<[u8; 2]>,
        packet: &mut Vec<u8>,
    ) -> Result<(), ScannerErrWithMsg> {
        packet.extend_from_slice(template);
        if packet.len() < 54 {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Assembling,
                msg: format!("Template too short for IPv4: {}", packet.len()),
            });
        }

        // set dst ip
        packet[30] = dst_ip[0];
        packet[31] = dst_ip[1];
        packet[32] = dst_ip[2];
        packet[33] = dst_ip[3];

        // get values for syn cookie
        let dst_port: [u8; 2] = if dst_port_opt.is_none() {
            match template[36..=37].try_into() {
                Ok(port) => port,
                Err(e) => {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Assembling,
                        msg: format!("Failed to get dst port: {:?}", e),
                    });
                }
            }
        } else {
            dst_port_opt.unwrap()
        };

        let src_port: [u8; 2] = match packet[34..=35].try_into() {
            Ok(port) => port,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Assembling,
                    msg: format!("Failed to get src port: {:?}", e),
                });
            }
        };

        let src_ip: [u8; 4] = match packet[26..=29].try_into() {
            Ok(ip) => ip,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Assembling,
                    msg: format!("Failed to get src ip: {:?}", e),
                });
            }
        };

        // // Vorherigen seq_number aus dem Template holen (für RFC 1624)
        // let prev_seq_number: [u8; 4] = match template[38..=41].try_into() {
        //     Ok(seq) => seq,
        //     Err(e) => {
        //         return Err(ScannnerErrWithMsg {
        //             err: ScanErr::Config,
        //             msg: format!("Failed to get previous seq number: {:?}", e),
        //         });
        //     }
        // };

        // set seq number
        let seq_number: [u8; 4] = shared::helper::create_sequence_number(
            hash_keys, &src_ip, &src_port, &dst_ip, &dst_port,
        )?
        .to_be_bytes();

        packet[38] = seq_number[0];
        packet[39] = seq_number[1];
        packet[40] = seq_number[2];
        packet[41] = seq_number[3];

        // add dst_ip to ip checksum
        let ip_checksum_old: [u8; 2] = match packet[24..=25].try_into() {
            Ok(cs) => cs,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Assembling,
                    msg: format!("Failed to get ip checksum: {:?}", e),
                });
            }
        };

        let mut ip_checksum = !(u16::from_be_bytes(ip_checksum_old)) as u32; // One's complement back to sum
        ip_checksum = ip_checksum.wrapping_add(((dst_ip[0] as u16) << 8 | dst_ip[1] as u16) as u32);
        ip_checksum = ip_checksum.wrapping_add(((dst_ip[2] as u16) << 8 | dst_ip[3] as u16) as u32);

        while (ip_checksum >> 16) != 0 {
            ip_checksum = (ip_checksum & 0xFFFF) + (ip_checksum >> 16);
        }

        let new_ip_checksum = !(ip_checksum as u16);
        let checksum_as_array: [u8; 2] = new_ip_checksum.to_be_bytes();

        packet[24] = checksum_as_array[0];
        packet[25] = checksum_as_array[1];

        // add seq_number & dst_ip & dst_port to tcp checksum
        let tcp_checksum_old: [u8; 2] = match packet[50..=51].try_into() {
            Ok(cs) => cs,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: format!("Failed to get tcp checksum: {:?}", e),
                });
            }
        };

        let mut tcp_checksum = !(u16::from_be_bytes(tcp_checksum_old)) as u32; // One's complement back to sum

        // // Subtrahiere alten Wert (RFC 1624)
        // let prev_seq_hi = ((prev_seq_number[0] as u16) << 8 | prev_seq_number[1] as u16) as u32;
        // let prev_seq_lo = ((prev_seq_number[2] as u16) << 8 | prev_seq_number[3] as u16) as u32;
        // tcp_checksum = tcp_checksum.wrapping_add(!prev_seq_hi);
        // tcp_checksum = tcp_checksum.wrapping_add(!prev_seq_lo);

        // addiere neuen Wert
        // set dst_port
        if dst_port_opt.is_some() {
            packet[36] = dst_port[0];
            packet[37] = dst_port[1];
            tcp_checksum =
                tcp_checksum.wrapping_add(((dst_port[0] as u16) << 8 | dst_port[1] as u16) as u32);
        }

        tcp_checksum =
            tcp_checksum.wrapping_add(((dst_ip[0] as u16) << 8 | dst_ip[1] as u16) as u32);
        tcp_checksum =
            tcp_checksum.wrapping_add(((dst_ip[2] as u16) << 8 | dst_ip[3] as u16) as u32);

        tcp_checksum =
            tcp_checksum.wrapping_add(((seq_number[0] as u16) << 8 | seq_number[1] as u16) as u32);
        tcp_checksum =
            tcp_checksum.wrapping_add(((seq_number[2] as u16) << 8 | seq_number[3] as u16) as u32);

        while (tcp_checksum >> 16) != 0 {
            tcp_checksum = (tcp_checksum & 0xFFFF) + (tcp_checksum >> 16);
        }

        let new_tcp_checksum = !(tcp_checksum as u16);
        let tcp_checksum_as_array: [u8; 2] = new_tcp_checksum.to_be_bytes();

        packet[50] = tcp_checksum_as_array[0];
        packet[51] = tcp_checksum_as_array[1];

        Ok(())
    }

    async fn complement_template_tcp_ipv6(
        hash_keys: &HashKeys,
        template: &[u8],
        dst_ip: [u8; 16],
        dst_port_opt: Option<[u8; 2]>,
        packet: &mut Vec<u8>,
    ) -> Result<(), ScannerErrWithMsg> {
        packet.extend_from_slice(template);
        if packet.len() < 74 {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Assembling,
                msg: format!("Template too short for IPv6: {}", packet.len()),
            });
        }

        // set dst ip
        for (i, byte) in dst_ip.iter().enumerate() {
            packet[38 + i] = *byte;
        }

        // get values for syn cookie
        let dst_port: [u8; 2] = if dst_port_opt.is_none() {
            match template[56..=57].try_into() {
                Ok(port) => port,
                Err(e) => {
                    return Err(ScannerErrWithMsg {
                        err: ScanErr::Assembling,
                        msg: format!("Failed to get dst port: {:?}", e),
                    });
                }
            }
        } else {
            dst_port_opt.unwrap()
        };

        let src_port: [u8; 2] = match packet[54..=55].try_into() {
            Ok(port) => port,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Assembling,
                    msg: format!("Failed to get src port: {:?}", e),
                });
            }
        };

        let src_ip: [u8; 16] = match packet[22..=37].try_into() {
            Ok(ip) => ip,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Assembling,
                    msg: format!("Failed to get src ip: {:?}", e),
                });
            }
        };

        // set sequence number
        let seq_number: [u8; 4] = shared::helper::create_sequence_number(
            hash_keys, &src_ip, &src_port, &dst_ip, &dst_port,
        )?
        .to_be_bytes();

        packet[58] = seq_number[0];
        packet[59] = seq_number[1];
        packet[60] = seq_number[2];
        packet[61] = seq_number[3];

        // add seq_number & dst_ip & dst_port to tcp checksum
        let tcp_checksum_old: [u8; 2] = match packet[70..=71].try_into() {
            Ok(cs) => cs,
            Err(e) => {
                return Err(ScannerErrWithMsg {
                    err: ScanErr::Config,
                    msg: format!("Failed to get tcp checksum: {:?}", e),
                });
            }
        };
        let mut tcp_checksum = !(u16::from_be_bytes(tcp_checksum_old)) as u32; // One's complement back to sum

        // addiere neuen Wert
        #[inline]
        fn fold(mut s: u32) -> u32 {
            while (s >> 16) != 0 {
                s = (s & 0xFFFF) + (s >> 16);
            }
            s
        }

        #[inline]
        fn add_word(tcp_checksum: u32, w: u16) -> u32 {
            fold(tcp_checksum.wrapping_add(w as u32))
        }

        // add all 8 words (16 bytes) of IPv6 destination (pseudoheader part)
        for i in (0..16).step_by(2) {
            let w = u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]);
            tcp_checksum = add_word(tcp_checksum, w);
        }

        // add TCP dst_port
        // set dst_port
        if dst_port_opt.is_some() {
            packet[56] = dst_port[0];
            packet[57] = dst_port[1];
            let w = u16::from_be_bytes(dst_port);
            tcp_checksum = add_word(tcp_checksum, w);
        }

        // add 2 words of TCP sequence number
        for i in (0..4).step_by(2) {
            let w = u16::from_be_bytes([seq_number[i], seq_number[i + 1]]);
            tcp_checksum = add_word(tcp_checksum, w);
        }

        tcp_checksum = fold(tcp_checksum);
        let new_checksum = !(tcp_checksum as u16);
        let bytes = new_checksum.to_be_bytes();
        packet[70] = bytes[0];
        packet[71] = bytes[1];

        Ok(())
    }

    fn decide_current_template(&self) -> usize {
        let len = self.config.templates.len();
        let idx = self.current_template.fetch_add(1, Ordering::Relaxed);
        idx % len
    }
}

#[cfg(test)]
mod tests {
    use crate::scan_utils::shared::types_and_config::HashKeys;

    use super::*;
    use etherparse::{
        Ethernet2Header, IpNumber, Ipv4Header, Ipv6FlowLabel, Ipv6Header, NetHeaders,
        PacketHeaders, TcpHeader, TransportHeader,
    };

    // Helper: Erstellt ein valides IPv4 TCP Template mit korrekten initialen Checksummen
    fn create_ipv4_template() -> Vec<u8> {
        let src_mac = [1, 2, 3, 4, 5, 6];
        let dst_mac = [6, 5, 4, 3, 2, 1];

        // Ethernet
        let eth_header = Ethernet2Header {
            source: src_mac,
            destination: dst_mac,
            ether_type: etherparse::EtherType::IPV4,
        };

        // IPv4
        let ip_header = Ipv4Header::new(
            20, // Payload Length (20 TCP) - Header adds 20 automatically
            64, // TTL
            IpNumber::TCP,
            [192, 168, 0, 1], // Src IP
            [0, 0, 0, 0],     // Dst IP (wird überschrieben)
        )
        .unwrap();

        // WICHTIG: Checksumme muss initial stimmen, da der Assembler inkrementell arbeitet!
        // etherparse berechnet sie beim Schreiben automatisch.

        // TCP
        let mut tcp_header = TcpHeader::new(
            12345, // Src Port
            0,     // Dst Port (wird überschrieben)
            0,     // Seq No
            64240, // Window
        );
        tcp_header.syn = true;
        tcp_header.checksum = tcp_header.calc_checksum_ipv4(&ip_header, &[]).unwrap();

        let mut packet = Vec::new();
        eth_header.write(&mut packet).unwrap();
        ip_header.write(&mut packet).unwrap();
        tcp_header.write(&mut packet).unwrap();

        packet
    }

    // Helper: Erstellt ein valides IPv6 TCP Template
    fn create_ipv6_template() -> Vec<u8> {
        let src_mac = [1, 2, 3, 4, 5, 6];
        let dst_mac = [6, 5, 4, 3, 2, 1];

        let eth_header = Ethernet2Header {
            source: src_mac,
            destination: dst_mac,
            ether_type: etherparse::EtherType::IPV6,
        };

        let ip_header = Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::default(),
            payload_length: 20, // TCP Header length
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // ::1
            destination: [0; 16],                                     // Dst IP (wird überschrieben)
        };

        let mut tcp_header = TcpHeader::new(
            12345, // Src Port
            0,     // Dst Port
            0,     // Seq No
            64240, // Window
        );
        tcp_header.syn = true;
        // Checksumme initial berechnen
        tcp_header.checksum = tcp_header.calc_checksum_ipv6(&ip_header, &[]).unwrap();

        let mut packet = Vec::new();
        eth_header.write(&mut packet).unwrap();
        ip_header.write(&mut packet).unwrap();
        tcp_header.write(&mut packet).unwrap();

        packet
    }

    #[tokio::test]
    async fn test_ipv4_assembly_correctness() {
        // 1. Setup
        let template = create_ipv4_template();
        let target_ip = [10, 0, 0, 5];
        let target_port: u16 = 80;

        // 2. Action
        let mut packet = Vec::with_capacity(template.len());
        let hash_keys = HashKeys { k0: None, k1: None };
        PacketAssembler::complement_template_tcp_ipv4(
            &hash_keys,
            &template,
            target_ip,
            Some(target_port.to_be_bytes()),
            &mut packet,
        )
        .await
        .expect("Assembler failed");
        let result = packet;

        // 3. Verification
        let parsed = PacketHeaders::from_ethernet_slice(&result).expect("Parsing failed");

        // A) IP Header Check
        if let Some(NetHeaders::Ipv4(ip, _)) = parsed.net.clone() {
            assert_eq!(ip.destination, target_ip, "Destination IP mismatch");

            // Verify IP Checksum
            // etherparse calc_header_checksum() berechnet die Checksumme, die im Header stehen sollte (unter Annahme Feld=0).
            // Wir vergleichen sie mit dem tatsächlichen Wert.
            let calc_cs = ip.calc_header_checksum();
            assert_eq!(
                calc_cs, ip.header_checksum,
                "IP Checksum invalid: calculated {:x}, expected {:x}",
                calc_cs, ip.header_checksum
            );
        } else {
            panic!("Not an IPv4 packet");
        }

        // B) TCP Header Check
        if let Some(TransportHeader::Tcp(tcp)) = parsed.transport {
            assert_eq!(
                tcp.destination_port, target_port,
                "Destination Port mismatch"
            );
            assert_ne!(tcp.sequence_number, 0, "Sequence number was not hashed/set");

            // Verify TCP Checksum
            // Wir nutzen etherparse um die erwartete Checksumme zu berechnen
            let ip_header = parsed.net.unwrap();

            let mut tcp_clean = tcp.clone();
            tcp_clean.checksum = 0;
            let calculated = tcp_clean
                .calc_checksum_ipv4(ip_header.ipv4_ref().unwrap().0, &[])
                .unwrap();

            assert_eq!(tcp.checksum, calculated, "TCP Checksum invalid");
        } else {
            panic!("Not a TCP packet");
        }
    }

    #[tokio::test]
    async fn test_ipv6_assembly_correctness() {
        // 1. Setup
        let template = create_ipv6_template();
        let target_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99];
        let target_port: u16 = 443;

        // 2. Action
        let mut packet = Vec::with_capacity(template.len());
        let hash_keys = HashKeys { k0: None, k1: None };
        PacketAssembler::complement_template_tcp_ipv6(
            &hash_keys,
            &template,
            target_ip,
            Some(target_port.to_be_bytes()),
            &mut packet,
        )
        .await
        .expect("Assembler IPv6 failed");
        let result = packet;

        // 3. Verification
        let parsed = PacketHeaders::from_ethernet_slice(&result).expect("Parsing failed");

        // A) IPv6 Header Check
        if let Some(NetHeaders::Ipv6(ip, _)) = parsed.net.clone() {
            assert_eq!(ip.destination, target_ip, "IPv6 Destination mismatch");

            // Regression Test für den Offset-Bug (36 vs 56):
            // Source IP ist ::1 ([...0, 1]). Byte 15 ist 1.
            // Im Paket liegt Source IP bei Offset 14 (Eth) + 8 = 22.
            // Byte 14 der Source IP liegt bei Offset 22 + 14 = 36.
            // Wenn wir fälschlicherweise an 36 schreiben, zerstören wir die Source IP.
            assert_eq!(
                ip.source[14], 0,
                "Source IP corrupted at byte 14 (Offset 36)"
            );
            assert_eq!(ip.source[15], 1, "Source IP corrupted at byte 15");
        } else {
            panic!("Not an IPv6 packet");
        }

        // B) TCP Header Check
        if let Some(TransportHeader::Tcp(tcp)) = parsed.transport {
            assert_eq!(
                tcp.destination_port, target_port,
                "Destination Port mismatch"
            );
            assert_ne!(tcp.sequence_number, 0, "Sequence number not set");

            // Verify TCP Checksum
            let ip_header = parsed.net.unwrap();
            let mut tcp_clean = tcp.clone();
            tcp_clean.checksum = 0;
            let calculated = tcp_clean
                .calc_checksum_ipv6(ip_header.ipv6_ref().unwrap().0, &[])
                .unwrap();

            assert_eq!(tcp.checksum, calculated, "TCP IPv6 Checksum invalid");
        } else {
            panic!("Not a TCP packet");
        }
    }

    #[tokio::test]
    async fn test_assemble_packets_ipv4_single() {
        // Setup
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let sender_chan = SenderChan::Packet(tx);
        let template = create_ipv4_template();
        let config = Arc::new(EmissionConfig {
            zero_copy: false,
            retries: 0,
            ipv6: false,
            protocol: 6,
            batch_size: 10,
            scan_rate: 100,
            templates: vec![template.clone()],
            send_in_batches: false,
            assembler_size: 1,
            parsing_timeout_millis: 1000,
            xdp: false,
            num_nic_queues: 1,
            reset: false,
            dst_mac: pnet::util::MacAddr::zero(),
            src_mac: pnet::util::MacAddr::zero(),
            dst_ports: vec![80],
            interface: "eno1".to_string(),
            hash_keys: HashKeys { k0: None, k1: None },
        });
        let current_template = Arc::new(AtomicUsize::new(0));
        let dst_ips =
            AssemblerDstIps::Ipv4(vec![[192, 168, 0, 1], [192, 168, 0, 2], [192, 168, 0, 3]]);

        // Action
        PacketAssembler::assemble_packets(
            dst_ips,
            sender_chan,
            current_template,
            config,
            Some(0), // dst_port_index
        )
        .await
        .expect("Assembly failed");

        // Verification
        let mut count = 0;
        while let Ok(packet) = rx.try_recv() {
            count += 1;
            let parsed = PacketHeaders::from_ethernet_slice(&packet).unwrap();
            if let Some(NetHeaders::Ipv4(ip, _)) = parsed.net {
                assert_eq!(ip.destination[0], 192);
                assert_eq!(ip.destination[1], 168);
                assert_eq!(ip.destination[2], 0);
                assert_eq!(ip.destination[3], count as u8);
            }
        }
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn test_assemble_packets_ipv4_batch() {
        // Setup
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let sender_chan = SenderChan::Batch(tx);
        let template = create_ipv4_template();
        let config = Arc::new(EmissionConfig {
            zero_copy: false,
            retries: 0,
            ipv6: false,
            protocol: 6,
            batch_size: 2, // Batch size 2
            scan_rate: 100,
            templates: vec![template.clone()],
            send_in_batches: true, // Enable batching
            assembler_size: 1,
            parsing_timeout_millis: 1000,
            xdp: false,
            num_nic_queues: 1,
            reset: false,
            dst_mac: pnet::util::MacAddr::zero(),
            src_mac: pnet::util::MacAddr::zero(),
            dst_ports: vec![80],
            interface: "eno1".to_string(),
            hash_keys: HashKeys { k0: None, k1: None },
        });
        let current_template = Arc::new(AtomicUsize::new(0));
        let dst_ips = AssemblerDstIps::Ipv4(vec![
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            [10, 0, 0, 3],
            [10, 0, 0, 4],
            [10, 0, 0, 5],
        ]);

        // Action
        PacketAssembler::assemble_packets(dst_ips, sender_chan, current_template, config, Some(0))
            .await
            .expect("Assembly failed");

        // Verification
        // Expect 3 batches: [1,2], [3,4], [5]
        let mut batches = Vec::new();
        while let Ok(batch) = rx.try_recv() {
            batches.push(batch);
        }

        assert_eq!(batches.len(), 3, "Should have 3 batches");
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 2);
        assert_eq!(batches[2].len(), 1);
    }

    #[tokio::test]
    async fn test_assemble_packets_ipv6_batch() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let sender_chan = SenderChan::Batch(tx);
        let template = create_ipv6_template();
        let config = Arc::new(EmissionConfig {
            zero_copy: false,
            retries: 0,
            ipv6: true,
            protocol: 6,
            batch_size: 2,
            scan_rate: 100,
            templates: vec![template.clone()],
            send_in_batches: true,
            assembler_size: 1,
            parsing_timeout_millis: 1000,
            xdp: false,
            num_nic_queues: 1,
            reset: false,
            dst_mac: pnet::util::MacAddr::zero(),
            src_mac: pnet::util::MacAddr::zero(),
            dst_ports: vec![80],
            interface: "eno1".to_string(),
            hash_keys: HashKeys { k0: None, k1: None },
        });
        let current_template = Arc::new(AtomicUsize::new(0));

        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst_ips = AssemblerDstIps::Ipv6(vec![ip, ip, ip]);

        PacketAssembler::assemble_packets(dst_ips, sender_chan, current_template, config, Some(0))
            .await
            .expect("Assembly failed");

        let mut batches = Vec::new();
        while let Ok(batch) = rx.try_recv() {
            batches.push(batch);
        }

        assert_eq!(batches.len(), 2); // [2, 1]
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[1].len(), 1);
    }

    #[tokio::test]
    async fn test_template_rotation() {
        // Setup
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let sender_chan = SenderChan::Packet(tx);

        // Template 1: Src Port 11111
        let mut t1 = create_ipv4_template();
        t1[34] = (11111u16 >> 8) as u8;
        t1[35] = (11111u16 & 0xFF) as u8;

        // Template 2: Src Port 22222
        let mut t2 = create_ipv4_template();
        t2[34] = (22222u16 >> 8) as u8;
        t2[35] = (22222u16 & 0xFF) as u8;

        let config = Arc::new(EmissionConfig {
            retries: 0,
            zero_copy: false,
            ipv6: false,
            protocol: 6,
            batch_size: 10,
            scan_rate: 100,
            templates: vec![t1, t2], // Two templates
            send_in_batches: false,
            assembler_size: 1,
            parsing_timeout_millis: 1000,
            xdp: false,
            num_nic_queues: 1,
            reset: false,
            dst_mac: pnet::util::MacAddr::zero(),
            src_mac: pnet::util::MacAddr::zero(),
            dst_ports: vec![80],
            interface: "eno1".to_string(),
            hash_keys: HashKeys { k0: None, k1: None },
        });
        let current_template = Arc::new(AtomicUsize::new(0));
        let dst_ips = AssemblerDstIps::Ipv4(vec![[1, 1, 1, 1], [2, 2, 2, 2], [3, 3, 3, 3]]);

        // Action
        PacketAssembler::assemble_packets(dst_ips, sender_chan, current_template, config, Some(0))
            .await
            .expect("Assembly failed");

        // Verification
        let mut packets: Vec<Vec<u8>> = Vec::new();
        while let Ok(packet) = rx.try_recv() {
            packets.push(packet);
        }
        assert_eq!(packets.len(), 3);

        // Check Src Ports to verify rotation
        // Packet 1 -> Template 1
        let p1 = PacketHeaders::from_ethernet_slice(&packets[0]).unwrap();
        if let Some(TransportHeader::Tcp(tcp)) = p1.transport {
            assert_eq!(tcp.source_port, 11111);
        }

        // Packet 2 -> Template 2
        let p2 = PacketHeaders::from_ethernet_slice(&packets[1]).unwrap();
        if let Some(TransportHeader::Tcp(tcp)) = p2.transport {
            assert_eq!(tcp.source_port, 22222);
        }

        // Packet 3 -> Template 1 (Wrapped around)
        let p3 = PacketHeaders::from_ethernet_slice(&packets[2]).unwrap();
        if let Some(TransportHeader::Tcp(tcp)) = p3.transport {
            assert_eq!(tcp.source_port, 11111);
        }
    }

    #[tokio::test]
    async fn test_malformed_template_error() {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let sender_chan = SenderChan::Packet(tx);

        // Too short template
        let template = vec![0u8; 10];

        let config = Arc::new(EmissionConfig {
            retries: 0,
            ipv6: false,
            zero_copy: false,
            protocol: 6,
            batch_size: 1,
            scan_rate: 100,
            templates: vec![template],
            send_in_batches: false,
            assembler_size: 1,
            parsing_timeout_millis: 1000,
            xdp: false,
            num_nic_queues: 1,
            reset: false,
            dst_mac: pnet::util::MacAddr::zero(),
            src_mac: pnet::util::MacAddr::zero(),
            dst_ports: vec![80],
            interface: "eno1".to_string(),
            hash_keys: HashKeys { k0: None, k1: None },
        });
        let current_template = Arc::new(AtomicUsize::new(0));
        let dst_ips = AssemblerDstIps::Ipv4(vec![[192, 168, 1, 1]]);

        let result = PacketAssembler::assemble_packets(
            dst_ips,
            sender_chan,
            current_template,
            config,
            Some(0),
        )
        .await;

        assert!(result.is_err());
        let err = result.err().unwrap();
        // We expect an error because it can't parse the template to find offsets
        assert!(err.msg.contains("Template too short"));
    }
}
