use ipnetwork::{Ipv4Network, Ipv6Network};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, ipv4_checksum as tcp_ipv4_checksum};
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::vec;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GivenConfig {
    #[serde(rename = "ScanID")]
    pub scan_id: u64,
    #[serde(rename = "Retries")]
    pub retries: u64,
    #[serde(rename = "ScanRate")]
    pub scan_rate: u64,
    #[serde(rename = "IPv6")]
    pub ipv6: bool,
    #[serde(rename = "Reset")]
    pub reset: bool,
    #[serde(rename = "Deduplicate")]
    pub deduplicate: bool,
    #[serde(rename = "SrcPorts")]
    pub src_ports: Vec<u16>,
    #[serde(rename = "SrcIPs")]
    pub src_ips: Vec<Vec<u8>>,
    #[serde(rename = "Protocol")]
    pub protocol: u64,
    #[serde(rename = "Templates")]
    pub templates: Vec<Vec<u8>>,
    #[serde(rename = "DstPorts")]
    pub dst_ports: Vec<u16>,
    #[serde(rename = "ZeroCopy")]
    pub zero_copy: bool,
    #[serde(rename = "GenericMode")]
    pub generic_mode: bool,
}

// New Enum and Function
#[derive(Clone, Debug)]
pub enum IpSource {
    RepeatIpv4 { ip: [u8; 4], count: u64 },
    RepeatIpv6 { ip: [u8; 16], count: u64 },
    RangeIpv4(Ipv4Network),
    RangeIpv6(Ipv6Network),
    ListIpv4(Vec<[u8; 4]>),
    ListIpv6(Vec<[u8; 16]>),
}

#[tokio::main]
async fn main() {
    // =================================================================================================
    // CONFIGURATION (manuual)
    // =================================================================================================

    // --- 1. GENERAL SETTINGS ---
    let interface = Some("enp6s0");
    let scanrate = 48; // in Mbit/s
    let retries = 0; // max 3
    let num_nic_queues = 1; // To find out how many are possible: sudo ethtool -l <interface>

    // --- 2. MODE SETTINGS ---
    let mut xdp = false; // Use XDP (High Performance) else AF_PACKET is used
    let mut zero_copy = true; // Use Zero-Copy (Requires Driver Support)
    let mut generic_mode = false; // Force Generic Mode (Slower, Driver Independent)
    let batch = true; // Send packets in batches (highly suggested)

    // --- 3. PACKET & BEHAVIOR ---
    let deduplicate = false; // Filter duplicate IPs
    let reset = false; // Send RST after SYN-ACK? (false for igb drivers)
    let send_ipv6 = false;
    let parsing_timeout_millis = 3000; // Time to wait after sending is finished
    let scan_id = 1; // irrelevant

    // --- 4. NETWORK ADRESSES ---
    // Ports
    let src_ports = vec![60000];
    // let src_ports: Vec<u16> = (60000..60128).collect();
    let dst_ports = vec![80];

    // MAC Addresses
    let gw_mac: MacAddr = MacAddr::new(0x00, 0x1b, 0x21, 0xda, 0xfc, 0xef); // Gateway
    let src_mac: MacAddr = MacAddr::new(0x00, 0x1b, 0x21, 0xf3, 0x7a, 0x55); // Source (Interface)

    // Source IPs
    let src_ipv4: Ipv4Network = "192.168.0.1/32".parse().unwrap();
    let addr_ipv6 = Ipv6Addr::from([
        0xfd, 0xad, 0x4c, 0x7e, 0x4d, 0x81, 0x00, 0x00, 0x8c, 0xc6, 0xb2, 0x19, 0x3c, 0xba, 0xf3,
        0x8e,
    ]);
    let src_ipv6 = Ipv6Network::new(addr_ipv6, 128).unwrap();

    // --- 5. TARGET CONFIGURATION (Destination IPs) ---
    // Uncomment the desired source:

    // A) Send to CIDR range
    // let dst_ips = IpSource::RangeIpv4("10.0.0.0/20".parse().unwrap());

    // B) Send to specific IPs
    // let dst_ips = IpSource::ListIpv4(vec![[192, 168, 0, 3], [192, 168, 0, 2]]);

    // C) Send to same IP repeatedly (Benchmark)
    let dst_ips = IpSource::RepeatIpv4 {
        ip: [192, 168, 0, 3],
        count: 4,
    };

    // D) File Input (Optional)
    let string_file_path: Option<&str> = None;
    // let string_file_path: Option<&str> = Some("/path/to/ipv4s.txt");
    let byte_file_path: Option<&str> = None;

    // =================================================================================================
    // LOGIC & VALIDATION (automatic)
    // =================================================================================================

    // Ensure logic constraints
    if !xdp {
        if zero_copy {
            eprintln!("WARN: Zero Copy requires XDP. Disabling Zero Copy.");
            zero_copy = false;
        }
        if generic_mode {
            eprintln!("WARN: Generic Mode requires XDP. Disabling Generic Mode.");
            generic_mode = false;
        }
    }

    // Print Config
    println!("\n=== SYN-Rust MOCK CONFIGURATION ===");
    println!("{:<20} {:?}", "Interface:", interface);
    println!("{:<20} {} Mbit/s", "Scan Rate:", scanrate);
    println!("{:<20} {}", "Mode:", if xdp { "XDP" } else { "AF_PACKET" });
    if xdp {
        println!("{:<20} {}", "  Zero Copy:", zero_copy);
        println!("{:<20} {}", "  Generic Mode:", generic_mode);
    }
    println!("{:<20} {}", "IPv6:", send_ipv6);
    println!("{:<20} {}", "Dedup:", deduplicate);
    println!("{:<20} {}", "Reset:", reset);
    println!("======================================\n");

    // --------------------------------------------------------------------------------------------------
    // --------------------------------------------------------------------------------------------------
    let single_dst_port = match dst_ports.as_slice() {
        [port] => Some(*port),
        _ => None,
    };
    let templates = match send_ipv6 {
        true => {
            let capacity = src_ipv4.size() as usize * src_ports.len();

            let mut vec = Vec::with_capacity(capacity);
            for ip in src_ipv6.iter() {
                for port in src_ports.iter() {
                    let template = build_template_ipv6(*port, ip, gw_mac, src_mac, single_dst_port);
                    vec.push(template);
                }
            }
            vec
        }
        false => {
            let capacity = src_ipv4.size() as usize * src_ports.len();

            let mut vec = Vec::with_capacity(capacity);
            for ip in src_ipv4.iter() {
                for port in src_ports.iter() {
                    let template = build_template_ipv4(*port, ip, gw_mac, src_mac, single_dst_port);
                    vec.push(template);
                }
            }
            vec
        }
    };
    let src_ips: Vec<Vec<u8>> = match send_ipv6 {
        true => src_ipv6.iter().map(|ip| ip.octets().to_vec()).collect(),
        false => src_ipv4.iter().map(|ip| ip.octets().to_vec()).collect(),
    };
    let cfg = GivenConfig {
        scan_id,
        retries,
        scan_rate: scanrate,
        ipv6: send_ipv6,
        reset,
        deduplicate,
        protocol: 1,
        templates,
        src_ports,
        src_ips,
        dst_ports,
        zero_copy,
        generic_mode,
    };

    let json = serde_json::to_string(&cfg).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(json.as_bytes());
    out.extend("\n".as_bytes());

    // Ermittle den Pfad zur aktuellen Binary und leite den Scanner-Pfad ab
    let mut scanner_path = std::env::current_exe().expect("Konnte Programmpfad nicht ermitteln");
    scanner_path.pop(); // Entfernt "mock_program" vom Pfad
    scanner_path.push("scanner"); // Fügt "scanner" hinzu

    // Argumente dynamisch zusammenbauen
    let mut args = vec![scanner_path.to_string_lossy().into_owned()];

    if xdp {
        args.push("--xdp".to_string());
    }
    if generic_mode {
        args.push("--generic-mode".to_string());
    }
    if batch {
        args.push("--batch".to_string());
    }
    args.push("--num-nic-queues".to_string());
    args.push(num_nic_queues.to_string());
    args.push("--parsing-timeout-millis".to_string());
    args.push(parsing_timeout_millis.to_string());
    if let Some(fp) = &string_file_path {
        args.push("--string-file-path".to_string());
        args.push(fp.to_string());
    }
    if let Some(fp) = &byte_file_path {
        args.push("--byte-file-path".to_string());
        args.push(fp.to_string());
    }
    if let Some(iface) = interface {
        args.push("--interface".to_string());
        args.push(iface.to_string());
    }

    // initializing child process
    let mut child = Command::new("sudo")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("Fehler beim Starten von main");

    let mut child_stdin = child.stdin.take().expect("Kein Stdin");
    let mut child_stdout = child.stdout.take().expect("Kein Stdout");

    let stdout_task = tokio::spawn(async move {
        let file = tokio::fs::File::create("scan_output.csv").await.unwrap();
        let mut writer = tokio::io::BufWriter::with_capacity(65536, file);
        if let Err(e) = tokio::io::copy(&mut child_stdout, &mut writer).await {
            eprintln!("Fehler beim Schreiben der CSV: {:?}", e);
        }
        let _ = writer.flush().await;
    });

    if let Err(e) = child_stdin.write_all(&out).await {
        eprintln!("Fehler beim Schreiben in die Pipe: {:?}", e);
    }

    if string_file_path.is_none() && byte_file_path.is_none() {
        let terminator = match &dst_ips {
            IpSource::RepeatIpv4 { .. } | IpSource::RangeIpv4(_) | IpSource::ListIpv4(_) => {
                vec![0u8; 4]
            }
            IpSource::RepeatIpv6 { .. } | IpSource::RangeIpv6(_) | IpSource::ListIpv6(_) => {
                vec![0u8; 16]
            }
        };

        if let Err(e) = write_ips_batched(&mut child_stdin, dst_ips).await {
            eprintln!("Fehler beim Batched Schreiben: {:?}", e);
        }

        if let Err(e) = child_stdin.write(&terminator).await {
            eprintln!("Fehler beim Schreiben in die Pipe: {:?}", e);
        }
    }

    if let Err(e) = child_stdin.flush().await {
        eprintln!("Fehler beim Flushen von stdin: {:?}", e);
    }

    // child_stdin.shutdown().await.ok();
    // drop(child_stdin); // important for child.await return
    // let _ = stdout_task.await;

    let status = child.wait().await;
    eprintln!("exited with status {:?}", status);

    // Warten bis der Output fertig geschrieben wurde
    let _ = stdout_task.await;
}

fn build_template_ipv6(
    src_port: u16,
    src_ip: Ipv6Addr,
    gw_mac: MacAddr,
    src_mac: MacAddr,
    single_dst_port: Option<u16>,
) -> Vec<u8> {
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::tcp::{MutableTcpPacket, ipv6_checksum as tcp_ipv6_checksum};
    use std::net::Ipv6Addr;

    // Ethernet + IPv6 + TCP
    let mut ethernet_buffer = [0u8; 14 + 40 + 20];
    let (eth_slice, rest) = ethernet_buffer.split_at_mut(14);
    let (ipv6_slice, tcp_slice) = rest.split_at_mut(40);

    // Ethernet Header
    let mut eth_packet = MutableEthernetPacket::new(eth_slice).unwrap();
    eth_packet.set_destination(gw_mac);
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv6);

    // IPv6 Header
    let mut ipv6_packet = MutableIpv6Packet::new(ipv6_slice).unwrap();
    ipv6_packet.set_version(6);
    ipv6_packet.set_payload_length(20); // TCP header, no payload
    ipv6_packet.set_next_header(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv6_packet.set_hop_limit(64);
    ipv6_packet.set_source(src_ip);
    // Zieladresse bleibt 0, wird später ersetzt
    ipv6_packet.set_destination(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));

    // TCP Header
    let mut tcp_packet = MutableTcpPacket::new(tcp_slice).unwrap();
    tcp_packet.set_source(src_port);
    if let Some(port) = single_dst_port {
        tcp_packet.set_destination(port);
    } else {
        tcp_packet.set_destination(0);
    }
    tcp_packet.set_sequence(0);
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);

    // TCP Checksum
    let tcp_checksum = tcp_ipv6_checksum(
        &tcp_packet.to_immutable(),
        &ipv6_packet.get_source(),
        &ipv6_packet.get_destination(),
    );
    tcp_packet.set_checksum(tcp_checksum);

    eprintln!("len ipv6 {}", ethernet_buffer.len());
    ethernet_buffer.to_vec()
}

fn build_template_ipv4(
    src_port: u16,
    src_ip: Ipv4Addr,
    gw_mac: MacAddr,
    src_mac: MacAddr,
    single_dst_port: Option<u16>,
) -> Vec<u8> {
    // Ethernet frame
    let mut ethernet_buffer = [0u8; 54]; // Ethernet + IPv4 + TCP
    let (eth_slice, rest) = ethernet_buffer.split_at_mut(14);
    let (ipv4_slice, tcp_slice) = rest.split_at_mut(20);

    let mut eth_packet = MutableEthernetPacket::new(eth_slice).unwrap();
    // home 02:10:18:40:6e:8c
    // work 48:5d:35:19:04:0e
    eth_packet.set_destination(gw_mac);

    // b0:25:aa:3d:fa:32
    eth_packet.set_source(src_mac);
    eth_packet.set_ethertype(EtherTypes::Ipv4);

    // IPv4 header
    let mut ipv4_packet = MutableIpv4Packet::new(ipv4_slice).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(40); // 20 (IPv4) + 20 (TCP) + 6 (Padding)
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(src_ip);
    // ipv4_packet.set_source(Ipv4Addr::new(192, 168, 0, 72));
    ipv4_packet.set_destination(Ipv4Addr::new(0, 0, 0, 0)); // dst_ip = 0
    ipv4_packet.set_identification(0x4219);
    ipv4_packet.set_flags(2);
    ipv4_packet.set_fragment_offset(0);
    // Checksum berechnen
    let checksum = ipv4_checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    // TCP header
    let mut tcp_packet = MutableTcpPacket::new(tcp_slice).unwrap();
    tcp_packet.set_source(src_port);
    if let Some(port) = single_dst_port {
        tcp_packet.set_destination(port);
    } else {
        tcp_packet.set_destination(0);
    }
    tcp_packet.set_sequence(0); // Sequence number = 0
    tcp_packet.set_acknowledgement(0);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(TcpFlags::SYN);
    tcp_packet.set_window(64240);
    tcp_packet.set_urgent_ptr(0);
    // TCP Checksum berechnen
    let tcp_checksum = tcp_ipv4_checksum(
        &tcp_packet.to_immutable(),
        &ipv4_packet.get_source(),
        &ipv4_packet.get_destination(),
    );
    tcp_packet.set_checksum(tcp_checksum);

    // Das Paket ist jetzt fertig
    let mut result = ethernet_buffer.to_vec();
    result.extend_from_slice(&[0u8; 6]);
    result
}

async fn write_ips_batched<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    source: IpSource,
) -> std::io::Result<()> {
    let ip_len = match &source {
        IpSource::RepeatIpv4 { .. } | IpSource::RangeIpv4(_) | IpSource::ListIpv4(_) => 4,
        IpSource::RepeatIpv6 { .. } | IpSource::RangeIpv6(_) | IpSource::ListIpv6(_) => 16,
    };

    let estimated_total_bytes: u64 = match &source {
        IpSource::RepeatIpv4 { count, .. } => count.saturating_mul(4),
        IpSource::RepeatIpv6 { count, .. } => count.saturating_mul(16),
        IpSource::RangeIpv4(net) => net.size().saturating_mul(4).into(),
        IpSource::RangeIpv6(_) => u64::MAX, // IPv6 range can be larger than u64 max bytes
        IpSource::ListIpv4(list) => (list.len() as u64).saturating_mul(4),
        IpSource::ListIpv6(list) => (list.len() as u64).saturating_mul(16),
    };

    // Buffer size logic: dynamic based on total size, max 64KB
    let max_buffer_size = 64 * 1024;
    let mut buffer_size = std::cmp::min(estimated_total_bytes, max_buffer_size as u64) as usize;

    // Ensure buffer size is a multiple of ip_len
    if buffer_size == 0 {
        return Ok(());
    }
    if !buffer_size.is_multiple_of(ip_len) {
        buffer_size -= buffer_size % ip_len;
    }
    if buffer_size == 0 {
        // Fallback for extremely small estimated_total_bytes < ip_len (should not happen if count >= 1)
        buffer_size = ip_len;
    }

    let mut buffer = Vec::with_capacity(buffer_size);

    match source {
        IpSource::RepeatIpv4 { ip, count } => {
            let ips_per_buffer = buffer_size / 4;
            for _ in 0..ips_per_buffer {
                buffer.extend_from_slice(&ip);
            }

            let full_writes = count / ips_per_buffer as u64;
            let remaining = count % ips_per_buffer as u64;

            for _ in 0..full_writes {
                writer.write_all(&buffer).await?;
            }
            if remaining > 0 {
                let remainder_bytes = remaining as usize * 4;
                writer.write_all(&buffer[..remainder_bytes]).await?;
            }
        }
        IpSource::RepeatIpv6 { ip, count } => {
            let ips_per_buffer = buffer_size / 16;
            for _ in 0..ips_per_buffer {
                buffer.extend_from_slice(&ip);
            }

            let full_writes = count / ips_per_buffer as u64;
            let remaining = count % ips_per_buffer as u64;

            for _ in 0..full_writes {
                writer.write_all(&buffer).await?;
            }
            if remaining > 0 {
                let remainder_bytes = remaining as usize * 16;
                writer.write_all(&buffer[..remainder_bytes]).await?;
            }
        }
        IpSource::RangeIpv4(net) => {
            for ip in net.iter() {
                buffer.extend_from_slice(&ip.octets());
                if buffer.len() >= buffer_size {
                    writer.write_all(&buffer).await?;
                    buffer.clear();
                }
            }
            if !buffer.is_empty() {
                writer.write_all(&buffer).await?;
            }
        }
        IpSource::RangeIpv6(net) => {
            for ip in net.iter() {
                buffer.extend_from_slice(&ip.octets());
                if buffer.len() >= buffer_size {
                    writer.write_all(&buffer).await?;
                    buffer.clear();
                }
            }
            if !buffer.is_empty() {
                writer.write_all(&buffer).await?;
            }
        }
        IpSource::ListIpv4(list) => {
            for ip in list {
                buffer.extend_from_slice(&ip);
                if buffer.len() >= buffer_size {
                    writer.write_all(&buffer).await?;
                    buffer.clear();
                }
            }
            if !buffer.is_empty() {
                writer.write_all(&buffer).await?;
            }
        }
        IpSource::ListIpv6(list) => {
            for ip in list {
                buffer.extend_from_slice(&ip);
                if buffer.len() >= buffer_size {
                    writer.write_all(&buffer).await?;
                    buffer.clear();
                }
            }
            if !buffer.is_empty() {
                writer.write_all(&buffer).await?;
            }
        }
    }
    writer.flush().await?;
    Ok(())
}
