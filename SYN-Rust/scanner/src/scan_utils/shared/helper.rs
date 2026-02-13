use core::hash;
use std::{
    hash::{DefaultHasher, Hash, Hasher},
    process::Command,
    sync::Arc,
};

use core_affinity::CoreId;
use pnet::{datalink, util::MacAddr};
use rand::{rng, seq::IndexedRandom};
use siphasher::sip::SipHasher24;
use tokio::sync::mpsc::Sender;
use tokio::{
    io::{BufReader, Stdin},
    sync::mpsc::Receiver,
};

use crate::{
    Args,
    scan_utils::{
        job_controlling::parser_std_in::StdInParser,
        shared::types_and_config::{
            CaptureConfig, EmissionConfig, HashKeys, ReceiverChan, ScanErr, ScannerErrWithMsg,
            SenderChan, TCP_IPV4_PACKET_SIZE, TCP_IPV6_PACKET_SIZE,
        },
    },
};

/// hash is just stable for the current programme run
pub fn create_sequence_number(
    hash_keys: &HashKeys,
    src_ip: &[u8],
    src_port: &[u8; 2],
    dst_ip: &[u8],
    dst_port: &[u8; 2],
) -> Result<u32, ScannerErrWithMsg> {
    let mut hasher = if let (Some(k0), Some(k1)) = (hash_keys.k0, hash_keys.k1) {
        SipHasher24::new_with_keys(k0, k1)
    } else {
        return Err(ScannerErrWithMsg {
            err: ScanErr::Config,
            msg: format!("Hash Keys are empty {:?}, {:?}", hash_keys.k0, hash_keys.k1),
        });
    };
    hasher.write(src_ip);
    hasher.write(dst_ip);
    hasher.write(src_port);
    hasher.write(dst_port);

    let cookie_full = hasher.finish();
    Ok(cookie_full as u32)
}

// FIXME use ip neighbor | grep REACHABLE for default selection
pub fn find_fitting_ethernet_ifindex() -> Option<u32> {
    for iface in datalink::interfaces() {
        // Prüfe auf Ethernet (MAC vorhanden, nicht Loopback, nicht WLAN)
        if iface.is_up() && !iface.is_loopback() && iface.mac.is_some()
        //&& iface.name.starts_with("e")
        {
            return Some(iface.index);
        }
    }
    None
}

pub fn find_ethernet_iface_name(src_mac: MacAddr) -> Option<String> {
    for iface in datalink::interfaces() {
        // Prüfe auf Ethernet (MAC vorhanden, nicht Loopback, nicht WLAN)
        if iface.is_up() && !iface.is_loopback() && iface.mac == Some(src_mac)
        //&& iface.name.starts_with("e")
        {
            return Some(iface.name);
        }
    }
    None
}

pub fn find_interface_index_by_name(name: &str) -> Option<u32> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
        .map(|iface| iface.index)
}

pub fn create_signal_channels(count: u64) -> (Vec<Sender<String>>, Vec<Receiver<String>>) {
    let mut tx_vec = Vec::with_capacity(count as usize);
    let mut rx_vec = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        tx_vec.push(tx);
        rx_vec.push(rx);
    }

    (tx_vec, rx_vec)
}

pub fn create_sender_receiver_lists(
    num_nic_queues: usize,
    send_in_batches: bool,
) -> (SenderChan, ReceiverChan) {
    if send_in_batches {
        let mut batch_senders = Vec::with_capacity(num_nic_queues);
        let mut batch_receivers = Vec::with_capacity(num_nic_queues);

        for _ in 0..num_nic_queues {
            let (tx_batch, rx_batch) = tokio::sync::mpsc::channel::<Vec<Vec<u8>>>(1000);
            batch_senders.push(tx_batch);
            batch_receivers.push(rx_batch);
        }

        (
            SenderChan::BatchList(batch_senders),
            ReceiverChan::BatchList(batch_receivers),
        )
    } else {
        let mut packet_senders = Vec::with_capacity(num_nic_queues);
        let mut packet_receivers = Vec::with_capacity(num_nic_queues);

        for _ in 0..num_nic_queues {
            let (tx_packet, rx_packet) = tokio::sync::mpsc::channel::<Vec<u8>>(1000);
            packet_senders.push(tx_packet);
            packet_receivers.push(rx_packet);
        }

        (
            SenderChan::PacketList(packet_senders),
            ReceiverChan::PacketList(packet_receivers),
        )
    }
}

pub fn create_dst_ip_channels(ipv6: bool) -> (SenderChan, ReceiverChan) {
    if ipv6 {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<[u8; 16]>>(100);
        (SenderChan::ParsedIpv6(tx), ReceiverChan::ParsedIpv6(rx))
    } else {
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<[u8; 4]>>(100);
        (SenderChan::ParsedIpv4(tx), ReceiverChan::ParsedIpv4(rx))
    }
}

/// Berechnet die optimale assembler_size
pub fn calculate_optimal_assembler_size(
    scan_rate_mbit: u64,
    batch_size: usize,
    ipv6: bool,
) -> usize {
    // Wenn keine Rate gesetzt ist (unendlich), nimm große Puffer
    if scan_rate_mbit == 0 {
        return 65536;
    }

    let packet_size: u64 = if ipv6 {
        TCP_IPV6_PACKET_SIZE as u64
    } else {
        TCP_IPV4_PACKET_SIZE as u64
    };

    let bytes_per_sec = scan_rate_mbit * 125_000;
    let packets_per_sec = bytes_per_sec / packet_size;

    let target_wakeups_per_sec = 10;

    let target_packet_count = packets_per_sec / target_wakeups_per_sec;

    let clamped_count = target_packet_count.clamp(2048, 262_144);

    let optimal = if batch_size > 0 {
        clamped_count.div_ceil(batch_size as u64)
    } else {
        clamped_count
    };

    optimal as usize
}

pub async fn prepare_configs_and_parser(
    args: &mut Args,
) -> Result<(EmissionConfig, CaptureConfig, StdInParser<Stdin>), String> {
    // Start parsing from stdIn: Config
    let std_in = tokio::io::stdin();
    let mut parser = StdInParser {
        dst_ip_sender: None,
        buf_reader: BufReader::new(std_in),
    };
    let given_cfg = Arc::new(
        parser
            .parse_config()
            .await
            .map_err(|e| format!("{:?}: {}", e.err, e.msg))?,
    );

    if args.interface.is_empty()
        && let Some(name) = find_ethernet_iface_name(MacAddr::from(given_cfg.src_mac))
    {
        args.interface = name;
    }

    eprintln!("Using device {}", args.interface);

    let batch_size = match (args.xdp, args.send_in_batches) {
        (true, true) => 32,
        (false, true) => 128,
        _ => 0,
    };
    let assembler_size =
        calculate_optimal_assembler_size(given_cfg.scan_rate, batch_size, given_cfg.ipv6);

    let (emission_config, capture_config) =
        given_cfg.extract_configs(args, batch_size, assembler_size);

    Ok((emission_config, capture_config, parser))
}

pub fn create_xdp_bi_sockets(
    num_nic_queues: usize,
    interface: String,
    zero_copy: bool,
) -> Result<
    (
        Vec<xdp_socket::socket::TxSocket>,
        Vec<xdp_socket::socket::RxSocket>,
    ),
    ScannerErrWithMsg,
> {
    let mut tx_sockets = Vec::with_capacity(num_nic_queues);
    let mut rx_sockets = Vec::with_capacity(num_nic_queues);
    for i in 0..num_nic_queues {
        let (tx, rx) = create_xdp_bi_socket(i, interface.clone(), zero_copy)?;
        tx_sockets.push(tx);
        rx_sockets.push(rx);
    }
    Ok((tx_sockets, rx_sockets))
}

fn create_xdp_bi_socket(
    current_nic_queue: usize,
    interface: String,
    zero_copy: bool,
) -> Result<(xdp_socket::socket::TxSocket, xdp_socket::socket::RxSocket), ScannerErrWithMsg> {
    let if_index = match find_interface_index_by_name(&interface) {
        Some(res) => res,
        None => {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Socket,
                msg: String::from("Error finding ethernet interface index"),
            });
        }
    };
    let config = xdp_socket::XdpConfig {
        zero_copy: Some(zero_copy),
        ..Default::default()
    };
    match xdp_socket::create_bi_socket(if_index, current_nic_queue as u32, Some(config)) {
        Ok(s) => {
            eprintln!("XDP bi socket started with zero-copy mode: {}", zero_copy);
            Ok(s)
        }
        Err(e) => Err(ScannerErrWithMsg {
            err: ScanErr::Socket,
            msg: format!(
                "Error creating xdp bi socket with zero-copy = {}: {:?}",
                zero_copy, e
            ),
        }),
    }
}

pub fn create_xdp_tx_sockets(
    num_nic_queues: usize,
    interface: String,
    zero_copy: bool,
) -> Result<Vec<xdp_socket::socket::TxSocket>, ScannerErrWithMsg> {
    let mut tx_sockets = Vec::with_capacity(num_nic_queues);
    for i in 0..num_nic_queues {
        let tx = create_xdp_tx_socket(i, interface.clone(), zero_copy)?;
        tx_sockets.push(tx);
    }
    Ok(tx_sockets)
}

fn create_xdp_tx_socket(
    current_nic_queue: usize,
    interface: String,
    zero_copy: bool,
) -> Result<xdp_socket::socket::TxSocket, ScannerErrWithMsg> {
    let if_index = match find_interface_index_by_name(&interface) {
        Some(res) => res,
        None => {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Socket,
                msg: String::from("Error finding ethernet interface index"),
            });
        }
    };

    let config = xdp_socket::XdpConfig {
        zero_copy: Some(zero_copy),
        ..Default::default()
    };
    match xdp_socket::create_tx_socket(if_index, current_nic_queue as u32, Some(config)) {
        Ok(s) => {
            eprintln!("XDP tx socket started with zero-copy mode: {}", zero_copy);
            Ok(s)
        }
        Err(e) => Err(ScannerErrWithMsg {
            err: ScanErr::Socket,
            msg: format!("Error creating xdp tx socket: {:?}", e),
        }),
    }
}

pub fn create_done_channels(count: usize) -> (Vec<Sender<String>>, Vec<Receiver<String>>) {
    let mut tx_channels = Vec::with_capacity(count);
    let mut rx_channels = Vec::with_capacity(count);
    for _ in 0..count {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        tx_channels.push(tx);
        rx_channels.push(rx);
    }
    (tx_channels, rx_channels)
}
