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
        shared::{
            helper,
            types_and_config::{
                CaptureConfig, EmissionConfig, HashKeys, ReceiverChan, ScanErr, ScannerErrWithMsg,
                SenderChan, TCP_IPV4_PACKET_SIZE, TCP_IPV6_PACKET_SIZE,
            },
        },
    },
};

pub fn _remove_xdp_program(interface: &str) -> Result<(), ScannerErrWithMsg> {
    let output = Command::new("ip")
        .args(["link", "set", "dev", interface, "xdp", "off"])
        .output()
        .map_err(|e| ScannerErrWithMsg {
            err: ScanErr::Cleanup,
            msg: format!("Failed to execute ip link set xdp off: {:?}", e),
        })?;

    if !output.status.success() {
        return Err(ScannerErrWithMsg {
            err: ScanErr::Cleanup,
            msg: format!(
                "Failed to remove XDP program: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        });
    }
    Ok(())
}

/// hash is just stable for the current programme run
pub fn _create_sequence_number(
    src_ip: &[u8],
    src_port: &[u8; 2],
    dst_ip: &[u8],
    dst_port: &[u8; 2],
) -> u32 {
    // hasher instances use the same key while running in the same programme
    let mut hasher = DefaultHasher::new();

    (src_ip, src_port, dst_ip, dst_port).hash(&mut hasher);
    hasher.finish() as u32
}

pub fn _create_xdp_rx_socket(
    current_nic_queue: usize,
    interface: String,
) -> Result<xdp_socket::socket::RxSocket, ScannerErrWithMsg> {
    let if_index = match helper::find_interface_index_by_name(&interface) {
        Some(res) => res,
        None => {
            return Err(ScannerErrWithMsg {
                err: ScanErr::Socket,
                msg: String::from("Error finding ethernet interface index"),
            });
        }
    };
    let config = xdp_socket::XdpConfig {
        zero_copy: Some(true),
        ..Default::default()
    };
    match xdp_socket::create_rx_socket(if_index, current_nic_queue as u32, Some(config)) {
        Ok(s) => {
            eprintln!("XDP rx socket started with zero-copy mode");
            Ok(s)
        }
        Err(_) => match xdp_socket::create_rx_socket(if_index, current_nic_queue as u32, None) {
            Ok(s) => {
                eprintln!("XDP rx socket started with copy mode");
                Ok(s)
            }
            Err(e) => Err(ScannerErrWithMsg {
                err: ScanErr::Socket,
                msg: format!("Error creating xdp rx socket: {:?}", e),
            }),
        },
    }
}

pub fn _decide_affinity_core(available: &[CoreId], used: &mut Vec<usize>) -> CoreId {
    // Filter noch nicht genutzte Kerne
    let available_cores: Vec<_> = available
        .iter()
        .filter(|c| !used.contains(&c.id))
        .cloned()
        .collect::<Vec<_>>();

    // Zufälligen Kern auswählen
    let core_id = *available_cores.choose(&mut rng()).unwrap();
    let id = core_id.id;
    used.push(id);
    core_id
}

pub fn _disable_incoming_packet_visibility_kernel()
-> Result<std::process::ExitStatus, ScannerErrWithMsg> {
    Command::new("sudo")
        .args([
            "iptables",
            "-I",
            "INPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,ACK",
            "SYN,ACK",
            "-j",
            "DROP",
        ])
        .status()
        .map_err(|e| ScannerErrWithMsg {
            err: ScanErr::Config,
            msg: format!("Error diabling automatic RST sending by kernel: {:?}", e),
        })
}

pub fn _enable_incoming_packet_visibility_kernel() -> Result<std::process::Output, ScannerErrWithMsg>
{
    Command::new("sudo")
        .args([
            "iptables",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "SYN,ACK",
            "SYN,ACK",
            "-j",
            "DROP",
        ])
        .output()
        .map_err(|e| ScannerErrWithMsg {
            err: ScanErr::Config,
            msg: format!("Error enabling automatic RST sending by kernel: {:?}", e),
        })
}
