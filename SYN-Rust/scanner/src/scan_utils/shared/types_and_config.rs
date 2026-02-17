use std::sync::Arc;

use aya::maps::{MapData, XskMap};
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{Receiver, Sender};

use crate::Args;

// Packet sizes used for rate_limiter in bytes
pub const TCP_IPV4_PACKET_SIZE: usize = 60;
pub const TCP_IPV6_PACKET_SIZE: usize = 74;
// TODO add UPD scan
pub const UDP_PACKET_SIZE: usize = 0;

pub const DONE: &str = "done";
pub const FINISH: &str = "finish";
pub const CONTINUE: &str = "continue";
pub const STOP: &str = "stop";

#[derive(Debug)]
pub struct ScannerErrWithMsg {
    pub err: ScanErr,
    pub msg: String,
}

#[derive(Debug, PartialEq)]
pub enum ScanErr {
    Socket,
    Config,
    Parsing,
    Input,
    Sending,
    Assembling,
    Capturing,
    RateLimiting,
    DuplicationBucket,
    Cleanup,
}

#[derive(Clone)]
pub struct SignalSender {
    pub tx_rate_limiter: Sender<String>,
}

impl<'a> IntoIterator for &'a SignalSender {
    type Item = &'a Sender<String>;
    type IntoIter = std::iter::Once<&'a Sender<String>>;

    fn into_iter(self) -> Self::IntoIter {
        // Erstellt einen Iterator, der genau einmal den tx_rate_limiter liefert.
        std::iter::once(&self.tx_rate_limiter)

        // Falls du später mehr Felder hast, kannst du chainen:
        // std::iter::once(&self.tx_rate_limiter).chain(std::iter::once(&self.tx_parser))
    }
}

pub struct SignalReceiver {
    pub rx_rate_limiter: Receiver<String>,
}

#[derive(Debug, Clone)]
pub struct HashKeys {
    pub k0: Option<u64>,
    pub k1: Option<u64>,
}

#[derive(Debug)]
pub enum SenderChan {
    ParsedIpv4(Sender<Vec<[u8; 4]>>),
    ParsedIpv6(Sender<Vec<[u8; 16]>>),
    Packet(Sender<Vec<u8>>),
    PacketList(Vec<Sender<Vec<u8>>>),
    Batch(Sender<Vec<Vec<u8>>>),
    BatchList(Vec<Sender<Vec<Vec<u8>>>>),
}

#[derive(Debug)]
pub enum ReceiverChan {
    ParsedIpv4(Receiver<Vec<[u8; 4]>>),
    ParsedIpv6(Receiver<Vec<[u8; 16]>>),
    Packet(Receiver<Vec<u8>>),
    PacketList(Vec<Receiver<Vec<u8>>>),
    Batch(Receiver<Vec<Vec<u8>>>),
    BatchList(Vec<Receiver<Vec<Vec<u8>>>>),
}

#[derive(Debug)]
pub enum AssemblerDstIps {
    Ipv4(Vec<[u8; 4]>),
    Ipv6(Vec<[u8; 16]>),
}

// Ermöglicht das Klonen von AssemblerDstIps für Retry-Buffer-Logik
impl Clone for AssemblerDstIps {
    fn clone(&self) -> Self {
        match self {
            AssemblerDstIps::Ipv4(vec) => AssemblerDstIps::Ipv4(vec.clone()),
            AssemblerDstIps::Ipv6(vec) => AssemblerDstIps::Ipv6(vec.clone()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Target<'a> {
    #[serde(rename = "Port")]
    pub port: u16,
    #[serde(rename = "Target")]
    pub ip: &'a [u8],
}

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
    #[serde(rename = "Deduplicate", default)]
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
    #[serde(skip)]
    pub dst_mac: [u8; 6],
    #[serde(skip)]
    pub src_mac: [u8; 6],
}

#[derive(Debug)]
pub struct EmissionConfig {
    pub retries: u64,
    pub ipv6: bool,
    pub protocol: u64,
    pub batch_size: usize,
    pub scan_rate: u64,
    pub templates: Vec<Vec<u8>>,
    pub send_in_batches: bool,
    pub assembler_size: usize,
    pub parsing_timeout_millis: u64,
    pub af_xdp: bool,
    pub num_nic_queues: usize,
    pub reset: bool,
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub dst_ports: Vec<u16>,
    pub interface: String,
    pub hash_keys: HashKeys,
    pub zero_copy: bool,
}

pub struct CaptureConfig {
    pub scan_id: u64,
    pub ipv6: bool,
    pub src_ports: Vec<u16>,
    pub src_ips: Vec<Vec<u8>>,
    pub reset: bool,
    pub deduplicate: bool,
    pub protocol: u64,
    pub parsing_timeout_millis: u64,
    pub interface: String,
    pub num_nic_queues: usize,
}

impl GivenConfig {
    pub fn extract_configs(
        &self,
        args: &Args,
        batch_size: usize,
        assembler_size: usize,
    ) -> (EmissionConfig, CaptureConfig) {
        let emission_config = EmissionConfig {
            retries: self.retries,
            ipv6: self.ipv6,
            protocol: self.protocol,
            batch_size,
            scan_rate: self.scan_rate,
            templates: self.templates.clone(),
            send_in_batches: args.send_in_batches,
            assembler_size,
            parsing_timeout_millis: args.parsing_timeout_millis,
            dst_mac: MacAddr::from(self.dst_mac),
            af_xdp: args.xdp,
            num_nic_queues: args.num_nic_queues,
            reset: self.reset,
            src_mac: MacAddr::from(self.src_mac),
            dst_ports: self.dst_ports.clone(),
            interface: args.interface.clone(),
            hash_keys: HashKeys { k0: None, k1: None },
            zero_copy: self.zero_copy,
        };
        let capture_config = CaptureConfig {
            scan_id: self.scan_id,
            ipv6: self.ipv6,
            src_ports: self.src_ports.clone(),
            src_ips: self.src_ips.clone(),
            reset: self.reset,
            deduplicate: self.deduplicate,
            parsing_timeout_millis: args.parsing_timeout_millis,
            protocol: self.protocol,
            interface: args.interface.clone(),
            num_nic_queues: args.num_nic_queues,
        };
        (emission_config, capture_config)
    }
}
