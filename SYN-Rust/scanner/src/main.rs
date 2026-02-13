use std::hash::Hash;
use std::sync::Arc;

use clap::Parser;
use clap_derive::Parser as DeriveParser;
use pnet::util::MacAddr;
use tokio::io::{BufReader, Stdin};

use crate::scan_utils::job_controlling::parser_std_in::StdInParser;
use crate::scan_utils::job_controlling::scan_job::ScanJob;
use crate::scan_utils::shared::helper::{self};

use crate::scan_utils::shared::types_and_config::{CaptureConfig, EmissionConfig, HashKeys};
use anyhow::Context;
use anyhow::Context as _;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use log::{info, warn};
use rand::Rng;
use tokio::signal; // (1)

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod scan_utils;

#[derive(DeriveParser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path zum File, aus welchem die dst_ips gelesen werden sollen
    #[arg(long, alias = "sfp", default_value_t = String::new())]
    string_file_path: String,

    /// Path zum File, aus welchem die dst_ips gelesen werden sollen
    #[arg(long, alias = "bfp", default_value_t = String::new())]
    bytes_file_path: String,

    /// Anzahl der NIC-Queues
    #[arg(long, alias = "nq", default_value_t = 1)]
    num_nic_queues: usize,

    /// Packet Parsing Timeout in Millisekunden
    #[arg(long, alias = "timeout", default_value_t = 3000)]
    parsing_timeout_millis: u64,

    /// Sollen Pakete in Batches gesendet werden?
    #[arg(long, alias = "batch")]
    send_in_batches: bool,

    /// XDP-Modus aktivieren
    #[arg(long)]
    xdp: bool,

    /// Generic XDP Mode erzwingen
    #[arg(long)]
    generic_mode: bool,

    /// Interface name for XDP attachment (e.g., eno1)
    #[arg(long, alias = "iface", default_value = "")]
    interface: String,
}

// struct Cleanup {
//     interface: String,
// }

// impl Drop for Cleanup {
//     fn drop(&mut self) {}
// }

// unit / integration Tests womöglich schreiben - ongoing
// assembler - check
// rate_limiter - check
// parser
// helper
// bucket
// (sender / receiver / finish broadcaster)

// TODO for the future:
// sudo ethtool -G enp6s0 rx 4096 tx 4096 hinzufügen
// change duplicate Erkennnung
// batch size für xdp auf 64? capturen in batches?
// config validation after parsing

// TODOs for future work
// (irq balance ausschalten und korrekte cores pinnen (siehe docs))
// Allgemeine Struktur anpassen für unterschiedliche Protokolle

// NOTICE: Error output and logging is bound to the StdErr output, use "sudo ./SYNScanner 2>stderr.txt"
// to show it in a seperate File or "sudo ./SYNScanner 2>/dev/null" to ignore it

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // ARGS & SCAN CONFIG
    let mut args = Args::parse();

    let (mut emission_cfg, mut capture_cfg, parser) = helper::prepare_configs_and_parser(&mut args)
        .await
        .expect("Failed to parse config");

    // XDP CONFIG
    // env_logger::init();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        log::debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at runtime
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/scanner"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut Xdp = ebpf.program_mut("xdp_node").unwrap().try_into()?;
    program.load()?;

    if args.generic_mode {
        program
            .attach(&emission_cfg.interface, XdpFlags::SKB_MODE)
            .context("failed to attach XDP program in SKB (Generic) mode")?;
        eprintln!("XDP Mode: SKB (Generic, enforced)");
    } else {
        if program
            .attach(&emission_cfg.interface, XdpFlags::DRV_MODE)
            .is_ok()
        {
            eprintln!("XDP Mode: Driver (Native, fast)");
        } else {
            program
                .attach(&emission_cfg.interface, XdpFlags::SKB_MODE)
                .context("failed to attach XDP program in both Driver and SKB mode")?;
            eprintln!("XDP Mode: SKB (Generic, slow)");
        }
    }
    // program.attach(&emission_cfg.interface, XdpFlags::default())?;

    // prepare shared recources
    let mut mode_map: aya::maps::Array<_, u8> =
        aya::maps::Array::try_from(ebpf.map_mut("MODE").unwrap())?;
    let mode_val: u8 = if capture_cfg.ipv6 { 1 } else { 0 };
    mode_map.set(0, mode_val, 0)?;

    let mut reset_map: aya::maps::Array<_, u8> =
        aya::maps::Array::try_from(ebpf.map_mut("RESET").unwrap())?;
    let reset_val: u8 = if emission_cfg.reset { 1 } else { 0 };
    reset_map.set(0, reset_val, 0)?;

    let mut siphash_map: aya::maps::Array<_, u64> =
        aya::maps::Array::try_from(ebpf.map_mut("SIPHASH_KEY").unwrap())?;
    let mut rng = rand::rng();
    let hash_keys = HashKeys {
        k0: Some(rng.random()),
        k1: Some(rng.random()),
    };
    emission_cfg.hash_keys = hash_keys.clone();
    siphash_map.set(0, hash_keys.k0.unwrap(), 0)?;
    siphash_map.set(1, hash_keys.k1.unwrap(), 0)?;

    if capture_cfg.ipv6 {
        let mut whitelist_ipv6: aya::maps::HashMap<_, [u8; 16], u8> =
            aya::maps::HashMap::try_from(ebpf.map_mut("WHITELIST_IPV6").unwrap())?;
        for ip in &capture_cfg.src_ips {
            if ip.len() == 16 {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(ip);
                whitelist_ipv6.insert(arr, 1, 0)?;
            }
        }
    } else {
        let mut whitelist_ipv4: aya::maps::HashMap<_, [u8; 4], u8> =
            aya::maps::HashMap::try_from(ebpf.map_mut("WHITELIST_IPV4").unwrap())?;
        for ip in &capture_cfg.src_ips {
            if ip.len() == 4 {
                let mut arr = [0u8; 4];
                arr.copy_from_slice(ip);
                whitelist_ipv4.insert(arr, 1, 0)?;
            }
        }
    }

    // Enable eBPF debug logs (set to 0 to disable)
    if let Ok(mut debug_map) = aya::maps::Array::<_, u8>::try_from(ebpf.map_mut("DEBUG").unwrap()) {
        let _ = debug_map.set(0, 0u8, 0);
    }

    let events = aya::maps::RingBuf::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // CLEANUP & CTRLC HANDLING
    // let _cleanup = Cleanup {
    //     interface: emission_cfg.interface.clone(),
    // };
    let cleanup_interface = emission_cfg.interface.clone();
    ctrlc::set_handler(move || {
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");

    // SCANJOB
    let arc_ec = Arc::new(emission_cfg);
    let arc_cc = Arc::new(capture_cfg);
    let (_external_stop, mut finish) =
        ScanJob::start_scanjob(args, arc_ec, arc_cc.clone(), parser, events).await;
    if finish.recv().await.is_none() {
        eprintln!("failed to finish scanjob successfully");
    };

    // Test
    if let Some(map) = ebpf.map("STATS")
        && let Ok(stats_map) = aya::maps::PerCpuArray::<_, u64>::try_from(map)
    {
        eprintln!("eBPF Stats:");
        let labels = ["Received", "Passed", "Valid", "RST sent"];
        for i in 0..4 {
            match stats_map.get(&i, 0) {
                Ok(values) => {
                    let sum: u64 = values.iter().sum();
                    eprintln!("  {}: {}", labels[i as usize], sum);
                }
                Err(e) => {
                    eprintln!("  {}: read error: {:?}", labels[i as usize], e);
                }
            }
        }
    }

    eprintln!("Scanjob done");
    std::process::exit(0);
}
