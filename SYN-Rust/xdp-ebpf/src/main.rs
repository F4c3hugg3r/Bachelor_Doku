#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_xdp_adjust_tail,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use core::hash::Hasher;
use core::mem;
use network_types::ip::Ipv6Hdr;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};
use xdp_common::PacketLog;

use aya_log_ebpf::info;
use siphasher::sip::SipHasher24;

// 0: RX_TOTAL, 1: RX_PASSED, 2: RX_VALID, 3: TX_RST
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

#[map]
static WHITELIST_IPV4: HashMap<[u8; 4], u8> = HashMap::with_max_entries(1024, 0);

#[map]
static WHITELIST_IPV6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(1024, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0); // 16MB RingBuf

// 0 = ipv4, 1 = ipv6
#[map]
static MODE: Array<u8> = Array::with_max_entries(1, 0);

// 0 = no reset, 1 = reset
#[map]
static RESET: Array<u8> = Array::with_max_entries(1, 0);

#[map]
static SIPHASH_KEY: Array<u64> = Array::with_max_entries(2, 0);

// 0 = no debug logs, 1 = enable selected logs
#[map]
static DEBUG: Array<u8> = Array::with_max_entries(1, 0);

#[xdp]
pub fn xdp_node(ctx: XdpContext) -> u32 {
    inc_stat(0); // RX_TOTAL
    let ret = match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    };

    if ret == xdp_action::XDP_PASS {
        inc_stat(1); // RX_PASSED
    } else if ret == xdp_action::XDP_TX {
        inc_stat(3); // TX_RST
    }

    ret
}

fn inc_stat(idx: u32) {
    if let Some(val) = STATS.get_ptr_mut(idx) {
        unsafe { *val += 1 };
    }
}

pub enum DstIpHdr {
    Ipv4(*const Ipv4Hdr),
    Ipv6(*const Ipv6Hdr),
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

// FIXME add support for other protocols
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let mode = *MODE.get(0).unwrap_or(&0);
    let debug = *DEBUG.get(0).unwrap_or(&0);

    // Unconditional log to verify logging works
    // info!(&ctx, "XDP pkt: mode={}, debug={}", mode, debug);

    let dst_ips: DstIpHdr = match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {
            if mode == 0 {
                match unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN) } {
                    Ok(hdr) => DstIpHdr::Ipv4(hdr),
                    Err(_) => {
                        if debug != 0 {
                            info!(&ctx, "pass: v4 truncated");
                        }
                        return Err(());
                    }
                }
            } else {
                if debug != 0 {
                    info!(
                        &ctx,
                        "pass: mode mismatch (v4), mode={}",
                        if mode == 0 { 4 } else { 6 }
                    );
                }
                return Ok(xdp_action::XDP_PASS);
            }
        }
        Ok(EtherType::Ipv6) => {
            if mode == 1 {
                DstIpHdr::Ipv6(unsafe { ptr_at(&ctx, EthHdr::LEN)? })
            } else {
                if debug != 0 {
                    info!(
                        &ctx,
                        "pass: mode mismatch (v6), mode={}",
                        if mode == 0 { 4 } else { 6 }
                    );
                }
                return Ok(xdp_action::XDP_PASS);
            }
        }
        _ => {
            if debug != 0 {
                let t = u16::from_be(unsafe { (*ethhdr).ether_type });
                info!(&ctx, "pass: non ip eth: {:x}", t);
            }
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let (ack_num, cookie, packet_log, tcp_flags) = match dst_ips {
        DstIpHdr::Ipv4(ip_hdr) => {
            let dst_addr = unsafe { (*ip_hdr).dst_addr };
            if unsafe { WHITELIST_IPV4.get(dst_addr).is_none() } {
                if debug != 0 {
                    info!(&ctx, "pass: v4 not whitelisted: {:i}", dst_addr);
                }
                return Ok(xdp_action::XDP_PASS);
            }

            match unsafe { (*ip_hdr).proto } {
                IpProto::Tcp => {}
                _ => {
                    let p = unsafe { (*ip_hdr).proto };
                    if debug != 0 {
                        info!(&ctx, "pass: v4 non-tcp: {}", p as u8);
                    }
                    return Ok(xdp_action::XDP_PASS);
                }
            }
            let ip_header_len = unsafe { (*ip_hdr).ihl() } as usize;
            let tcphdr: *const TcpHdr = match unsafe { ptr_at(&ctx, EthHdr::LEN + ip_header_len) } {
                Ok(h) => h,
                Err(_) => {
                    if debug != 0 {
                        info!(&ctx, "pass: v4 tcp truncated");
                    }
                    return Err(());
                }
            };

            let src_addr_bytes = unsafe { (*ip_hdr).src_addr };
            let dst_addr_bytes = unsafe { (*ip_hdr).dst_addr };

            let src_port_bytes = unsafe { (*tcphdr).source };
            let dst_port_bytes = unsafe { (*tcphdr).dest };

            let k0 = *SIPHASH_KEY.get(0).unwrap_or(&0);
            let k1 = *SIPHASH_KEY.get(1).unwrap_or(&0);

            let mut hasher = SipHasher24::new_with_keys(k0, k1);

            hasher.write(&dst_addr_bytes);
            hasher.write(&src_addr_bytes);
            hasher.write(&dst_port_bytes);
            hasher.write(&src_port_bytes);

            let cookie_full = hasher.finish();
            let cookie = cookie_full as u32;

            let mut src_addr = [0u8; 16];
            src_addr[0] = src_addr_bytes[0];
            src_addr[1] = src_addr_bytes[1];
            src_addr[2] = src_addr_bytes[2];
            src_addr[3] = src_addr_bytes[3];

            let log = PacketLog {
                src_addr,
                port: src_port_bytes,
                version: 4,
            };

            let tcp_flags = unsafe { *((tcphdr as *const u8).add(13)) };

            (
                u32::from_be_bytes(unsafe { (*tcphdr).ack_seq }),
                cookie,
                log,
                tcp_flags,
            )
        }
        DstIpHdr::Ipv6(ip) => {
            let dst_addr = unsafe { (*ip).dst_addr };
            if unsafe { WHITELIST_IPV6.get(dst_addr).is_none() } {
                if debug != 0 {
                    info!(&ctx, "pass: v6 not whitelisted");
                }
                return Ok(xdp_action::XDP_PASS);
            }
            match unsafe { (*ip).next_hdr } {
                IpProto::Tcp => {}
                _ => {
                    let p = unsafe { (*ip).next_hdr };
                    if debug != 0 {
                        info!(&ctx, "pass: v6 non-tcp: {}", p as u8);
                    }
                    return Ok(xdp_action::XDP_PASS);
                }
            }
            // FIXME wenn der ipv6 Header Options hat, ist der Offset falsch
            let ip_header_len = 40;
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + ip_header_len)? };

            let src_addr_bytes = unsafe { (*ip).src_addr };
            let dst_addr_bytes = unsafe { (*ip).dst_addr };

            let src_port_bytes = unsafe { (*tcphdr).source };
            let dst_port_bytes = unsafe { (*tcphdr).dest };

            let k0 = *SIPHASH_KEY.get(0).unwrap_or(&0);
            let k1 = *SIPHASH_KEY.get(1).unwrap_or(&0);

            let mut hasher = SipHasher24::new_with_keys(k0, k1);

            hasher.write(&dst_addr_bytes);
            hasher.write(&src_addr_bytes);
            hasher.write(&dst_port_bytes);
            hasher.write(&src_port_bytes);

            let cookie_full = hasher.finish();
            let cookie = cookie_full as u32;

            let log = PacketLog {
                src_addr: src_addr_bytes,
                port: src_port_bytes,
                version: 6,
            };

            let tcp_flags = unsafe { *((tcphdr as *const u8).add(13)) };

            (
                u32::from_be_bytes(unsafe { (*tcphdr).ack_seq }),
                cookie,
                log,
                tcp_flags,
            )
        }
    };

    // RST | ACK check
    if (tcp_flags & 0x04) != 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // 4. Validierung (ack == cookie + 1)
    if (ack_num.wrapping_sub(1)) == cookie {
        inc_stat(2); // RX_VALID
        if let Some(mut entry) = EVENTS.reserve::<PacketLog>(0) {
            entry.write(packet_log);
            entry.submit(0);
        }
        // if debug != 0 {
        //     info!(&ctx, "redirect q={}", idx as u64);
        // }

        let reset = *RESET.get(0).unwrap_or(&0);
        if reset != 0 {
            try_rst_packet(&ctx)
        } else {
            Ok(xdp_action::XDP_DROP)
        }
    } else {
        if debug != 0 {
            info!(
                &ctx,
                "pass: cookie mismatch, ack={}, cookie={}", ack_num, cookie
            );
        }
        Ok(xdp_action::XDP_PASS)
    }
}

fn try_rst_packet(ctx: &XdpContext) -> Result<u32, ()> {
    let debug = *DEBUG.get(0).unwrap_or(&0);

    // 1. Ethernet Header
    let eth: *mut EthHdr = match unsafe { ptr_at_mut(ctx, 0) } {
        Ok(p) => p,
        Err(_) => {
            if debug != 0 {
                info!(ctx, "rst: eth ptr fail");
            }
            return Err(());
        }
    };

    // Check IPv4
    if u16::from_be(unsafe { (*eth).ether_type }) != 0x0800 {
        if debug != 0 {
            info!(ctx, "rst: not ipv4");
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // 2. IPv4 Header
    let ip: *mut Ipv4Hdr = match unsafe { ptr_at_mut(ctx, EthHdr::LEN) } {
        Ok(p) => p,
        Err(_) => {
            if debug != 0 {
                info!(ctx, "rst: ip ptr fail");
            }
            return Err(());
        }
    };

    // Check TCP
    if unsafe { (*ip).proto } != IpProto::Tcp {
        if debug != 0 {
            info!(ctx, "rst: not tcp");
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // 3. TCP Header
    let tcp: *mut TcpHdr = match unsafe { ptr_at_mut(ctx, EthHdr::LEN + Ipv4Hdr::LEN) } {
        Ok(p) => p,
        Err(_) => {
            if debug != 0 {
                info!(ctx, "rst: tcp ptr fail");
            }
            return Err(());
        }
    };

    if debug != 0 {
        info!(ctx, "rst: prep packet");
    }

    unsafe {
        mem::swap(&mut (*eth).src_addr, &mut (*eth).dst_addr);
        mem::swap(&mut (*ip).src_addr, &mut (*ip).dst_addr);

        // Set IP length to 40 bytes (20 IP + 20 TCP)
        let new_ip_len = (Ipv4Hdr::LEN + TcpHdr::LEN) as u16;
        (*ip).tot_len = new_ip_len.to_be_bytes();

        (*ip).check = [0u8; 2];
        (*ip).check = calc_csum(ip as *const u8, Ipv4Hdr::LEN, 0).to_le_bytes();

        // TCP Swap & Flags
        mem::swap(&mut (*tcp).source, &mut (*tcp).dest);

        // SEQ = Old ACK
        (*tcp).seq = (*tcp).ack_seq;
        (*tcp).ack_seq = [0u8; 4];

        let tcp_bytes = tcp as *mut u8;
        *tcp_bytes.add(12) = 0x50; // Data Offset 5 (20 bytes)
        *tcp_bytes.add(13) = 0x04; // RST flag

        (*tcp).window = [0u8; 2];
        (*tcp).urg_ptr = [0u8; 2];
        (*tcp).check = [0u8; 2];

        // checksum
        let ip_u8 = ip as *mut u8;
        let src_ptr = ip_u8.add(12) as *const u16;
        let dst_ptr = ip_u8.add(16) as *const u16;

        let mut pseudo_sum = 0u32;
        pseudo_sum += *src_ptr as u32;
        pseudo_sum += *src_ptr.add(1) as u32;
        pseudo_sum += *dst_ptr as u32;
        pseudo_sum += *dst_ptr.add(1) as u32;

        let proto = (*ip).proto as u32;
        pseudo_sum += proto << 8;

        let len = new_ip_len as u32 - Ipv4Hdr::LEN as u32; // 20 Bytes
        pseudo_sum += len << 8;
        // let tcp_len = TcpHdr::LEN as u32;
        // pseudo_sum += tcp_len << 8;
        (*tcp).check = calc_csum(tcp as *const u8, TcpHdr::LEN, pseudo_sum).to_le_bytes();

        let current_len = (ctx.data_end() - ctx.data()) as isize;
        let desired_len = (EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN) as isize;
        let delta = desired_len - current_len; // Sollte negativ sein

        if delta < 0 {
            if debug != 0 {
                info!(ctx, "rst: adj tail {}", delta as i32);
            }
            let ret = bpf_xdp_adjust_tail(ctx.ctx, delta as i32);
            if ret < 0 {
                if debug != 0 {
                    info!(ctx, "rst: adj tail err {}", ret);
                }
                return Err(());
            }
            // Nach diesem Call sind alle Pointer (eth, ip, tcp) UNGÜLTIG!
            // Wir greifen aber auch nicht mehr darauf zu.
        }
    }

    if debug != 0 {
        info!(ctx, "rst: tx");

        // Dump packet for debugging
        let data = ctx.data();
        let data_end = ctx.data_end();
        let len = data_end - data;
        info!(ctx, "rst: len {}", len);

        if len >= 54 {
            let b = data as *const u8;
            if data + 54 > data_end {
                return Ok(xdp_action::XDP_ABORTED);
            }
            unsafe {
                // Ethernet (0-13)
                info!(
                    ctx,
                    "Eth Dst: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    *b.add(0),
                    *b.add(1),
                    *b.add(2),
                    *b.add(3),
                    *b.add(4),
                    *b.add(5)
                );
                info!(
                    ctx,
                    "Eth Src: {:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    *b.add(6),
                    *b.add(7),
                    *b.add(8),
                    *b.add(9),
                    *b.add(10),
                    *b.add(11)
                );
                info!(ctx, "Eth Type: {:x}{:x}", *b.add(12), *b.add(13));

                // IP (14-33)
                info!(
                    ctx,
                    "IP Ver/IHL: {:x} TOS: {:x} Len: {:x}{:x}",
                    *b.add(14),
                    *b.add(15),
                    *b.add(16),
                    *b.add(17)
                );
                info!(
                    ctx,
                    "IP Id: {:x}{:x} Off: {:x}{:x}",
                    *b.add(18),
                    *b.add(19),
                    *b.add(20),
                    *b.add(21)
                );
                info!(
                    ctx,
                    "IP TTL: {:x} Proto: {:x} Sum: {:x}{:x}",
                    *b.add(22),
                    *b.add(23),
                    *b.add(24),
                    *b.add(25)
                );
                info!(
                    ctx,
                    "IP Src: {:x}.{:x}.{:x}.{:x}",
                    *b.add(26),
                    *b.add(27),
                    *b.add(28),
                    *b.add(29)
                );
                info!(
                    ctx,
                    "IP Dst: {:x}.{:x}.{:x}.{:x}",
                    *b.add(30),
                    *b.add(31),
                    *b.add(32),
                    *b.add(33)
                );

                // TCP (34-53)
                info!(
                    ctx,
                    "TCP Src: {:x}{:x} Dst: {:x}{:x}",
                    *b.add(34),
                    *b.add(35),
                    *b.add(36),
                    *b.add(37)
                );
                info!(
                    ctx,
                    "TCP Seq: {:x}{:x}{:x}{:x}",
                    *b.add(38),
                    *b.add(39),
                    *b.add(40),
                    *b.add(41)
                );
                info!(
                    ctx,
                    "TCP Ack: {:x}{:x}{:x}{:x}",
                    *b.add(42),
                    *b.add(43),
                    *b.add(44),
                    *b.add(45)
                );
                info!(
                    ctx,
                    "TCP Off/Flg: {:x}{:x} Win: {:x}{:x}",
                    *b.add(46),
                    *b.add(47),
                    *b.add(48),
                    *b.add(49)
                );
                info!(
                    ctx,
                    "TCP Sum: {:x}{:x} Urg: {:x}{:x}",
                    *b.add(50),
                    *b.add(51),
                    *b.add(52),
                    *b.add(53)
                );
            }
        } else {
            info!(ctx, "rst: len too short for dump");
        }
    }
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

// Simple One's Complement Checksumme für eBPF
#[inline(always)]
fn calc_csum(data: *const u8, len: usize, initial_sum: u32) -> u16 {
    let mut sum = initial_sum;
    let mut i = 0;

    // Verifier Loop Limit Workaround: Wir summieren in 2-Byte Schritten
    // Da wir nur Header (max ~60 Bytes) summieren, ist eine Obergrenze von 40 Iterationen sicher.
    while i < 40 {
        if i >= len / 2 {
            break;
        }
        unsafe {
            let val = *(data as *const u16).add(i);
            // Wir summieren die rohen Bytes (Network Order), das ist okay für Checksum
            sum += val as u32;
        }
        i += 1;
    }

    // Carry Bits falten
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// #[cfg(not(test))]
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     unsafe {
//         use core::hint::unreachable_unchecked;
//         unreachable_unchecked()
//     }
// }

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

// #![no_std]
// #![no_main]

// use aya_ebpf::{
//     bindings::xdp_action,
//     helpers::bpf_xdp_adjust_tail,
//     macros::{map, xdp},
//     maps::{Array, HashMap, PerCpuArray, RingBuf},
//     programs::XdpContext,
// };
// use aya_log_ebpf::info;
// use core::hash::Hasher;
// use core::mem;
// use siphasher::sip::SipHasher24;
// use xdp_common::PacketLog;

// // Wir nutzen die einfachen Structs vom DummyReceiver
// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct EthHdr {
//     pub dst_addr: [u8; 6],
//     pub src_addr: [u8; 6],
//     pub ether_type: u16,
// }

// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct Ipv4Hdr {
//     pub version_ihl: u8,
//     pub tos: u8,
//     pub tot_len: u16,
//     pub id: u16,
//     pub frag_off: u16,
//     pub ttl: u8,
//     pub proto: u8,
//     pub check: u16,
//     pub src_addr: u32,
//     pub dst_addr: u32,
// }

// #[repr(C)]
// #[derive(Debug, Copy, Clone)]
// pub struct TcpHdr {
//     pub source: u16,
//     pub dest: u16,
//     pub seq: u32,
//     pub ack_seq: u32,
//     pub doff_res: u8,
//     pub flags: u8,
//     pub window: u16,
//     pub check: u16,
//     pub urg_ptr: u16,
// }

// // Maps (angepasst für Scanner Funktionalität)
// // 0: RX_TOTAL, 1: RX_PASSED, 2: RX_VALID_COOKIE, 3: TX_RST
// #[map]
// static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// #[map]
// static WHITELIST_IPV4: HashMap<[u8; 4], u8> = HashMap::with_max_entries(1024, 0);

// #[map]
// static EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0); // 16MB RingBuf

// #[map]
// static SIPHASH_KEY: Array<u64> = Array::with_max_entries(2, 0);

// const ETH_P_IP: u16 = 0x0800;
// const IPPROTO_TCP: u8 = 6;
// const TCP_FLAG_ACK: u8 = 0x10;
// const TCP_FLAG_RST: u8 = 0x04;

// #[xdp]
// pub fn xdp_scanner(ctx: XdpContext) -> u32 {
//     match try_xdp_scanner(ctx) {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_ABORTED,
//     }
// }

// // Die sichere ptr_at Funktion vom DummyReceiver
// #[inline(always)]
// fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, u32> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = mem::size_of::<T>();

//     if start + offset + len > end {
//         return Err(xdp_action::XDP_DROP);
//     }

//     Ok((start + offset) as *mut T)
// }

// fn try_xdp_scanner(ctx: XdpContext) -> Result<u32, u32> {
//     if let Some(stats) = STATS.get_ptr_mut(0) {
//         unsafe { *stats += 1 }; // RX_TOTAL
//     }

//     // 1. Parsing
//     let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
//     if unsafe { (*eth_hdr).ether_type } != u16::from_be(ETH_P_IP) {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
//     if unsafe { (*ipv4_hdr).proto } != IPPROTO_TCP {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     let ihl = unsafe { (*ipv4_hdr).version_ihl } & 0x0F;
//     let ip_hdr_len = (ihl as usize) * 4;

//     if mem::size_of::<EthHdr>() + ip_hdr_len > (ctx.data_end() - ctx.data()) {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     let tcp_hdr: *const TcpHdr = ptr_at(&ctx, mem::size_of::<EthHdr>() + ip_hdr_len)?;

//     // --- FIX: Variablen HIER definieren, damit sie überall verfügbar sind ---
//     let src_addr = unsafe { (*ipv4_hdr).src_addr };
//     let dst_addr = unsafe { (*ipv4_hdr).dst_addr };
//     let src_port = unsafe { (*tcp_hdr).source };
//     let dst_port = unsafe { (*tcp_hdr).dest };
//     let ack_seq = unsafe { u32::from_be((*tcp_hdr).ack_seq) };
//     let tcp_flags = unsafe { (*tcp_hdr).flags };

//     // 2. Filter: Wir suchen NUR nach ACKs (Antwort auf unsere SYNs)
//     // Wenn KEIN ACK Flag gesetzt ist -> ignorieren
//     if (tcp_flags & TCP_FLAG_ACK) == 0 {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     // 3. Whitelist Check
//     // Wir prüfen, ob das Paket an eine IP geht, die wir erwarten (dest_addr = Wir).
//     // Die Variable `dst_addr` ist jetzt bekannt.
//     let dst_addr_bytes = dst_addr.to_ne_bytes();
//     if unsafe { WHITELIST_IPV4.get(dst_addr_bytes).is_none() } {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     // 4. Cookie Validierung
//     let k0 = *SIPHASH_KEY.get(0).unwrap_or(&0);
//     let k1 = *SIPHASH_KEY.get(1).unwrap_or(&0);

//     let mut hasher = SipHasher24::new_with_keys(k0, k1);
//     hasher.write(&src_addr.to_ne_bytes()); // Target IP
//     hasher.write(&dst_addr.to_ne_bytes()); // My IP (Scanner IP)
//     hasher.write(&src_port.to_ne_bytes()); // Target Port
//     hasher.write(&dst_port.to_ne_bytes()); // My Port

//     let cookie = hasher.finish() as u32;

//     // Check: ACK == Cookie + 1
//     if ack_seq.wrapping_sub(1) != cookie {
//         return Ok(xdp_action::XDP_DROP);
//     }

//     // --- Valid Cookie Found ---

//     if let Some(stats) = STATS.get_ptr_mut(2) {
//         unsafe { *stats += 1 }; // RX_VALID_COOKIE
//     }

//     // 5. RingBuf Logging
//     if let Some(mut entry) = EVENTS.reserve::<PacketLog>(0) {
//         let mut src_addr_arr = [0u8; 16];
//         let src_bytes = src_addr.to_ne_bytes();
//         // IPv4 in die ersten 4 Bytes mappen
//         src_addr_arr[0] = src_bytes[0];
//         src_addr_arr[1] = src_bytes[1];
//         src_addr_arr[2] = src_bytes[2];
//         src_addr_arr[3] = src_bytes[3];

//         let log = PacketLog {
//             src_addr: src_addr_arr,
//             port: src_port.to_ne_bytes(), // Port in Network Byte Order belassen
//             version: 4,
//         };
//         entry.write(log);
//         entry.submit(0);
//     }

//     // 6. RST Paket Senden
//     // Werte zwischenspeichern
//     let src_mac = unsafe { (*eth_hdr).src_addr };
//     let dst_mac = unsafe { (*eth_hdr).dst_addr };

//     let new_len = mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>() + mem::size_of::<TcpHdr>();
//     let old_len = ctx.data_end() - ctx.data();
//     let delta = (new_len as isize) - (old_len as isize);

//     if delta != 0 {
//         let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta as i32) };
//         if ret != 0 {
//             return Err(xdp_action::XDP_ABORTED);
//         }
//     }

//     // Pointer neu laden nach adjust_tail
//     let eth_hdr: *mut EthHdr = ptr_at(&ctx, 0)?;
//     let ipv4_hdr: *mut Ipv4Hdr = ptr_at(&ctx, mem::size_of::<EthHdr>())?;
//     let tcp_hdr: *mut TcpHdr = ptr_at(&ctx, mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>())?;

//     unsafe {
//         // Layer 2
//         (*eth_hdr).src_addr = dst_mac;
//         (*eth_hdr).dst_addr = src_mac;

//         // Layer 3
//         (*ipv4_hdr).version_ihl = 0x45;
//         (*ipv4_hdr).tot_len = u16::to_be(40);
//         (*ipv4_hdr).src_addr = dst_addr;
//         (*ipv4_hdr).dst_addr = src_addr;
//         (*ipv4_hdr).check = 0;
//         (*ipv4_hdr).check = ipv4_csum(ipv4_hdr);

//         // Layer 4
//         (*tcp_hdr).source = dst_port;
//         (*tcp_hdr).dest = src_port;
//         (*tcp_hdr).seq = u32::to_be(ack_seq);
//         (*tcp_hdr).ack_seq = 0;
//         (*tcp_hdr).doff_res = 0x50;
//         (*tcp_hdr).flags = TCP_FLAG_RST;
//         (*tcp_hdr).window = 0;
//         (*tcp_hdr).check = 0;
//         (*tcp_hdr).urg_ptr = 0;

//         (*tcp_hdr).check = tcp_csum(ipv4_hdr, tcp_hdr);
//     }

//     if let Some(stats) = STATS.get_ptr_mut(3) {
//         unsafe { *stats += 1 }; // TX_RST
//     }

//     Ok(xdp_action::XDP_TX)
// }

// unsafe fn ipv4_csum(hdr: *mut Ipv4Hdr) -> u16 {
//     let ptr = hdr as *const u16;
//     let mut sum = 0u32;
//     // Statische Loop Bounds für Verifier
//     for i in 0..10 {
//         sum += unsafe { *ptr.add(i) } as u32;
//     }
//     while (sum >> 16) != 0 {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }
//     !sum as u16
// }

// unsafe fn tcp_csum(ip_hdr: *mut Ipv4Hdr, tcp_hdr: *mut TcpHdr) -> u16 {
//     let mut sum = 0u32;

//     let src_ptr = unsafe { &(*ip_hdr).src_addr } as *const u32 as *const u16;
//     sum += unsafe { *src_ptr } as u32;
//     sum += unsafe { *src_ptr.add(1) } as u32;

//     let dst_ptr = unsafe { &(*ip_hdr).dst_addr } as *const u32 as *const u16;
//     sum += unsafe { *dst_ptr } as u32;
//     sum += unsafe { *dst_ptr.add(1) } as u32;

//     sum += u16::to_be(6) as u32; // Proto TCP
//     sum += u16::to_be(20) as u32; // TCP Len (immer 20 da wir kürzen)

//     let tcp_ptr = tcp_hdr as *const u16;
//     for i in 0..10 {
//         sum += unsafe { *tcp_ptr.add(i) } as u32;
//     }

//     while (sum >> 16) != 0 {
//         sum = (sum & 0xFFFF) + (sum >> 16);
//     }
//     !sum as u16
// }
