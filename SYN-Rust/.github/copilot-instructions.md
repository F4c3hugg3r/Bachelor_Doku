# SYN-Rust: AI Coding Assistant Instructions

## Project Overview
High-performance asynchronous SYN port scanner written in Rust using XDP (eXpress Data Path) for kernel-level packet processing. The scanner combines userspace Rust with eBPF programs for maximum throughput.

## Architecture

### Three-Workspace Structure
- **`scanner/`** - Main userspace application (async tokio-based)
- **`xdp-ebpf/`** - eBPF program compiled to BPF bytecode (no_std, runs in kernel)
- **`xdp-common/`** - Shared types between userspace and eBPF (must be `no_std`)

### Critical Build Process
The `scanner/build.rs` compiles `xdp-ebpf` separately using `aya-build` with nightly Rust and `bpf-linker`. The resulting BPF bytecode is embedded into the scanner binary at compile time via `aya::include_bytes_aligned!`. **Never modify build.rs without understanding this compilation chain.**

### Data Flow Pipeline
1. **Parser** (`parser_std_in.rs`) → reads IPs from stdin/file (dual-mode: text or binary format)
2. **Assembler** (`assembler.rs`) → builds TCP SYN packets with templates
3. **Rate Limiter** (`rate_limiter.rs`) → enforces scan rate (Mbit/s)
4. **Sender** (`sender.rs`) → transmits via AF_XDP sockets (supports zero-copy) or raw sockets
5. **XDP Program** (`xdp-ebpf/src/main.rs`) → filters SYN-ACK responses in kernel
6. **Receiver** (`receiver.rs`) → captures responses via eBPF RingBuf or pcap (supports deduplication buffering)
7. **Bucket** (`bucket.rs`) → deduplicates responses using timed hash buckets (controlled by `deduplicate` config)

All components communicate via tokio mpsc channels. The `ScanJob` orchestrates spawning and coordination.

### Parser Input Formats
**Text Mode** (human-readable, ~55K IPs/s):
```
192.168.1.1
10.0.0.1
...
```

**Binary Mode** (production, ~2.8M IPs/s - 51× faster):
- IPv4: 4 bytes per address (raw octets)
- IPv6: 16 bytes per address
- Terminator: `[0,0,0,0]` signals end of stream
- Use `--bytes-file-path` or pipe binary data to stdin

**Key Parser Optimizations:**
- 8KB sliding window buffer prevents fragmented IP loss
- Batch accumulation (2048 IPs) with `std::mem::replace` for zero-copy moves
- Pre-allocated Vec capacity avoids growth reallocations

## Critical Conventions

### XDP vs Non-XDP Modes
- **XDP enabled** (`--xdp` flag): Uses AF_XDP sockets + eBPF filtering. Requires kernel >=5.8, privileged access, and proper cleanup.
- **XDP disabled**: Falls back to raw sockets + pcap. Slower but more portable.

**XDP Cleanup Protocol**: Always detach XDP programs gracefully. Improper shutdown (e.g., `kill -9`) requires manual recovery:
```bash
sudo ip link set dev <interface> xdp off
# If still broken: sudo rmmod <nic_driver> && sudo modprobe <nic_driver>
```

### Configuration Pattern
All scan parameters flow through `GivenConfig` (JSON-serialized) → `EmissionConfig` + `CaptureConfig` structs. See `types_and_config.rs` for the canonical split. The `mock_program.rs` binary demonstrates hardcoded config for testing without parsing JSON.

**Config Flow in Normal Mode:**
1. First line from stdin: JSON config (see `GivenConfig` in `types_and_config.rs` for fields like `ScanRate`, `ZeroCopy`, `Deduplicate`) + templates
2. Parser extracts dst_mac/src_mac from first 12 bytes of templates[0]
3. Subsequent stdin: Binary or text IP addresses
4. Terminator `[0,0,0,0]` signals end of IP stream

### Threading Model
- **Tokio async tasks**: Parsers, coordinators, channel orchestration
- **Blocking native threads**: XDP socket I/O (see `sender.rs` thread::spawn for AF_XDP)
- **Core pinning**: Use `core_affinity` to pin sender threads to specific CPUs for performance (see rate_limiter.rs)

### Hash-Based Port Encoding
The scanner encodes source ports using SipHash24 with shared keys between userspace and eBPF:
- Keys generated in `main.rs` and written to eBPF maps (`SIPHASH_KEY`)
- Assembler computes hash of dst_ip to derive src_port
- XDP program validates responses by recomputing hash (see `calculate_src_port_cookie` in xdp-ebpf)
This prevents state tracking by encoding scan metadata in packets themselves.

## Development Workflows

### Building
```bash
# Full release build (builds eBPF + scanner)
cargo build --release

# Mock program for testing (hardcoded config)
cargo build --release --bin mock_program

# eBPF changes require scanner rebuild (build.rs dependency)
```

### Running
**Always use sudo** for raw sockets/XDP. Example:
```bash
# Normal mode (reads JSON config + IPs from stdin)
sudo ./target/release/scanner --xdp --interface enp6s0 --nq 4

# Test mode (mock_program with hardcoded targets)
sudo ./target/release/mock_program
```

**Never exit with `kill -9`** when XDP is enabled. Use Ctrl+C (SIGINT) for proper cleanup via ctrlc handler.

### Key Flags
- `--interface/-iface`: NIC name (required for XDP)
- `--xdp`: Enable XDP mode (default: true)
- `--num-nic-queues/-nq`: Number of NIC queues to use (check with `ethtool -l <iface>`)
- `--parsing-timeout-millis/--timeout`: How long to capture after sending (default: 5000ms, **never use 0**)
- `--send-in-batches/--batch`: Batch packet transmission (recommended for XDP)
- `--string-file-path/--sfp`: Text file with newline-separated IPs
- `--bytes-file-path/--bfp`: Binary file with raw IP bytes (4 or 16 bytes per address)

### eBPF Map Access Pattern
Userspace: `aya::maps::HashMap`, `aya::maps::Array`, `aya::maps::RingBuf`
eBPF: `aya_ebpf::maps::HashMap`, `aya_ebpf::maps::Array`, etc.

Always check `MODE` map value (0=IPv4, 1=IPv6) to branch logic correctly in eBPF.

### Channel Enums
Use `SenderChan` and `ReceiverChan` enums (in `types_and_config.rs`) to handle batched vs. non-batched channels polymorphically. See assembler.rs for match patterns.

## Error Handling
Custom `ScannerErrWithMsg` wraps `ScanErr` enum with context strings. Use `?` operator and provide descriptive messages:
```rust
Err(ScannerErrWithMsg {
    err: ScanErr::Assembling,
    msg: format!("Failed to complement template: {}", e),
})
```

## Dependencies to Know
- **aya/aya-ebpf**: eBPF framework (forked from main repo in workspace deps)
- **xdp-socket**: AF_XDP bindings (custom fork: `F4c3hugg3r/xdp-rs`)
- **pnet**: Template creation (Ethernet/IP/TCP headers)
- **etherparse**: packet parsing library
- **pcap**: legacy packet capture
- **tokio**: Async runtime with full features enabled
- **jemalloc**: Custom allocator (`tikv-jemallocator`)

## Testing Strategy
Use `mock_program.rs` with hardcoded configs to test without complex input parsing. Configure test parameters at the top of `main()` (scan rate, target IPs, ports, etc.). Output writes to stderr by default—redirect with `2>output.txt` or `2>/dev/null`.

### mock_program Architecture
`mock_program.rs` is a **test harness** that:
1. Generates templates with `pnet` (pre-builds Ethernet/IP/TCP headers with MACs from first template)
2. Spawns scanner as child process via `sudo` with piped stdin/stdout
3. Streams IPs in binary format at ~2.1M IPs/s
4. Captures scan results to `scan_output.txt` asynchronously

**IP Generation Modes** (via `IpSource` enum):
- `RepeatIpv4 { ip, count }`: Pre-fills 64KB buffer once, reuses for all writes (45× faster than naive)
- `RangeIpv4(network)`: Streaming iterator over CIDR blocks (O(1) memory, handles `/8` ranges)
- `ListIpv4(vec)`: Explicit IP list

**Template Generation Strategy:**
- Cartesian product: Source IPs × Source Ports = Templates
- Single-port scans: dst_port embedded in template (30% faster assembly)
- Multi-port scans: dst_port=0 placeholder, assembler fills per-packet

**Performance Characteristics:**
- 64KB adaptive buffers (matches Linux pipe size)
- Single flush at end (60× fewer syscalls vs. per-write flush)
- Async stdout handler prevents pipe blocking deadlocks

## Formatters
Use `cargo fmt` which applies `rustfmt.toml` settings (imports are grouped by Std/External/Crate with granularity=Crate).

## When Modifying eBPF Code
- Remember `#![no_std]` - no standard library, no allocations, no panics
- Test helpers must be `#[inline(always)]` to ensure eBPF verifier acceptance
- Use `info!` from `aya_log_ebpf` sparingly (performance impact)
- Update `STATS` map counters for debugging (0: RX_TOTAL, 1: RX_PASSED, 2: RX_VALID[cookies], 3: TX_RST)
- **Available Maps**:
  - `STATS`: PerCpuArray (Counters)
  - `WHITELIST_IPV4/6`: HashMap (Filter targets)
  - `EVENTS`: RingBuf (Packet transfer to userspace)
  - `MODE`: Array (0=IPv4, 1=IPv6)
  - `RESET`: Array (0=No RST, 1=Send RST)
  - `SIPHASH_KEY`: Array (Keys for cookie generation)
  - `DEBUG`: Array (0=Off, 1=Enable logs)
- Changes require full rebuild: `cargo build --release` (triggers build.rs)
