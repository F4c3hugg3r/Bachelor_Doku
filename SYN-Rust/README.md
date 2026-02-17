# SYN-Rust

-> high-performance, asynchronous SYN-Portscanner written purely in Rust

## Prerequisites

**Kernel Version:**
The XDP functionality requires a Linux kernel version of **5.8 or higher**.

## Setup & Dependencies

To install all necessary dependencies (BCC, aya, rust-toolchains, build-essentials) on a Debian-based system (Ubuntu/Debian/Kali), simply run the provided setup script in the root directory:

```bash
cd SYN-Rust
chmod +x setup_dependencies.sh
./setup_dependencies.sh
```

If you use the setup script and the program was used before in an older version, make sure to delete the old build:

```bash
cargo clean
```

*Note for Non-Debian Users:*
If you are using Fedora or Arch, please refer to the content of the script and install the corresponding packages (specifically `libelf`, `libbpf`, `kernel-headers` and `libpcap`) manually.

## Configuration

All relevant configurations (interface, target IPs, timeout, XDP mode, batch size, etc.) must be edited directly in the source code of the launcher program: **`bin/mock_program.rs`**

## Building & Running Standalone

1. **Configure the scanner** in `bin/mock_program.rs`.
2. **Build the release binaries:**
   ```bash
   cargo build --release
   cargo build --release --bin mock_program
   ```
3. **Run the program with root privileges:**
   ```bash
   sudo ./target/release/mock_program
   ```