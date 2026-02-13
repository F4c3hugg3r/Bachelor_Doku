#!/bin/bash

# Das Skript beenden, wenn ein Befehl fehlschlägt (Fehlererkennung)
set -e

echo "[*] Aktualisiere Paketlisten..."
sudo apt-get update

# Variable für die aktuelle Kernel-Version setzen
KERNEL_VERSION=$(uname -r)

echo "[*] Installiere System-Abhängigkeiten (apt)..."
# Zusammenfassung aller apt-Pakete aus Ihren Anforderungen:
# - xdp-socket: libelf-dev, libbpf-dev, gcc-multilib, linux-headers
# - aya: linux-tools, linux-tools-common, linux-tools-generic
# - jemalloc: build-essential
sudo apt-get install -y \
    build-essential \
    libelf-dev \
    libbpf-dev \
    gcc-multilib \
    linux-headers-${KERNEL_VERSION} \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-${KERNEL_VERSION}

echo "[*] System-Abhängigkeiten installiert."

# Prüfen, ob rustup installiert ist
if ! command -v rustup &> /dev/null; then
    echo "[!] Fehler: 'rustup' wurde nicht gefunden."
    echo "    Bitte installieren Sie Rust zuerst: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "[*] Richte Rust Toolchains ein..."

# Stable Toolchain installieren
echo "    -> Installing stable..."
rustup toolchain install stable

# Nightly Toolchain mit rust-src Komponente installieren (für BPF/Aya oft notwendig)
echo "    -> Installing nightly + rust-src..."
rustup toolchain install nightly --component rust-src

# bpf-linker installieren
echo "[*] Installiere bpf-linker (via Cargo)..."
if ! command -v bpf-linker &> /dev/null; then
    cargo install bpf-linker
else
    echo "    -> bpf-linker ist bereits installiert. Aktualisiere..."
    cargo install bpf-linker --force
fi

echo "------------------------------------------------"
echo "[OK] Alle Abhängigkeiten erfolgreich installiert."
echo "------------------------------------------------"