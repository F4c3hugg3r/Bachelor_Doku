#!/bin/bash

# Das Skript sofort beenden, wenn ein Befehl fehlschlägt
set -e

# --- KONFIGURATION ---
# Wir nutzen exakt die Version vom 08.12.2025 (Rust 1.94).
# Neuere Versionen (1.95+, Feb 2026) erzeugen fehlerhaften BTF-Code.
RUST_NIGHTLY_VERSION="nightly-2025-12-08"

echo "=================================================="
echo "[*] SYN-Rust Setup Script"
echo "=================================================="

echo "[*] 1. System-Updates..."
sudo apt-get update

KERNEL_VERSION=$(uname -r)

echo "[*] 2. Installiere System-Abhängigkeiten (apt)..."
sudo apt-get install -y \
    build-essential \
    libelf-dev \
    libbpf-dev \
    gcc-multilib \
    linux-headers-${KERNEL_VERSION} \
    linux-tools-common \
    linux-tools-generic \
    linux-tools-${KERNEL_VERSION} \
    libpcap-dev

echo "[*] System-Abhängigkeiten installiert."

# Prüfen, ob rustup installiert ist
if ! command -v rustup &> /dev/null; then
    echo "[!] Fehler: 'rustup' wurde nicht gefunden."
    echo "    Bitte installieren Sie Rust zuerst: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

echo "[*] 3. Bereinige Toolchains..."

# Entferne die allgemeine "nightly" (die oft auf die kaputte 1.95 zeigt),
# damit keine Verwechslungsgefahr besteht.
if rustup toolchain list | grep -q "^nightly-x86_64"; then
    echo "    -> Entferne allgemeine 'nightly' Toolchain (Vermeidung von Version 1.95+)..."
    rustup toolchain uninstall nightly
fi

echo "[*] 4. Richte spezifische Rust Toolchains ein..."

# Stable Toolchain (für normale Tools)
rustup toolchain install stable

# Unsere spezifische funktionierende Version installieren
echo "    -> Installiere $RUST_NIGHTLY_VERSION + rust-src..."
rustup toolchain install "$RUST_NIGHTLY_VERSION" --component rust-src

# --- PROJEKT SPEZIFISCHE SCHRITTE ---
# Wir prüfen, ob wir im Projekt sind. Das ist WICHTIG für den bpf-linker Build.
if [ -f "Cargo.toml" ]; then
    echo "------------------------------------------------"
    echo "[*] 5. Konfiguriere aktuelles Projekt..."
    
    # SCHRITT A: Override setzen
    # Das muss passieren, BEVOR wir bpf-linker installieren, damit der Linker
    # gegen die hier definierte Rust-Version gebaut wird.
    echo "    -> Setze Toolchain Override auf $RUST_NIGHTLY_VERSION..."
    rustup override set "$RUST_NIGHTLY_VERSION"

    # SCHRITT B: bpf-linker passend zur Toolchain bauen
    echo "    -> Installiere bpf-linker (Rebuild gegen Rust 1.94)..."
    # Wir deinstallieren ihn zuerst, um sicherzugehen, dass keine alten Artefakte bleiben
    if command -v bpf-linker &> /dev/null; then
        cargo uninstall bpf-linker 2>/dev/null || true
    fi
    # Installation erzwingen
    cargo install bpf-linker

    # SCHRITT C: Aufräumen & Bauen
    echo "    -> Führe 'cargo clean' aus (Verhindert ABI-Mismatch)..."
    cargo clean

    echo "    -> Baue Programm"
    cargo build --release
    cargo build --release --bin mock_program

    echo "------------------------------------------------"
    echo "[OK] Setup und Build erfolgreich!"
    echo "     Starten Sie das Programm mit: sudo ./target/release/mock_program"
else
    # Fallback, falls das Skript nicht im Projektordner liegt
    echo "------------------------------------------------"
    echo "[*] Installiere bpf-linker global (für $RUST_NIGHTLY_VERSION)..."
    # Wir nutzen explizit '+version', da kein Override aktiv ist
    cargo +$RUST_NIGHTLY_VERSION install bpf-linker --force
    
    echo "------------------------------------------------"
    echo "[OK] Umgebung installiert."
    echo "     HINWEIS: Sie befinden sich nicht in einem Rust-Projektordner."
    echo "     Bitte führen Sie im Projektordner einmalig aus:"
    echo "     rustup override set $RUST_NIGHTLY_VERSION"
fi