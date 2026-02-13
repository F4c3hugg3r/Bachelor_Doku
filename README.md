# SYN-Rust

## Voraussetzungen

**Kernel-Version:**
Die XDP-Funktionalität erfordert eine Linux-Kernel-Version von **5.8 oder höher**.

## Einrichtung & Abhängigkeiten

Um alle notwendigen Abhängigkeiten (BCC, aya, rust-toolchains, build-essentials) auf einem Debian-basierten System (Ubuntu/Debian/Kali) zu installieren, führen Sie einfach das bereitgestellte Setup-Skript im Stammverzeichnis aus:

```bash
cd SYN-Rust
chmod +x setup_dependencies.sh
./setup_dependencies.sh
```

*Hinweis für Nicht-Debian-Benutzer:*
Wenn Sie Fedora oder Arch verwenden, beziehen Sie sich bitte auf den Inhalt des Skripts und installieren Sie die entsprechenden Pakete (insbesondere `libelf`, `libbpf`, `kernel-headers` und `libpcap`) manuell.

## Konfiguration

Alle relevanten Konfigurationen (Schnittstelle, Ziel-IPs, Timeout, XDP-Modus, Batch-Größe usw.) müssen direkt im Quellcode des 
Startprogramms bearbeitet werden: **`bin/mock_program.rs`**

## Erstellen & Ausführen

1. **Konfigurieren Sie den Scanner** in `bin/mock_program.rs`.
2. **Erstellen Sie die Release-Binärdateien:**
   ```bash
   cargo build --release
   cargo build --release --bin mock_program
   ```
3. **Führen Sie das Programm mit Root-Rechten aus:**
   ```bash
   sudo ./target/release/mock_program
   ```


# Benchmark 

## Messdaten

Die Messdaten sind nach Test beschriftet in **Benchmark/messdaten** zu finden. Dort sind für die Evaluationsszenarien_1 und -2 alle Diagramme und Auswertungsdateien zu finden. Die Ausgaben der Scanner konnten leider nicht mit aufgenommen werden, da sie teils mehrere Hundert Megabyte groß sind und GitHub dies nicht erlaubt. Der Ordner **xdpdump** ist dabei stellvertretend für die Ergebnisse von Evaluationstest_2. Um diese auszuwerten, kann mit folgendem Command Wireshark installiert werden:

```bash
sudo apt-get install wireshark
```

## Replizierbarkeit

Der Ablauf aller Tests, sowie die dafür benötigte Skripte und Programme sind in diesem Projekt zu finden. Für den genauen Ablauf sind die Eingaben und Ausgaben im Terminal in **Benchmark/messdaten/logs_benchmark_suite.txt** für den Scanner-Knoten und in **Benchmark/messdaten/logs_dummy_receiver.txt** für den Ziel-Knoten zu finden und können entsprechend repliziert werden. Die dafür genutzten Binaries sind in **Benchmark/Binaries** zu finden.

Der Aufbau der Hardware ist bereits in der Bachelorarbeit beschrieben.