#!/usr/bin/env python3
import os
import sys
import json
import glob
import socket
import struct
import ipaddress
import pandas as pd
import argparse
import time

# --- KONFIGURATION ---
TARGET_CIDR = '10.0.0.0/20'  # Standard, kann via CLI überschrieben werden
# ---------------------

def get_network_config(cidr):
    """Berechnet Netzwerk-Integer, Maske und max. Hosts."""
    net = ipaddress.ip_network(cidr, strict=False)
    net_int = int(net.network_address)
    mask_int = int(net.netmask)
    total_hosts = net.num_addresses
    return net_int, mask_int, total_hosts

def ip_to_int(ip_str):
    """Wandelt IP-String in Integer um."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except (socket.error, OSError, TypeError):
        return None

def get_ips_from_file(filepath):
    """
    Generator, der IPs aus verschiedenen Dateiformaten extrahiert.
    Unterstützt: JSON (Masscan), CSV (ZMap/Rust), List (Masscan -oL)
    """
    # 1. JSON Handling (Masscan)
    if filepath.endswith('.json'):
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    for entry in data:
                        # Masscan JSON Struktur: [{'ip': '...', 'ports': [...]}, ...]
                        if 'ip' in entry:
                            yield entry['ip']
            return
        except Exception as e:
            # Fallback falls kein valides JSON, versuche Text-Parsing
            pass

    # 2. Text/CSV Zeilenweise Handling
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Masscan -oL Format: "open tcp 80 10.0.0.5 ..."
            if line.startswith("open ") and len(line.split()) >= 4:
                yield line.split()[3]
            
            # ZMap / Rust CSV Format: "10.0.0.5" oder "10.0.0.5,80,..."
            elif ',' in line:
                yield line.split(',')[0]
            
            # Einfache Liste
            else:
                yield line.split()[0]

def process_file(filepath, net_config):
    """
    Analysiert eine einzelne Datei auf Validität, Parität und Coverage.
    """
    net_int, mask_int, total_possible_hosts = net_config
    
    unique_hits = set()
    stats = {
        'Total Lines': 0,
        'Malformed': 0,
        'Outside Range': 0,
        'Even IPs (Correct)': 0,
        'Odd IPs (False)': 0,
        'Duplicates': 0
    }

    # IPs extrahieren und prüfen
    for ip_str in get_ips_from_file(filepath):
        stats['Total Lines'] += 1
        
        ip_int = ip_to_int(ip_str)
        if ip_int is None:
            stats['Malformed'] += 1
            continue

        # 1. Range Check
        if (ip_int & mask_int) != net_int:
            stats['Outside Range'] += 1
            continue

        # 2. Duplicate Check (für Coverage)
        if ip_int in unique_hits:
            stats['Duplicates'] += 1
            # Wir zählen Duplikate nicht für Parität/Coverage
            continue
        
        unique_hits.add(ip_int)

        # 3. Parity Check (Gerade = Richtig, Ungerade = Falsch)
        if (ip_int & 1) == 0:
            stats['Even IPs (Correct)'] += 1
        else:
            stats['Odd IPs (False)'] += 1

    # Metriken berechnen
    unique_count = len(unique_hits)
    
    # Coverage: Wie viel % des Subnetzes gefunden?
    coverage = (unique_count / total_possible_hosts) * 100 if total_possible_hosts > 0 else 0
    
    # Accuracy: Wie viel % der gefundenen eindeutigen IPs waren "richtig" (gerade)?
    accuracy = (stats['Even IPs (Correct)'] / unique_count) * 100 if unique_count > 0 else 0

    return {
        'Unique IPs': unique_count,
        'Coverage %': round(coverage, 2),
        'Accuracy %': round(accuracy, 2),
        **stats
    }

def analyze_directory(root_dir, cidr):
    results = []
    print(f"Konfiguriere Netz: {cidr}")
    try:
        net_config = get_network_config(cidr)
        print(f"Hosts im Netz: {net_config[2]:,}")
    except ValueError as e:
        print(f"Fehlerhafte CIDR: {e}")
        sys.exit(1)

    # Patterns für verschiedene Scanner
    # Priorisierung: JSON vor TXT bei Masscan
    patterns = [
        "**/results.json",           # Masscan JSON
        "**/*output_results.txt",    # Masscan TXT
        "**/*outpput_results.txt",   # Masscan TXT (Typo)
        "**/output_results.csv",     # ZMap
        "**/scan_output.csv"         # Rust
    ]
    
    found_files = []
    for pattern in patterns:
        found_files.extend(glob.glob(os.path.join(root_dir, pattern), recursive=True))
    
    # Deduplizierung (falls Dateien mehrfach gematcht werden)
    found_files = sorted(list(set(found_files)))

    print(f"Gefundene Dateien: {len(found_files)}")

    for filepath in found_files:
        # Metadaten aus Pfad extrahieren (Scanner/Run)
        path_parts = filepath.split(os.sep)
        
        # Heuristik um Scanner/Run zu finden (Verzeichnisstruktur Annahme: root/Scanner/Run/File)
        # Wir suchen von hinten nach vorne
        try:
            if "scan_output.csv" in filepath:
                scanner = path_parts[-3]
                run = path_parts[-2]
            elif "Masscan" in filepath or "results" in filepath:
                # Versuche Scanner Name aus Pfad zu raten
                if "Masscan" in path_parts[-3]:
                    scanner = path_parts[-3]
                    run = path_parts[-2]
                elif "ZMap" in path_parts[-3]:
                    scanner = path_parts[-3]
                    run = path_parts[-2]
                else:
                    scanner = "Unknown"
                    run = "Unknown"
        except IndexError:
            scanner = "Unknown"
            run = "Unknown"

        print(f"Analysiere: {scanner} -> {run} ({os.path.basename(filepath)})")
        
        # Validierung durchführen
        file_stats = process_file(filepath, net_config)
        
        # Ergebnis zusammenbauen
        row = {
            'Scanner': scanner,
            'Run': run,
            'File': os.path.basename(filepath),
            **file_stats
        }
        results.append(row)

    return results

def main():
    parser = argparse.ArgumentParser(description='Batch-Validierung von Scanner-Ergebnissen.')
    parser.add_argument('directory', help='Pfad zum Messdaten-Verzeichnis')
    parser.add_argument('--cidr', default=TARGET_CIDR, help=f'Ziel CIDR (Default: {TARGET_CIDR})')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.directory):
        print(f"Fehler: Verzeichnis '{args.directory}' nicht gefunden.")
        sys.exit(1)

    data = analyze_directory(args.directory, args.cidr)
    
    if not data:
        print("Keine Dateien gefunden.")
        sys.exit(0)

    # DataFrame
    df = pd.DataFrame(data)
    
    # Spalten sortieren für bessere Lesbarkeit
    cols = ['Scanner', 'Run', 'Coverage %', 'Accuracy %', 'Unique IPs', 'Even IPs (Correct)', 'Odd IPs (False)', 'Total Lines', 'Duplicates', 'File']
    # Nur Spalten nutzen, die auch existieren (falls was schief ging)
    cols = [c for c in cols if c in df.columns]
    df = df[cols]
    
    # Sortieren
    df = df.sort_values(by=['Scanner', 'Run'])

    print("\n--- Validierungs-Ergebnisse ---")
    print(df.to_string(index=False))

    # CSV Export
    outfile = os.path.join(args.directory, 'validation_summary.csv')
    df.to_csv(outfile, index=False, sep=';')
    print(f"\nZusammenfassung gespeichert unter: {outfile}")

    # Aggregation (Durchschnitt pro Scanner)
    avg_df = df.groupby('Scanner')[['Coverage %', 'Accuracy %', 'Unique IPs']].mean().reset_index()
    print("\n--- Durchschnitt pro Scanner ---")
    print(avg_df.to_string(index=False))

if __name__ == "__main__":
    main()
