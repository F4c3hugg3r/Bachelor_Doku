#!/usr/bin/env python3
import os
import sys
import json
import csv
import glob
import pandas as pd

def count_masscan_file(filepath):
    """Liest Masscan Output (JSON oder List-Format -oL)"""
    count = 0
    try:
        # Versuch 1: Als JSON lesen (falls es eine .json Datei ist oder json content hat)
        if filepath.endswith('.json'):
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        return len(data)
            except:
                pass # Fallback zu Line-Counting

        # Versuch 2: Zeilenweise (für -oL Output oder dirty JSON)
        # Masscan -oL Format: "open tcp 80 1.2.3.4 1234567890"
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Prüfung auf Masscan Liste: "open" <proto> <port> <ip> ...
                if line.startswith("open "):
                    count += 1
                # Prüfung auf JSON fragment (falls dirty json)
                elif "ip" in line and "ports" in line:
                    count += 1
        return count
    except Exception as e:
        print(f"Fehler bei Masscan Datei {filepath}: {e}")
        return -1

def count_zmap_csv(filepath):
    """Zählt Zeilen in ZMap Output (CSV)."""
    try:
        with open(filepath, 'r') as f:
            # Anforderung: "einfach nur die Zeilen" zählen.
            # Wir zählen nicht-leere Zeilen, unabhängig von Header/Spalten.
            return sum(1 for line in f if line.strip())
    except Exception as e:
        print(f"Fehler bei ZMap Datei {filepath}: {e}")
        return -1

def count_rust_txt(filepath):
    """Zählt Zeilen in SYN-Rust Output (typisch CSV 'ip,port')."""
    try:
        # Anforderung: "einfach nur die Zeilen" zählen.
        # Wir zählen nicht-leere Zeilen, unabhängig von CSV-Parsing.
        with open(filepath, 'r') as f:
            return sum(1 for line in f if line.strip())
    except Exception as e:
        print(f"Fehler bei Rust Datei {filepath}: {e}")
        return -1

def analyze_directory(root_dir):
    results = []
    
    # Rekursiv alle Unterordner durchsuchen
    # Struktur: root/ScannerName/run_X/
    
    # 1. Suche nach Masscan (results.json ODER output_results.txt)
    # Masscan kann .json oder .txt sein. WICHTIG: Auch den Typo "outpput_results.txt" beachten.
    masscan_files = glob.glob(os.path.join(root_dir, "**", "results.json"), recursive=True) + \
                    glob.glob(os.path.join(root_dir, "**", "*output_results.txt"), recursive=True) + \
                    glob.glob(os.path.join(root_dir, "**", "*outpput_results.txt"), recursive=True)
    
    # Deduplizieren falls overlap
    masscan_files = list(set(masscan_files))

    for filepath in masscan_files:
        # Debug Output auch für Masscan
        if "Masscan" in filepath or "outpput" in filepath:
             print(f"DEBUG: Gefunden Masscan File {filepath}")

        if "Masscan" not in filepath: # Safety check falls andere tool txt nutzen
             # Wenn der Ordnername "Masscan" enthält, ist es wahrscheinlich Masscan
             path_parts = filepath.split(os.sep)
             if "Masscan" not in path_parts[-3]:
                 continue

        path_parts = filepath.split(os.sep)
        scanner = path_parts[-3] 
        run = path_parts[-2]
        filename = os.path.basename(filepath)
        
        count = count_masscan_file(filepath)
        results.append({'Scanner': scanner, 'Run': run, 'File': filename, 'Hits': count})

    # 2. Suche nach ZMap (output_results.csv)
    for filepath in glob.glob(os.path.join(root_dir, "**", "output_results.csv"), recursive=True):
        path_parts = filepath.split(os.sep)
        scanner = path_parts[-3]
        run = path_parts[-2]
        
        count = count_zmap_csv(filepath)
        results.append({'Scanner': scanner, 'Run': run, 'File': 'output_results.csv', 'Hits': count})

    # 3. Suche nach SYN-Rust (scan_output.csv)
    for filepath in glob.glob(os.path.join(root_dir, "**", "scan_output.csv"), recursive=True):
        print(f"DEBUG: Gefunden {filepath}") # DEBUG PRINT
        path_parts = filepath.split(os.sep)
        scanner = path_parts[-3]
        run = path_parts[-2]
        
        count = count_rust_txt(filepath)  # CSV logic reuse
        results.append({'Scanner': scanner, 'Run': run, 'File': 'scan_output.csv', 'Hits': count})

    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_responses.py pfad/zu/messdaten/TIMESTAMP_Benchmark_Suite")
        sys.exit(1)
        
    root_dir = sys.argv[1]
    if not os.path.exists(root_dir):
        print(f"Fehler: Verzeichnis '{root_dir}' nicht gefunden.")
        sys.exit(1)

    print(f"Validiere Ergebnisse in: {root_dir} ...")
    data = analyze_directory(root_dir)
    
    if not data:
        print("Keine Ergebnis-Dateien (results.json, output_results.csv, scan_output.txt) gefunden!")
        sys.exit(0)

    # DataFrame erstellen für schöne Ausgabe
    df = pd.DataFrame(data)
    
    # Sortieren
    df = df.sort_values(by=['Scanner', 'Run'])
    
    # Berechnung der Durchschnittlichen Hits pro Scanner
    avg_hits = df.groupby('Scanner')['Hits'].mean().reset_index()
    avg_hits.rename(columns={'Hits': 'Ø Hits'}, inplace=True)

    print("\n--- Detaillierte Validierung pro Run ---")
    print(df.to_string(index=False))
    
    print("\n--- Zusammenfassung (Durchschnittliche Treffer) ---")
    print(avg_hits.to_string(index=False))
    
    # CSV Export der Validierung
    outfile = os.path.join(root_dir, 'validierung_hits.csv')
    df.to_csv(outfile, index=False, sep=';')
    print(f"\nValidierungs-Tabelle gespeichert in: {outfile}")

if __name__ == "__main__":
    main()
