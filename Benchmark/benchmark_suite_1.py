#!/usr/bin/env python3
import time
import subprocess
import sys
import os
import datetime
import shlex
import threading

# --- KONFIGURATION -----------------------------------------------------------
INTERFACE = "enp6s0"         # Ihr Netzwerk-Interface
INTERVAL = 0.1               # Messfrequenz (Sekunden)

# Benchmark-Parameter
ROUNDS = 5                   # Wiederholungen pro Szenario
BASELINE_SEC = 5             # Dauer der Grundlast-Messung (Baseline)
PRE_RECORD_SEC = 1           # Wie lange vor dem Start schon messen? (für Plot-Sichtbarkeit)
POST_RECORD_SEC = 1          # Wie lange nach dem Ende weiter messen?

IDLE_THRESHOLD_PPS = 100     # Unter 100 pps gilt als "fertig"
IDLE_TIMEOUT_SEC = 5.0       # Wie lange muss Ruhe sein, bis wir killen?

SCENARIOS = [
{
         "name": "SYN-Rust (XDP, Generic)",
         "cmd": "/home/lennard/Bachelor/SYN-Rust/target/release/mock_program_g_3"
     },
    {
        "name": "SYN-Rust (XDP, Copy)",
        "cmd": "/home/lennard/Bachelor/SYN-Rust/target/release/mock_program_c_3"
    },
     {
        "name": "SYN-Rust (XDP, Zero-Copy)",
        "cmd": "/home/lennard/Bachelor/SYN-Rust/target/release/mock_program_zc_3"
    },
     {
        "name": "SYN-Rust (AF_PACKET)",
        "cmd": "/home/lennard/Bachelor/SYN-Rust/target/release/mock_program_afp_3"
    }
]
# -----------------------------------------------------------------------------

def get_timestamp_str():
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

def save_ethtool_stats(iface, filename):
    try:
        with open(filename, "w") as outfile:
            subprocess.run(["ethtool", "-S", iface], stdout=outfile, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("WARNUNG: 'ethtool' nicht gefunden.")

def read_proc_stat():
    with open('/proc/stat', 'r') as f:
        for line in f:
            if line.startswith('cpu '):
                parts = line.split()
                user = int(parts[1])
                system = int(parts[3])
                softirq = int(parts[7])
                total = sum(int(x) for x in parts[1:])
                return user, system, softirq, total
    return 0, 0, 0, 0

def read_net_dev(iface):
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if iface in line:
                    data = line.split(':')[1].split()
                    rx_pkts = int(data[1])
                    tx_pkts = int(data[9])
                    return rx_pkts, tx_pkts
    except:
        return 0, 0
    return 0, 0

def read_mem_info():
    mem = {}
    with open('/proc/meminfo', 'r') as f:
        for line in f:
            parts = line.split(':')
            if len(parts) == 2:
                mem[parts[0].strip()] = int(parts[1].split()[0])
    return mem['MemTotal'] - mem['MemFree'] - mem.get('Buffers', 0) - mem.get('Cached', 0)

def measure_worker(csv_file, stop_event, shared_state):
    """
    Läuft in einem separaten Thread und schreibt CSV.
    Aktualisiert shared_state['pps'] für den Watchdog im Main-Thread.
    """
    last_user, last_sys, last_soft, last_total = read_proc_stat()
    last_rx, last_tx = read_net_dev(INTERFACE)
    last_time = time.time()
    start_time_global = time.time()

    with open(csv_file, 'w') as f:
        f.write("Time_s;CPU_User_%;CPU_System_%;CPU_SoftIRQ_%;RAM_Used_MB;TX_PPS;RX_PPS\n")
        
        while not stop_event.is_set():
            time.sleep(INTERVAL)
            
            curr_user, curr_sys, curr_soft, curr_total = read_proc_stat()
            curr_rx, curr_tx = read_net_dev(INTERFACE)
            curr_mem = read_mem_info()
            curr_time = time.time()

            time_delta = curr_time - last_time
            total_delta = curr_total - last_total
            
            if total_delta > 0 and time_delta > 0:
                cpu_user = (curr_user - last_user) / total_delta * 100
                cpu_sys  = (curr_sys - last_sys)   / total_delta * 100
                cpu_soft = (curr_soft - last_soft) / total_delta * 100
                tx_pps = (curr_tx - last_tx) / time_delta
                rx_pps = (curr_rx - last_rx) / time_delta
                ram_mb = curr_mem / 1024
                rel_time = curr_time - start_time_global

                f.write(f"{rel_time:.2f};{cpu_user:.2f};{cpu_sys:.2f};{cpu_soft:.2f};{ram_mb:.2f};{tx_pps:.0f};{rx_pps:.0f}\n")
                f.flush()

                # Daten für Watchdog bereitstellen
                shared_state['pps'] = tx_pps

                last_user, last_sys, last_soft, last_total = curr_user, curr_sys, curr_soft, curr_total
                last_rx, last_tx = curr_rx, curr_tx
                last_time = curr_time

def run_measurement_cycle(run_dir, cmd_str=None, duration=None):
    """
    Steuert den Messablauf:
    1. Startet Mess-Thread
    2. Wartet PRE_RECORD_SEC
    3. Startet Prozess (falls cmd_str) ODER wartet duration (Baseline)
    4. Wartet auf Prozess-Ende (Watchdog)
    5. Wartet POST_RECORD_SEC
    6. Stoppt Mess-Thread
    """
    metrics_csv = f"{run_dir}/metrics.csv" if cmd_str else f"{run_dir}/baseline.csv"
    
    stop_event = threading.Event()
    shared_state = {'pps': 0}
    
    # 1. Messung starten
    t = threading.Thread(target=measure_worker, args=(metrics_csv, stop_event, shared_state))
    t.start()
    
    # 2. Baseline Modus (Kein Prozess)
    if cmd_str is None:
        print(".", end="", flush=True)
        time.sleep(duration)
        stop_event.set()
        t.join()
        return

    # 3. Scanner Modus
    print(" [Pre-Record]", end="", flush=True)
    time.sleep(PRE_RECORD_SEC)
    
    # Ethtool Start
    save_ethtool_stats(INTERFACE, f"{run_dir}/ethtool_start.txt")
    
    # Prozess starten
    proc = subprocess.Popen(shlex.split(cmd_str), cwd=run_dir)
    print(f" [Start PID {proc.pid}]", end="", flush=True)
    
    # Watchdog Loop
    has_started_sending = False
    idle_counter = 0
    
    try:
        while proc.poll() is None:
            time.sleep(INTERVAL)
            current_pps = shared_state['pps']
            print(".", end="", flush=True)
            
            # Watchdog Logik
            if current_pps > 500:
                has_started_sending = True
                idle_counter = 0
            
            if has_started_sending and current_pps < IDLE_THRESHOLD_PPS:
                idle_counter += 1
                if (idle_counter * INTERVAL) >= IDLE_TIMEOUT_SEC:
                    print(f" [Auto-Stop: Idle]", end="", flush=True)
                    proc.terminate()
                    break
    except KeyboardInterrupt:
        proc.kill()
        stop_event.set()
        t.join()
        raise

    # Ethtool Ende
    save_ethtool_stats(INTERFACE, f"{run_dir}/ethtool_end.txt")
    
    # 4. Nachlaufzeit
    print(" [Post-Record]", end="", flush=True)
    time.sleep(POST_RECORD_SEC)
    
    stop_event.set()
    t.join()

def main():
    root_run_id = get_timestamp_str() + "_Benchmark_Suite"
    root_log_dir = f"./messdaten/{root_run_id}"
    os.makedirs(root_log_dir, exist_ok=True)
    
    print(f"=== Benchmark Suite Gestartet ===")
    print(f"Output: {root_log_dir}")
    print(f"Interface: {INTERFACE}")
    print("=================================\n")

    try:
        for scenario in SCENARIOS:
            scen_name = scenario["name"]
            cmd = scenario["cmd"]
            print(f"\n>>> Szenario: {scen_name}")
            
            for i in range(1, ROUNDS + 1):
                run_dir = f"{root_log_dir}/{scen_name}/run_{i}"
                os.makedirs(run_dir, exist_ok=True)
                
                print(f"\n   Run {i}/{ROUNDS}: ", end="")
                
                # Baseline
                print("Baseline...", end="", flush=True)
                run_measurement_cycle(run_dir, cmd_str=None, duration=BASELINE_SEC)
                
                # Scanner Test
                print(" Active Test...", end="", flush=True)
                run_measurement_cycle(run_dir, cmd_str=cmd)
                print(" Done.")
                
                time.sleep(1) # Kurze Atempause zwischen Runs

    except KeyboardInterrupt:
        print("\nAbbruch durch Nutzer.")
        sys.exit(1)

    print(f"\nFertig. Daten in: {root_log_dir}")

if __name__ == "__main__":
    main()
