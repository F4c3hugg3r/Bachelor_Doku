#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys
import os
import glob

# --- KONFIGURATION -----------------------------------------------------------
PPS_THRESHOLD = 100         # Ab wann gilt der Scanner als "aktiv"?
PPS_Y_LIMIT = 16_000_00    # Fixe Skala für Plots (1e6)
XTICK_LABEL_FONTSIZE = 8   # Schriftgröße der Namen unten (X-Achse)
# -----------------------------------------------------------------------------

def plot_run_details(df, output_file, title_suffix):
    """
    Erstellt Detail-Plots für einen einzelnen Run (Zeigt vollen Zeitraum).
    """
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12), sharex=True)
    
    # A) Paketrate
    # Optimierung für lange Runs (> 30s)
    line_width = 1.0
    alpha_val = 1.0
    max_time = df['Time_s'].max()
    
    if max_time > 30:
        line_width = 0.5
        alpha_val = 0.8
        # Optional: Downsampling für extrem lange Runs (> 2 Min)
        if max_time > 120 and len(df) > 1000:
            df_plot = df.iloc[::2] # Jeden 2. Punkt nehmen
        else:
            df_plot = df
    else:
        df_plot = df

    ax1.plot(df_plot['Time_s'], df_plot['TX_PPS'], color='blue', label='TX PPS', linewidth=line_width, alpha=alpha_val)
    if 'RX_PPS' in df_plot.columns:
        ax1.plot(df_plot['Time_s'], df_plot['RX_PPS'], color='green', label='RX PPS', linewidth=line_width, alpha=alpha_val)
    
    ax1.set_ylabel('PPS')
    ax1.set_title(f'Netzwerk-Durchsatz ({title_suffix})')
    ax1.set_ylim(0, PPS_Y_LIMIT)
    ax1.grid(True, linestyle='--', alpha=0.7)
    ax1.legend(loc='upper right')

    # B) CPU
    ax2.stackplot(df['Time_s'], 
                  df['CPU_User_%'], df['CPU_System_%'], df['CPU_SoftIRQ_%'],
                  labels=['User', 'System', 'SoftIRQ (XDP)'],
                  colors=['#2ca02c', '#7f7f7f', '#d62728'], alpha=0.8)
    ax2.set_ylabel('CPU (%)')
    ax2.set_title('CPU Nutzungsprofil (Absolut)')
    ax2.grid(True, linestyle='--', alpha=0.7)
    ax2.legend(loc='upper right')

    # C) RAM
    ax3.plot(df['Time_s'], df['RAM_Used_MB'], color='purple', label='RAM (System Total)', linewidth=1.5)
    ax3.set_ylabel('MB')
    ax3.set_xlabel('Laufzeit (s)')
    ax3.set_title('Speicherverbrauch (Absolut)')
    ax3.grid(True, linestyle='--', alpha=0.7)
    ax3.legend(loc='upper right')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150)
    plt.close()


def parse_ethtool_stats(filename):
    """Parses ethtool stats file. Returns dict of key-value pairs."""
    stats = {}
    if not os.path.exists(filename):
        return stats
    
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 2:
                key = parts[0].strip()
                try:
                    val = int(parts[1].strip())
                    stats[key] = val
                except ValueError:
                    pass
    return stats

def load_run_data(run_folder, scanner_name, run_name):
    """
    Lädt Daten und berechnet ZWEI Sets an Statistiken:
    1. Sliced (nur aktive Phase) - bereinigt
    2. Full (gesamte Laufzeit) - bereinigt
    """
    baseline_file = os.path.join(run_folder, "baseline.csv")
    metrics_file = os.path.join(run_folder, "metrics.csv")
    ethtool_start_file = os.path.join(run_folder, "ethtool_start.txt")
    ethtool_end_file = os.path.join(run_folder, "ethtool_end.txt")

    if not (os.path.exists(baseline_file) and os.path.exists(metrics_file)):
        return None, None, None

    # 1. Baseline laden
    df_base = pd.read_csv(baseline_file, sep=';')
    base_stats = {
        'cpu_usr': df_base['CPU_User_%'].mean(),
        'cpu_sys': df_base['CPU_System_%'].mean(),
        'cpu_soft': df_base['CPU_SoftIRQ_%'].mean(),
        'ram_mb': df_base['RAM_Used_MB'].mean()
    }
    base_stats['cpu_total'] = base_stats['cpu_usr'] + base_stats['cpu_sys'] + base_stats['cpu_soft']

    # 2. Metrics laden (FULL DATA)
    df_main = pd.read_csv(metrics_file, sep=';')

    # FIX: Negative PPS filtern (passiert bei Counter-Resets/Overflows)
    if 'TX_PPS' in df_main.columns:
        df_main['TX_PPS'] = df_main['TX_PPS'].clip(lower=0)
    if 'RX_PPS' in df_main.columns:
        df_main['RX_PPS'] = df_main['RX_PPS'].clip(lower=0)
    
    # Detail-Plot erstellen
    plot_filename = os.path.join(run_folder, "detail_plot_timeseries.png")
    plot_run_details(df_main, plot_filename, f"{scanner_name} - {run_name}")

    # --- Ethtool Analysis ---
    eth_start = parse_ethtool_stats(ethtool_start_file)
    eth_end = parse_ethtool_stats(ethtool_end_file)
    
    # Wir suchen nach Standard-Keys oder typischen Driver-Keys
    # Für MelanoX/Intel gibt es oft rx_packets / tx_packets
    tx_hardware = 0
    rx_hardware = 0
    
    if eth_start and eth_end:
        # Hier muss man ggf. je nach NIC anpassen. Wir summieren "packets" keys.
        # Fallback: tx_packets, rx_packets (Standard)
        if 'tx_packets' in eth_end:
            val_end = eth_end['tx_packets']
            val_start = eth_start.get('tx_packets', 0)
            if val_end < val_start: # Reset detected
                tx_hardware = val_end
            else:
                tx_hardware = val_end - val_start
        
        if 'rx_packets' in eth_end:
            val_end = eth_end['rx_packets']
            val_start = eth_start.get('rx_packets', 0)
            if val_end < val_start: # Reset detected
                rx_hardware = val_end
            else:
                rx_hardware = val_end - val_start
            
    # Calculate measured totals from CSV (Approximate: Mean PPS * Duration)
    # Genauere Integration: Sum(PPS) * Interval. CSV hat variable delta-t, aber wir mitteln.
    # df_main['TX_PPS'] contains rates. df_main['Time_s'] tells us total time.
    # Da wir sampling haben, ist Sum(PPS) * Interval eine Näherung.
    # Besser: Anzahl Samples * Mean PPS * SamplingInterval (wobei SamplingInterval ~ 0.1s ist aber schwankt)
    # Wir nehmen an: (LastTime - FirstTime) * MeanPPS
    duration = df_main['Time_s'].max() - df_main['Time_s'].min() if len(df_main) > 1 else 0
    
    # Integration über Trapezregel oder Rechtecksumme
    # Einfache Summe: Sum(PPS * 0.1) -> da Interval fix ist 0.1 in benchmark_suite.
    # Aber benchmark_suite schreibt tatsächliche Zeitabstände. 
    # Wir können einfach die Differenz der Pakete auslesen wenn wir sie hätten. Haben aber nur PPS.
    # Also: Integral(PPS dt)
    # df_main['dt'] = df_main['Time_s'].diff().fillna(0.1) # approx
    # total_tx_software = (df_main['TX_PPS'] * df_main['dt']).sum()
    # Da CSV nicht dt speichert, müssen wir es berechnen (Time_s ist kumulativ?) 
    # Ja, Time_s ist rel_time.
    time_steps = df_main['Time_s'].diff().fillna(0.1) # erstes Element 0.1 annehmen
    total_tx_measured = (df_main['TX_PPS'] * time_steps).sum()
    
    total_rx_measured = 0
    if 'RX_PPS' in df_main.columns:
        total_rx_measured = (df_main['RX_PPS'] * time_steps).sum()

    ethtool_stats_result = {
        'tx_hw': tx_hardware,
        'rx_hw': rx_hardware,
        'tx_sw': total_tx_measured,
        'rx_sw': total_rx_measured,
        'tx_diff_percent': ((total_tx_measured - tx_hardware) / tx_hardware * 100) if tx_hardware > 0 else 0,
        'rx_diff_percent': ((total_rx_measured - rx_hardware) / rx_hardware * 100) if rx_hardware > 0 else 0
    }

    # --- A) FULL STATS (Gesamte Laufzeit, Netto) ---
    # Wir nehmen den Durchschnitt über alles (inkl. Start/Stop Rampen) und ziehen Baseline ab
    full_stats = {
        'pps': df_main['TX_PPS'].mean(),
        'cpu_usr_net': max(0, df_main['CPU_User_%'].mean() - base_stats['cpu_usr']),
        'cpu_sys_net': max(0, df_main['CPU_System_%'].mean() - base_stats['cpu_sys']),
        'cpu_soft_net': max(0, df_main['CPU_SoftIRQ_%'].mean() - base_stats['cpu_soft']),
        'ram_net': max(0, df_main['RAM_Used_MB'].mean() - base_stats['ram_mb']),
        'baseline_cpu_total': base_stats['cpu_total'], # Für Plotting merken
        'baseline_ram': base_stats['ram_mb'],           # Für Plotting merken
        'ethtool': ethtool_stats_result
    }
    full_stats['cpu_total_net'] = full_stats['cpu_usr_net'] + full_stats['cpu_sys_net'] + full_stats['cpu_soft_net']

    # --- B) SLICED STATS (Nur aktive Phase, Netto) ---
    active_indices = df_main.index[df_main['TX_PPS'] > PPS_THRESHOLD].tolist()
    
    if active_indices:
        first_idx = active_indices[0]
        last_idx = active_indices[-1]
        df_active = df_main.iloc[first_idx : last_idx + 1].copy()
        
        sliced_stats = {
            'pps': df_active['TX_PPS'].mean(),
            'cpu_usr_net': max(0, df_active['CPU_User_%'].mean() - base_stats['cpu_usr']),
            'cpu_sys_net': max(0, df_active['CPU_System_%'].mean() - base_stats['cpu_sys']),
            'cpu_soft_net': max(0, df_active['CPU_SoftIRQ_%'].mean() - base_stats['cpu_soft']),
            'ram_net': max(0, df_active['RAM_Used_MB'].mean() - base_stats['ram_mb']),
            'eff_sliced': 0,
            'ethtool': ethtool_stats_result # Copy also to sliced for easy access
        }
        sliced_stats['cpu_total_net'] = sliced_stats['cpu_usr_net'] + sliced_stats['cpu_sys_net'] + sliced_stats['cpu_soft_net']
        
        if sliced_stats['cpu_total_net'] > 0.1:
            sliced_stats['eff_sliced'] = sliced_stats['pps'] / sliced_stats['cpu_total_net']
    else:
        # Fallback falls keine Pakete flossen
        sliced_stats = full_stats.copy()
        sliced_stats['eff_sliced'] = 0

    # --- C) TIMESERIES (Für Plots) ---
    df_ts_out = df_main.copy()
    df_ts_out['Time_Relative'] = df_ts_out['Time_s'] - df_ts_out['Time_s'].iloc[0]
    
    # Netto-Werte (noch ungesmoothed)
    df_ts_out['CPU_Total_Net'] = (df_ts_out['CPU_User_%'] + df_ts_out['CPU_System_%'] + df_ts_out['CPU_SoftIRQ_%']) - base_stats['cpu_total']
    df_ts_out['RAM_Net'] = df_ts_out['RAM_Used_MB'] - base_stats['ram_mb']
    
    # 1. Glättung (Smoothing) - Gleitender Durchschnitt
    # Window-Size: ca. 2 Sekunden (bei 0.1s Interval -> 20 Samples)
    # Adaptiv: Wenn Zeitspanne über 60s, dann stärkere Glättung (5s -> 50 Samples)
    max_duration = df_ts_out['Time_Relative'].max()
    if max_duration > 60:
        SMOOTH_WINDOW = 40
    else:
        SMOOTH_WINDOW = 20
    
    cols_to_smooth = ['TX_PPS', 'CPU_Total_Net', 'RAM_Net']
    if 'RX_PPS' in df_ts_out.columns:
        cols_to_smooth.append('RX_PPS')
        
    for col in cols_to_smooth:
        df_ts_out[col] = df_ts_out[col].rolling(window=SMOOTH_WINDOW, min_periods=1, center=True).mean()

    # 2. Clipping (NACH Smoothing, um negative Artefakte zu vermeiden)
    # CPU Netto kann durch Baseline-Subtraktion (und Rauschen) negativ werden -> Abschneiden bei 0
    df_ts_out['CPU_Total_Net'] = df_ts_out['CPU_Total_Net'].clip(lower=0)
    
    # RAM Netto ebenfalls bei 0 abschneiden
    df_ts_out['RAM_Net'] = df_ts_out['RAM_Net'].clip(lower=0)

    # Clean unused columns for return
    ret_cols = ['Time_Relative', 'TX_PPS', 'CPU_Total_Net', 'RAM_Net']
    if 'RX_PPS' in df_ts_out.columns:
        ret_cols.append('RX_PPS')

    return sliced_stats, full_stats, df_ts_out[ret_cols]

def analyze_scenarios(root_dir):
    subdirs = [d for d in glob.glob(os.path.join(root_dir, "*")) if os.path.isdir(d)]
    subdirs.sort()

    results_sliced = []
    results_full = []
    results_timeseries = []

    for scenario_path in subdirs:
        scenario_name = os.path.basename(scenario_path)
        print(f"Analysiere Scanner: {scenario_name} ...")
        
        runs_sliced = []
        runs_full = []
        runs_dfs = []
        
        run_dirs = glob.glob(os.path.join(scenario_path, "run_*"))
        run_dirs.sort() 
        
        for run_path in run_dirs:
            run_name = os.path.basename(run_path)
            stats_sl, stats_fl, df_ts = load_run_data(run_path, scenario_name, run_name)
            if stats_sl:
                runs_sliced.append(stats_sl)
                runs_full.append(stats_fl)
                runs_dfs.append(df_ts)
        
        if not runs_sliced:
            continue

        # Aggregation Sliced
        df_sl = pd.DataFrame(runs_sliced)
        summ_sl = df_sl.mean(numeric_only=True).to_dict()
        summ_sl['std_pps'] = df_sl['pps'].std() if len(df_sl) > 1 else 0.0
        summ_sl['std_ram'] = df_sl['ram_net'].std() if len(df_sl) > 1 else 0.0
        summ_sl['scanner'] = scenario_name
        results_sliced.append(summ_sl)

        # Aggregation Full (für Tabelle & Baseline Info)
        df_fl = pd.DataFrame(runs_full)
        summ_fl = df_fl.mean(numeric_only=True).to_dict()
        summ_fl['scanner'] = scenario_name
        # Wir speichern hier auch die Baseline für den Plot
        summ_fl['baseline_cpu_total'] = df_fl['baseline_cpu_total'].mean()
        summ_fl['baseline_ram'] = df_fl['baseline_ram'].mean()
        
        # Ethtool Stats aggregieren (Achtung: ethtool ist dict in col, muss entpackt werden)
        if 'ethtool' in df_fl.columns and not df_fl['ethtool'].isnull().all():
            ethtool_series = df_fl['ethtool'].apply(pd.Series)
            ethtool_mean = ethtool_series.mean()
            # In summ_fl mergen
            for k, v in ethtool_mean.items():
                summ_fl[f'eth_{k}'] = v
        else:
             # Defaults
            for k in ['tx_hw', 'rx_hw', 'tx_sw', 'rx_sw', 'tx_diff_percent', 'rx_diff_percent']:
                summ_fl[f'eth_{k}'] = 0
            
        results_full.append(summ_fl)

        # Aggregation Timeseries
        if runs_dfs:
            combined_df = pd.concat(runs_dfs)
            combined_df['Time_Rounded'] = combined_df['Time_Relative'].round(1)
            avg_ts = combined_df.groupby('Time_Rounded').mean().reset_index()
            results_timeseries.append({'scanner': scenario_name, 'data': avg_ts})

    # Sortierung nach Scanner-Name für konsistente Grafiken
    df_res_sliced = pd.DataFrame(results_sliced)
    if not df_res_sliced.empty:
        df_res_sliced = df_res_sliced.sort_values('scanner')

    df_res_full = pd.DataFrame(results_full)
    if not df_res_full.empty:
        df_res_full = df_res_full.sort_values('scanner')
        
    results_timeseries.sort(key=lambda x: x['scanner'])

    return df_res_sliced, df_res_full, results_timeseries

def plot_bar_comparisons(df_sliced, df_full, output_dir):
    """
    Erstellt Balkendiagramme.
    - Sliced Daten für die Balken (Netto).
    - Full Daten für Baseline-Integration (Stacked Bar).
    """
    if df_sliced.empty: return
    
    # helper to sort and update labels
    def get_sorted(df, col, ascending=False):
        df_srt = df.sort_values(col, ascending=ascending)
        return df_srt, df_srt['scanner'], np.arange(len(df_srt))

    # 1. PPS Bar (Sortiert nach PPS absteigend)
    df_plot, scanners, x_pos = get_sorted(df_sliced, 'pps', ascending=False)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(x_pos, df_plot['pps'], yerr=df_plot['std_pps'], align='center', alpha=0.9, capsize=10, color='#1f77b4')
    ax.set_xticks(x_pos)
    ax.set_xticklabels(scanners, rotation=10, ha='right', fontsize=XTICK_LABEL_FONTSIZE)
    ax.set_ylabel('Ø Paketrate (PPS) bei aktivem Senden')
    ax.set_title('Vergleich: Sendeleistung (aktiv)')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    for i, v in enumerate(df_plot['pps']):
        ax.text(i, v, f"{v:,.0f}", ha='center', va='bottom', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_balken_1_pps.png'), dpi=300)
    plt.close()
    
    # 2. CPU Stacked Bar (Netto, aktiv) - Sortiert nach CPU Total absteigend
    df_plot, scanners, x_pos = get_sorted(df_sliced, 'cpu_total_net', ascending=False)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    width = 0.6
    
    p_usr = ax.bar(x_pos, df_plot['cpu_usr_net'], width, label='User Space (Netto)', color='#2ca02c')
    
    bot_sys = df_plot['cpu_usr_net']
    p_sys = ax.bar(x_pos, df_plot['cpu_sys_net'], width, bottom=bot_sys, label='Kernel Space (Netto)', color='#7f7f7f')
    
    bot_soft = bot_sys + df_plot['cpu_sys_net']
    p_soft = ax.bar(x_pos, df_plot['cpu_soft_net'], width, bottom=bot_soft, label='SoftIRQ (Netto)', color='#d62728')

    ax.set_xticks(x_pos)
    ax.set_xticklabels(scanners, rotation=10, ha='right', fontsize=XTICK_LABEL_FONTSIZE)
    ax.set_ylabel('CPU Auslastung (%)')
    ax.set_title('CPU Gesamtlast (Netto, aktiv)')
    ax.legend(loc='upper left', bbox_to_anchor=(1, 1))
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_balken_2_cpu_total_aktiv.png'), dpi=300)
    plt.close()

    # 2b. CPU Stacked Bar (Netto, gesamt) - NEU - Sortiert nach CPU Total absteigend
    if not df_full.empty:
        df_plot_full, scanners_full, x_pos_full = get_sorted(df_full, 'cpu_total_net', ascending=False)
        
        fig, ax = plt.subplots(figsize=(10, 6))
        
        p_usr = ax.bar(x_pos_full, df_plot_full['cpu_usr_net'], width, label='User Space (Netto)', color='#2ca02c')
        
        bot_sys = df_plot_full['cpu_usr_net']
        p_sys = ax.bar(x_pos_full, df_plot_full['cpu_sys_net'], width, bottom=bot_sys, label='Kernel Space (Netto)', color='#7f7f7f')
        
        bot_soft = bot_sys + df_plot_full['cpu_sys_net']
        p_soft = ax.bar(x_pos_full, df_plot_full['cpu_soft_net'], width, bottom=bot_soft, label='SoftIRQ (Netto)', color='#d62728')

        ax.set_xticks(x_pos_full)
        ax.set_xticklabels(scanners_full, rotation=10, ha='right', fontsize=XTICK_LABEL_FONTSIZE)
        ax.set_ylabel('CPU Auslastung (%)')
        ax.set_title('CPU Gesamtlast (Netto, gesamt)')
        ax.legend(loc='upper left', bbox_to_anchor=(1, 1))
        ax.grid(axis='y', linestyle='--', alpha=0.5)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'vergleich_balken_2b_cpu_total_gesamt.png'), dpi=300)
        plt.close()

    # 3. RAM Bar (Netto + Baseline als Text) - Sortiert nach RAM Netto absteigend
    df_plot, scanners, x_pos = get_sorted(df_sliced, 'ram_net', ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Asymmetrische Error-Bars berechnen
    ram_vals = df_plot['ram_net'].values
    ram_stds = df_plot['std_ram'].values
    
    lower_errs = np.minimum(ram_vals, ram_stds) # Darf nicht größer als der Wert selbst sein
    upper_errs = ram_stds
    
    asymmetric_err = [lower_errs, upper_errs]
    
    bars = ax.bar(x_pos, df_plot['ram_net'], yerr=asymmetric_err, align='center', alpha=0.9, capsize=10, color='#9467bd')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(scanners, rotation=10, ha='right', fontsize=XTICK_LABEL_FONTSIZE)
    ax.set_ylabel('RAM Mehrverbrauch Netto (MB)')
    ax.set_title('Vergleich: Speichernutzung (Netto, aktiv)')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.set_ylim(bottom=0) # Erzwingt Start bei 0
    
    # Text-Labels für Netto-Wert
    for i, rect in enumerate(bars):
        height = rect.get_height()
        net_val = df_plot['ram_net'].iloc[i] # Achtung: iloc verwenden da sortiert
        
        # Netto über Balken
        ax.text(rect.get_x() + rect.get_width()/2., height,
                f'+{net_val:.1f} MB',
                ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_balken_3_ram.png'), dpi=300)
    plt.close()

    # 4. CPU Effizienz Bar (PPS per % CPU) - Sortiert nach Effizienz absteigend
    df_plot, scanners, x_pos = get_sorted(df_sliced, 'eff_sliced', ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.bar(x_pos, df_plot['eff_sliced'], align='center', alpha=0.9, capsize=10, color='darkblue')
    
    ax.set_xticks(x_pos)
    ax.set_xticklabels(scanners, rotation=10, ha='right', fontsize=XTICK_LABEL_FONTSIZE)
    ax.set_ylabel('Effizienz (PPS / 1% CPU)')
    ax.set_title('Vergleich: CPU Effizienz (aktiv)')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    
    for i, rect in enumerate(bars):
        height = rect.get_height()
        ax.text(rect.get_x() + rect.get_width()/2., height,
                f'{height:.0f}',
                ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_balken_4_effizienz.png'), dpi=300)
    plt.close()

def plot_time_series_comparison(ts_data_list, output_dir):
    if not ts_data_list: return
    # Erweiterte Farbpalette für viele Teilnehmer
    colors = [
        '#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', 
        '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf',
        '#000080', '#800000', '#008000', '#808000', '#008080'
    ]
    
    # 1. PPS
    plt.figure(figsize=(10, 6))
    for i, entry in enumerate(ts_data_list):
        # Time_Rounded gibt es nicht mehr explizit, wir nutzen Time_Relative
        time_col = 'Time_Relative' if 'Time_Relative' in entry['data'].columns else 'Time_s'
        plt.plot(entry['data'][time_col], entry['data']['TX_PPS'], label=entry['scanner'], color=colors[i % len(colors)], linewidth=2)
    plt.xlabel('Zeit (s)')
    plt.ylabel('Paketrate (PPS)')
    plt.title('Netzwerk-Durchsatz über Zeit (geglättet)')
    plt.ylim(0, PPS_Y_LIMIT)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_zeitreihe_1_pps.png'), dpi=300)
    plt.close()

    # 2. CPU Netto (Zeitreihe lassen wir Netto für Vergleichbarkeit)
    plt.figure(figsize=(10, 6))
    for i, entry in enumerate(ts_data_list):
        time_col = 'Time_Relative' if 'Time_Relative' in entry['data'].columns else 'Time_s'
        plt.plot(entry['data'][time_col], entry['data']['CPU_Total_Net'], label=entry['scanner'], color=colors[i % len(colors)], linewidth=2)
    plt.xlabel('Zeit (s)')
    plt.ylabel('CPU Auslastung Netto (%)')
    plt.title('CPU-Last über Zeit (Netto, geglättet)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_zeitreihe_2_cpu.png'), dpi=300)
    plt.close()

    # 3. RAM Netto
    plt.figure(figsize=(10, 6))
    for i, entry in enumerate(ts_data_list):
        time_col = 'Time_Relative' if 'Time_Relative' in entry['data'].columns else 'Time_s'
        plt.plot(entry['data'][time_col], entry['data']['RAM_Net'], label=entry['scanner'], color=colors[i % len(colors)], linewidth=2)
    plt.xlabel('Zeit (s)')
    plt.ylabel('RAM Mehrverbrauch (MB)')
    plt.title('Speichernutzung über Zeit (Netto, geglättet)')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'vergleich_zeitreihe_3_ram.png'), dpi=300)
    plt.close()

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 plot_benchmark_suite.py pfad/zu/messdaten")
        sys.exit(1)
    
    root_dir = sys.argv[1]
    if not os.path.exists(root_dir):
        print("Fehler: Pfad nicht gefunden.")
        sys.exit(1)

    print(f"Lese Daten aus: {root_dir}")
    df_sliced, df_full, ts_data = analyze_scenarios(root_dir)
    
    if df_sliced.empty:
        print("Keine Daten.")
        sys.exit(1)

    print("Erstelle Grafiken...")
    plot_bar_comparisons(df_sliced, df_full, root_dir)
    plot_time_series_comparison(ts_data, root_dir)
    
    print("Generiere kombinierte Tabelle...")
    
    # Wir mergen Sliced und Full Daten in eine Tabelle
    # Wichtig: Alle Werte sind bereits NETTO (Baseline bereinigt)
    
    # 1. Slice Daten vorbereiten
    export_slice = df_sliced[['scanner', 'pps', 'cpu_total_net', 'cpu_soft_net', 'ram_net', 'eff_sliced']].copy()
    export_slice.columns = ['Scanner', 'PPS (aktiv)', 'CPU Netto [%] (aktiv)', 'SoftIRQ [%] (aktiv)', 'RAM Netto [MB] (aktiv)', 'Effizienz [PPS/CPU(%)] (aktiv)']
    
    # 2. Full Daten vorbereiten (inklusive Ethtool Stats)
    export_full = df_full[['scanner', 'pps', 'cpu_total_net', 'cpu_soft_net', 'ram_net', 
                           'eth_tx_hw', 'eth_tx_sw', 'eth_tx_diff_percent', 
                           'eth_rx_hw', 'eth_rx_sw', 'eth_rx_diff_percent']].copy()
    export_full.columns = ['Scanner', 'PPS (gesamt)', 'CPU Netto [%] (gesamt)', 'SoftIRQ [%] (gesamt)', 'RAM Netto [MB] (gesamt)',
                           'Eth Txs (HW)', 'Eth Txs (SW)', 'Diff TX [%]', 'Eth Rxs (HW)', 'Eth Rxs (SW)', 'Diff RX [%]']
    
    # Merge on Scanner name
    final_df = pd.merge(export_slice, export_full, on='Scanner')
    
    # Sortieren nach PPS (aktiv) absteigend für die Tabelle
    final_df = final_df.sort_values('Effizienz [PPS/CPU(%)] (aktiv)', ascending=False)
    
    # --- ETH TOOL Tabelle auslagern ---
    eth_cols = ['Scanner', 
                'Eth Txs (HW)', 'Eth Txs (SW)', 'Diff TX [%]', 
                'Eth Rxs (HW)', 'Eth Rxs (SW)', 'Diff RX [%]']
    
    ethtool_df = final_df[eth_cols].copy()
    ethtool_csv_out = os.path.join(root_dir, 'ethtool_ergebnisse.csv')
    ethtool_df.to_csv(ethtool_csv_out, index=False, sep=';', float_format='%.2f')
    print(f"Ethtool Ergebnisse gespeichert in: {ethtool_csv_out}")

    # --- Haupt-Tabelle ---
    # Spalten sortieren für Lesbarkeit (ohne Ethtool Detail Werte)
    cols = ['Scanner',  
            'Effizienz [PPS/CPU(%)] (aktiv)',
            'PPS (aktiv)',
            'CPU Netto [%] (aktiv)', 'RAM Netto [MB] (aktiv)',
            'CPU Netto [%] (gesamt)', 'RAM Netto [MB] (gesamt)'
            ]
    
    main_df = final_df[cols].copy()
    
    csv_out = os.path.join(root_dir, 'zusammenfassung_ergebnisse_final.csv')
    main_df.to_csv(csv_out, index=False, sep=';', float_format='%.2f')
    
    print("\n--- Summary ---")
    print(main_df.to_string(index=False))
    print("\n--- Ethtool Stats ---")
    print(ethtool_df.to_string(index=False))
    
    print(f"\nFertig. Ergebnisse in {root_dir}")

if __name__ == "__main__":
    main()
