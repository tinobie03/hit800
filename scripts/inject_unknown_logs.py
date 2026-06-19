#!/usr/bin/env python3
"""
inject_unknown_logs.py
======================
Generates synthetic network flow logs with random/unknown attack patterns.
Directly injects them into SQLite to test IDS detection of novel attacks.

Usage:
  python3 inject_unknown_logs.py [num_logs] [db_path]

Example:
  python3 inject_unknown_logs.py 100 /data/ids.db
"""

import sys
import sqlite3
import random
import json
from datetime import datetime, timedelta, timezone
import numpy as np

# CICFlowMeter feature names (76 features)
FEATURES = [
    "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Len", "Bwd Header Len",
    "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt",
    "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt",
    "Down/Up Ratio", "Pkt Size Avg",
    "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg",
    "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
    "Init Fwd Win Byts", "Init Bwd Win Byts",
    "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

def generate_benign_flow():
    """Generate a normal/benign network flow."""
    flow = {}
    for feature in FEATURES:
        if "Flags" in feature or "Flag Cnt" in feature:
            flow[feature] = random.uniform(0, 5)
        elif "Duration" in feature:
            flow[feature] = random.uniform(100, 10000)
        elif "Pkts/s" in feature or "Byts/s" in feature:
            flow[feature] = random.uniform(0.1, 50)
        elif "Mean" in feature or "Avg" in feature:
            flow[feature] = random.uniform(100, 500)
        elif "Std" in feature:
            flow[feature] = random.uniform(10, 200)
        elif "Max" in feature:
            flow[feature] = random.uniform(500, 2000)
        elif "Min" in feature:
            flow[feature] = random.uniform(10, 100)
        else:
            flow[feature] = random.uniform(0, 1000)
    return flow

def generate_novel_attack_1():
    """Novel attack 1: Extreme variance in flow characteristics (unknown pattern)."""
    flow = generate_benign_flow()
    # Mix very high packet rates with very low variance
    flow["Flow Pkts/s"] = random.uniform(500, 2000)  # Extreme rate
    flow["Pkt Len Std"] = random.uniform(0.1, 5)     # Very low variance (suspicious)
    flow["SYN Flag Cnt"] = random.uniform(100, 500)  # Many SYN flags
    flow["ACK Flag Cnt"] = random.uniform(50, 200)   # Many ACK flags
    flow["FIN Flag Cnt"] = random.uniform(10, 50)    # FIN flags
    return flow

def generate_novel_attack_2():
    """Novel attack 2: Unusual flag combinations never seen in training."""
    flow = generate_benign_flow()
    # All flags set simultaneously (impossible in normal TCP)
    flow["FIN Flag Cnt"] = random.uniform(50, 150)
    flow["SYN Flag Cnt"] = random.uniform(50, 150)
    flow["RST Flag Cnt"] = random.uniform(50, 150)
    flow["PSH Flag Cnt"] = random.uniform(50, 150)
    flow["URG Flag Cnt"] = random.uniform(50, 150)
    flow["Fwd PSH Flags"] = random.uniform(50, 150)
    flow["Bwd PSH Flags"] = random.uniform(50, 150)
    return flow

def generate_novel_attack_3():
    """Novel attack 3: Asymmetric bidirectional patterns."""
    flow = generate_benign_flow()
    # Extreme asymmetry between forward and backward
    flow["Tot Fwd Pkts"] = random.uniform(10000, 50000)
    flow["Tot Bwd Pkts"] = random.uniform(1, 10)
    flow["TotLen Fwd Pkts"] = random.uniform(500000, 1000000)
    flow["TotLen Bwd Pkts"] = random.uniform(1, 100)
    flow["Fwd Byts/b Avg"] = random.uniform(1000, 5000)
    flow["Bwd Byts/b Avg"] = random.uniform(0.1, 5)
    return flow

def generate_novel_attack_4():
    """Novel attack 4: Timing anomaly - rapid packet bursts with gaps."""
    flow = generate_benign_flow()
    # Unusual timing patterns
    flow["Flow IAT Mean"] = random.uniform(0.001, 0.01)  # Very small inter-arrival times
    flow["Flow IAT Std"] = random.uniform(1000, 5000)    # Huge variance in timing
    flow["Fwd IAT Mean"] = random.uniform(0.001, 0.01)
    flow["Fwd IAT Std"] = random.uniform(1000, 5000)
    flow["Active Mean"] = random.uniform(0.001, 0.01)
    flow["Idle Mean"] = random.uniform(5000, 10000)
    return flow

def generate_novel_attack_5():
    """Novel attack 5: Protocol confusion - mixed attack characteristics."""
    flow = generate_benign_flow()
    # Characteristics that suggest multiple attacks happening
    flow["Flow Duration"] = random.uniform(0.1, 1)      # Very short flow
    flow["Flow Pkts/s"] = random.uniform(1000, 5000)    # High packet rate
    flow["Pkt Len Var"] = random.uniform(0.01, 0.1)     # Low variance
    flow["Down/Up Ratio"] = random.uniform(10, 100)     # Extreme asymmetry
    flow["Subflow Fwd Pkts"] = random.uniform(10000, 50000)
    flow["Init Fwd Win Byts"] = random.uniform(0, 100)
    return flow

def generate_unknown_log_entry(attack_type=None):
    """Generate a single log entry with unknown attack pattern."""
    now = datetime.now(timezone.utc)
    timestamp = (now - timedelta(seconds=random.randint(0, 60))).isoformat()

    if attack_type is None:
        attack_type = random.choice([1, 2, 3, 4, 5])

    if attack_type == 1:
        flow = generate_novel_attack_1()
        attack_name = "Novel Pattern 1: Extreme Variance"
    elif attack_type == 2:
        flow = generate_novel_attack_2()
        attack_name = "Novel Pattern 2: Impossible Flags"
    elif attack_type == 3:
        flow = generate_novel_attack_3()
        attack_name = "Novel Pattern 3: Asymmetric Flow"
    elif attack_type == 4:
        flow = generate_novel_attack_4()
        attack_name = "Novel Pattern 4: Timing Anomaly"
    elif attack_type == 5:
        flow = generate_novel_attack_5()
        attack_name = "Novel Pattern 5: Protocol Confusion"
    else:
        flow = generate_benign_flow()
        attack_name = "BENIGN"

    # Random source IPs from attacker VM
    source_ip = f"192.168.64.{random.randint(3, 50)}"

    log_entry = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_host": f"attacker-{source_ip.split('.')[-1]}",
        "attack_type": attack_name,
        **flow
    }

    return log_entry

def init_sqlite(db_path):
    """Initialize SQLite database with logs table if needed."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create logs table if it doesn't exist
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        source_host TEXT,
        label TEXT,
        data TEXT
    )""")

    conn.commit()
    conn.close()

def inject_logs_to_sqlite(db_path, num_logs=100, distribution=None):
    """Inject synthetic unknown attack logs into SQLite."""
    if distribution is None:
        # Default: 20% of each novel attack type
        distribution = [0, 1, 1, 1, 1, 1]  # 1 BENIGN per 5 unknown attacks

    init_sqlite(db_path)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    print(f"[*] Generating {num_logs} synthetic unknown attack logs...")

    inserted = 0
    for i in range(num_logs):
        # Pick attack type based on distribution
        attack_type = random.choice([1, 2, 3, 4, 5])

        log_entry = generate_unknown_log_entry(attack_type)

        # Convert flow dict to JSON string for storage
        data_json = json.dumps({k: v for k, v in log_entry.items() if k not in ["timestamp", "source_ip", "source_host"]})

        c.execute(
            "INSERT INTO logs (timestamp, source_ip, source_host, label, data) VALUES (?, ?, ?, ?, ?)",
            (
                log_entry["timestamp"],
                log_entry["source_ip"],
                log_entry["source_host"],
                log_entry["attack_type"],
                data_json
            )
        )

        inserted += 1
        if (i + 1) % 10 == 0:
            print(f"  [{i + 1}/{num_logs}] Inserted {log_entry['attack_type']}")

    conn.commit()
    conn.close()

    print(f"\n[✓] Successfully injected {inserted} unknown attack logs into {db_path}")
    print("[*] These logs will be picked up by the inference service on next poll cycle")
    print("[*] Monitor detection with: tail -f logs/service.log")

if __name__ == "__main__":
    num_logs = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    db_path = sys.argv[2] if len(sys.argv) > 2 else "/data/ids.db"

    print("╔════════════════════════════════════════════════════════════╗")
    print("║     Synthetic Unknown Attack Log Generator                 ║")
    print("║     Tests IDS detection of novel/zero-day patterns         ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    inject_logs_to_sqlite(db_path, num_logs)

    print()
    print("📊 Attack patterns generated:")
    print("   1. Extreme Variance — High rate + low variability")
    print("   2. Impossible Flags — All TCP flags set simultaneously")
    print("   3. Asymmetric Flow — Extreme upstream/downstream imbalance")
    print("   4. Timing Anomaly — Micro-bursts with macro-level gaps")
    print("   5. Protocol Confusion — Mixed attack characteristics")
