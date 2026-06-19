"""
OneMoney IDS/IPS — background polling service (SQLite-based).

Every POLL_INTERVAL seconds:
  1. Query SQLite for new CICFlowMeter log entries
  2. Normalise features with the saved StandardScaler
  3. Run the 1D-CNN; classify as ATTACK if sigmoid >= THRESHOLD (0.40)
  4. Write alerts to SQLite (alerts table)
  5. Block attacker IPs via iptables and persist blocks to SQLite (blocked_ips table)

Run directly:
  python -m inference.service

Or via docker-compose (requires privileged + host-network mode for iptables).
"""

import os
import time
import json
import sqlite3
import logging
import subprocess
import numpy as np
import joblib
import tensorflow as tf
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/service.log"),
    ],
)
log = logging.getLogger(__name__)

DB_PATH       = os.getenv("DB_PATH",        "/data/ids.db")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))
BATCH_SIZE    = int(os.getenv("BATCH_SIZE",    "500"))
THRESHOLD     = float(os.getenv("THRESHOLD",   "0.40"))

MODEL_PATH    = os.getenv("MODEL_PATH",  "model/onemoney_cnn.h5")
SCALER_PATH   = os.getenv("SCALER_PATH", "model/scaler.pkl")

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

def severity(attack_prob: float) -> str:
    if attack_prob >= 0.95:
        return "CRITICAL"
    if attack_prob >= 0.80:
        return "HIGH"
    if attack_prob >= 0.60:
        return "MEDIUM"
    return "LOW"

def load_assets():
    log.info(f"Loading model from {MODEL_PATH} ...")
    model = tf.keras.models.load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    log.info(f"Model and scaler loaded. Threshold = {THRESHOLD}")
    return model, scaler

def init_sqlite():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        source_host TEXT,
        label TEXT,
        data TEXT
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_host TEXT,
        source_ip TEXT,
        prediction TEXT,
        severity TEXT,
        attack_prob REAL,
        blocked INTEGER,
        indexed_at TEXT,
        raw_log TEXT,
        attack_type TEXT DEFAULT 'UNKNOWN'
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS blocked_ips (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        blocked_at TEXT,
        active INTEGER
    )""")

    c.execute("""CREATE TABLE IF NOT EXISTS whitelist (
        ip TEXT PRIMARY KEY,
        reason TEXT,
        added_at TEXT,
        active INTEGER DEFAULT 1
    )""")

    conn.commit()
    conn.close()
    log.info(f"SQLite initialized: {DB_PATH}")
    return DB_PATH

_blocked_cache: set = set()
_whitelist_cache: set = set()

def load_whitelist():
    """Load whitelisted IPs from database into memory cache"""
    global _whitelist_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip FROM whitelist WHERE active = 1")
        _whitelist_cache = {row[0] for row in c.fetchall()}
        conn.close()
        if _whitelist_cache:
            log.info(f"Loaded {len(_whitelist_cache)} whitelisted IPs")
    except Exception as exc:
        log.warning(f"Could not load whitelist: {exc}")
        _whitelist_cache = set()

def is_whitelisted(ip: str) -> bool:
    """Check if IP is in whitelist"""
    return ip in _whitelist_cache if ip else False

def _run_iptables(args: list) -> bool:
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            log.warning(f"iptables {' '.join(args)}: {result.stderr.strip()}")
            return False
        return True
    except FileNotFoundError:
        log.warning("iptables not found — IP blocking unavailable in this environment.")
        return False
    except Exception as exc:
        log.error(f"iptables error: {exc}")
        return False

def block_ip(ip: str, reason: str = "CNN detection") -> bool:
    if ip in _blocked_cache or ip in ("unknown", "", "0.0.0.0"):
        return False

    # Don't block whitelisted IPs
    if is_whitelisted(ip):
        log.debug(f"Skipping block for whitelisted IP: {ip}")
        return False

    ok_in  = _run_iptables(["-I", "INPUT",  "-s", ip, "-j", "DROP"])
    ok_out = _run_iptables(["-I", "OUTPUT", "-d", ip, "-j", "DROP"])

    now = datetime.now(timezone.utc).isoformat()
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, active) VALUES (?, ?, ?, ?)",
            (ip, reason, now, 1)
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.error(f"SQLite block record error for {ip}: {exc}")

    if ok_in or ok_out:
        _blocked_cache.add(ip)
        log.warning(f"BLOCKED IP: {ip}  reason={reason}")
    else:
        log.warning(f"DB-recorded block for {ip} (iptables unavailable).")

    return True

def restore_persisted_blocks():
    count = 0
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip FROM blocked_ips WHERE active = 1")
        for (ip,) in c.fetchall():
            if ip and ip not in _blocked_cache:
                _run_iptables(["-I", "INPUT",  "-s", ip, "-j", "DROP"])
                _run_iptables(["-I", "OUTPUT", "-d", ip, "-j", "DROP"])
                _blocked_cache.add(ip)
                count += 1
        conn.close()
    except Exception as exc:
        log.error(f"SQLite restore error: {exc}")
    if count:
        log.info(f"Restored {count} persisted IP blocks from SQLite.")

def fetch_new_logs(last_id) -> list:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if last_id is None:
            c.execute("SELECT * FROM logs ORDER BY id ASC LIMIT ?", (BATCH_SIZE,))
        else:
            c.execute("SELECT * FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?", (last_id, BATCH_SIZE))
        rows = c.fetchall()
        logs = [dict(row) for row in rows]
        conn.close()
        log.info(f"Fetched {len(logs)} log entries")
        return logs
    except Exception as exc:
        log.error(f"SQLite fetch error: {exc}")
        return []

def extract_features(logs: list, scaler) -> tuple:
    rows, valid = [], []
    for log_doc in logs:
        try:
            data = json.loads(log_doc.get("data", "{}")) if isinstance(log_doc.get("data"), str) else log_doc.get("data", {})
            row = [float(data.get(col, 0.0)) for col in FEATURES]
            rows.append(row)
            valid.append(log_doc)
        except (ValueError, TypeError, json.JSONDecodeError):
            continue

    if not rows:
        return None, []

    X = np.array(rows, dtype=np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X)
    X_cnn = X_scaled.reshape(X_scaled.shape[0], X_scaled.shape[1], 1)
    return X_cnn, valid

def classify(model, X_cnn: np.ndarray) -> tuple:
    proba = model.predict(X_cnn, verbose=0)
    if proba.shape[1] == 1:
        attack_probs = proba[:, 0]
    else:
        attack_probs = proba[:, 1]
    preds = (attack_probs >= THRESHOLD).astype(int)
    return preds, attack_probs

def build_alerts(logs: list, preds: np.ndarray, attack_probs: np.ndarray) -> list:
    now = datetime.now(timezone.utc).isoformat()
    alerts = []
    for log_doc, pred, prob in zip(logs, preds, attack_probs):
        source_ip = log_doc.get("source_ip", "unknown")

        # Override: whitelist internal IPs as BENIGN
        if is_whitelisted(source_ip):
            label = "BENIGN"
            sev = "NONE"
            pred_prob = 0.0
        else:
            label = "ATTACK" if pred == 1 else "BENIGN"
            sev = severity(float(prob)) if pred == 1 else "NONE"
            pred_prob = round(float(prob), 4)

        alerts.append({
            "timestamp":   log_doc.get("timestamp", now),
            "source_host": log_doc.get("source_host", "unknown"),
            "source_ip":   source_ip,
            "prediction":  label,
            "severity":    sev,
            "attack_prob": pred_prob,
            "blocked":     0,
            "indexed_at":  now,
            "raw_log":     json.dumps(log_doc),
            "attack_type": "UNKNOWN",
        })
    return alerts

def push_to_sqlite(alerts: list):
    if not alerts:
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        for alert in alerts:
            c.execute(
                """INSERT INTO alerts
                   (timestamp, source_host, source_ip, prediction, severity, attack_prob, blocked, indexed_at, raw_log, attack_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert["timestamp"], alert["source_host"], alert["source_ip"],
                 alert["prediction"], alert["severity"], alert["attack_prob"],
                 alert["blocked"], alert["indexed_at"], alert["raw_log"], alert.get("attack_type", "UNKNOWN"))
            )
        conn.commit()
        conn.close()
        log.info(f"SQLite inserted {len(alerts)} alerts.")
    except Exception as exc:
        log.error(f"SQLite insert error: {exc}")

def run():
    init_sqlite()
    load_whitelist()
    model, scaler = load_assets()
    restore_persisted_blocks()

    last_id = None
    total_attacks = 0

    log.info(f"Inference service started. Poll every {POLL_INTERVAL}s, threshold={THRESHOLD}")

    while True:
        try:
            logs = fetch_new_logs(last_id)

            if logs:
                last_id = logs[-1]["id"]

                X_cnn, valid_logs = extract_features(logs, scaler)
                if X_cnn is not None:
                    preds, attack_probs = classify(model, X_cnn)

                    n_attack = int(preds.sum())
                    n_benign = len(preds) - n_attack
                    total_attacks += n_attack

                    log.info(
                        f"Classified {len(preds)} | ATTACK={n_attack} "
                        f"BENIGN={n_benign} | cumulative attacks={total_attacks}"
                    )

                    all_alerts = build_alerts(valid_logs, preds, attack_probs)
                    attack_alerts = [a for a in all_alerts if a["prediction"] == "ATTACK"]

                    for alert in attack_alerts:
                        ip = alert["source_ip"]
                        was_new = block_ip(ip, reason="CNN inference")
                        if was_new:
                            alert["blocked"] = 1

                    push_to_sqlite(attack_alerts)

        except Exception as exc:
            log.error(f"Inference loop error: {exc}", exc_info=True)

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
