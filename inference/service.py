"""SQLite-backed CNN inference and host firewall enforcement service."""

import json
import ipaddress
import logging
import os
import time
from datetime import datetime, timezone

import joblib
import numpy as np
import tensorflow as tf
from ids_core.database import connect, init_schema
from ids_core.features import FEATURES
from ids_core.firewall import block_ip as apply_firewall_block, normalize_ip

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = lambda: None
load_dotenv()
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("logs/service.log")],
)
log = logging.getLogger(__name__)

DB_PATH = os.getenv("DB_PATH", "data/ids.db")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "10"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "500"))
THRESHOLD = float(os.getenv("THRESHOLD", "0.50"))
AUTO_BLOCK = os.getenv("AUTO_BLOCK", "false").lower() in {"1", "true", "yes"}
PROTECTED_NETWORKS = tuple(
    ipaddress.ip_network(value.strip())
    for value in os.getenv(
        "PROTECTED_NETWORKS",
        "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    ).split(",")
    if value.strip()
)
MODEL_PATH = os.getenv("MODEL_PATH", "model/onemoney_cnn.h5")
SCALER_PATH = os.getenv("SCALER_PATH", "model/scaler.pkl")

_blocked_cache: set[str] = set()
_whitelist_cache: set[str] = set()


def severity(probability: float) -> str:
    if probability >= 0.95:
        return "CRITICAL"
    if probability >= 0.80:
        return "HIGH"
    if probability >= 0.60:
        return "MEDIUM"
    return "LOW"


def load_assets():
    model = tf.keras.models.load_model(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    expected = len(FEATURES)
    if getattr(scaler, "n_features_in_", expected) != expected:
        raise RuntimeError("Scaler does not match the canonical 76-feature contract")
    if tuple(model.input_shape[1:]) != (expected, 1):
        raise RuntimeError(f"Model input {model.input_shape} does not match ({expected}, 1)")
    log.info("Model and scaler loaded; threshold=%s", THRESHOLD)
    return model, scaler


def load_runtime_lists() -> None:
    global _blocked_cache, _whitelist_cache
    with connect(DB_PATH) as conn:
        _whitelist_cache = {row[0] for row in conn.execute(
            "SELECT ip FROM whitelist WHERE active = 1"
        )}
        _blocked_cache = {row[0] for row in conn.execute(
            "SELECT ip FROM blocked_ips WHERE active = 1"
        )}


def is_whitelisted(ip: str) -> bool:
    return bool(ip and ip in _whitelist_cache)


def is_protected(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(address in network for network in PROTECTED_NETWORKS)


def block_ip(ip: str, reason: str = "CNN inference") -> bool:
    try:
        ip = normalize_ip(ip)
    except ValueError:
        log.warning("Refusing to block invalid IP: %r", ip)
        return False
    if ip in _blocked_cache or is_whitelisted(ip) or is_protected(ip):
        return False
    if not apply_firewall_block(ip):
        log.error("Firewall rejected block for %s; database was not changed", ip)
        return False
    now = datetime.now(timezone.utc).isoformat()
    with connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, active) VALUES (?, ?, ?, 1)",
            (ip, reason, now),
        )
    _blocked_cache.add(ip)
    log.warning("BLOCKED IP: %s reason=%s", ip, reason)
    return True


def restore_persisted_blocks() -> None:
    if not AUTO_BLOCK:
        log.info("Automatic blocking disabled; persisted blocks were not restored")
        return
    failures = []
    for ip in sorted(_blocked_cache):
        if is_protected(ip):
            log.warning("Not restoring protected address %s", ip)
            continue
        if not apply_firewall_block(ip):
            failures.append(ip)
    if failures:
        log.error("Could not restore %d persisted firewall blocks: %s", len(failures), failures)


def get_cursor() -> int:
    with connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT value FROM service_state WHERE key = 'inference_last_log_id'"
        ).fetchone()
    return int(row[0]) if row else 0


def fetch_new_logs(last_id: int) -> list[dict]:
    with connect(DB_PATH) as conn:
        conn.row_factory = __import__("sqlite3").Row
        rows = conn.execute(
            "SELECT * FROM logs WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, BATCH_SIZE),
        ).fetchall()
    return [dict(row) for row in rows]


def extract_features(logs: list[dict], scaler):
    rows, valid = [], []
    for log_doc in logs:
        try:
            data = log_doc.get("data", {})
            if isinstance(data, str):
                data = json.loads(data)
            rows.append([float(data.get(name, 0.0)) for name in FEATURES])
            valid.append(log_doc)
        except (ValueError, TypeError, json.JSONDecodeError):
            log.warning("Skipping malformed log id=%s", log_doc.get("id"))
    if not rows:
        return None, []
    values = np.nan_to_num(np.asarray(rows, dtype=np.float32))
    scaled = scaler.transform(values)
    return scaled.reshape(-1, len(FEATURES), 1), valid


def classify(model, values: np.ndarray):
    output = model.predict(values, verbose=0)
    probabilities = output[:, 0] if output.shape[1] == 1 else output[:, 1]
    return (probabilities >= THRESHOLD).astype(int), probabilities


def current_attack_run() -> tuple[str, bool]:
    """Return (attack_type, no_block) for the in-progress/just-finished simulation.

    Labels alerts at creation time so they are tagged correctly despite the
    capture/inference latency. Returns ('UNKNOWN', False) when none is active.
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        with connect(DB_PATH) as conn:
            row = conn.execute(
                """SELECT attack_type, no_block FROM attack_runs
                   WHERE start_time <= ?
                     AND (end_time IS NULL OR ? <= datetime(end_time, '+30 seconds'))
                   ORDER BY id DESC LIMIT 1""",
                (now, now),
            ).fetchone()
        if row:
            return (row[0] or "UNKNOWN"), bool(row[1])
    except Exception:
        pass
    return "UNKNOWN", False


def build_attack_alerts(logs, predictions, probabilities, label="UNKNOWN") -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    alerts = []
    for log_doc, prediction, probability in zip(logs, predictions, probabilities):
        ip = log_doc.get("source_ip") or "unknown"
        if prediction != 1 or is_whitelisted(ip):
            continue
        probability = float(probability)
        alerts.append({
            "source_log_id": log_doc["id"],
            "timestamp": log_doc.get("timestamp", now),
            "source_host": log_doc.get("source_host", "unknown"),
            "source_ip": ip,
            "prediction": "ATTACK",
            "severity": severity(probability),
            "attack_prob": round(probability, 4),
            "blocked": 0,
            "indexed_at": now,
            "raw_log": json.dumps(log_doc),
            "attack_type": label,
        })
    return alerts


def commit_batch(alerts: list[dict], cursor: int) -> None:
    with connect(DB_PATH) as conn:
        for alert in alerts:
            conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (timestamp, source_host, source_ip, prediction, severity, attack_prob,
                    blocked, indexed_at, raw_log, attack_type, source_log_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert["timestamp"], alert["source_host"], alert["source_ip"],
                 alert["prediction"], alert["severity"], alert["attack_prob"],
                 alert["blocked"], alert["indexed_at"], alert["raw_log"],
                 alert["attack_type"], alert["source_log_id"]),
            )
        conn.execute(
            "INSERT OR REPLACE INTO service_state (key, value) VALUES ('inference_last_log_id', ?)",
            (str(cursor),),
        )


def process_once(model, scaler, last_id: int) -> int:
    load_runtime_lists()  # Whitelist and manual blocks take effect on the next poll.
    logs = fetch_new_logs(last_id)
    if not logs:
        return last_id
    cursor = logs[-1]["id"]
    values, valid_logs = extract_features(logs, scaler)
    alerts = []
    if values is not None:
        predictions, probabilities = classify(model, values)
        label, no_block = current_attack_run()
        alerts = build_attack_alerts(valid_logs, predictions, probabilities, label)
        for alert in alerts:
            # Low-risk runs are still detected and shown, but never firewalled.
            if AUTO_BLOCK and not no_block and block_ip(alert["source_ip"]):
                alert["blocked"] = 1
    commit_batch(alerts, cursor)
    log.info("Processed %d logs; attacks=%d; cursor=%d", len(logs), len(alerts), cursor)
    return cursor


def run() -> None:
    init_schema(DB_PATH)
    model, scaler = load_assets()
    load_runtime_lists()
    restore_persisted_blocks()
    cursor = get_cursor()
    log.info(
        "Inference started; poll=%ss threshold=%s cursor=%s auto_block=%s",
        POLL_INTERVAL, THRESHOLD, cursor, AUTO_BLOCK,
    )
    while True:
        try:
            cursor = process_once(model, scaler, cursor)
        except Exception:
            log.exception("Inference loop error")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
