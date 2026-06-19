"""SQLite-backed CNN inference and host firewall enforcement service."""

import json
import ipaddress
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import joblib
import numpy as np
import tensorflow as tf
from ids_core.database import connect, init_schema
from ids_core.features import FEATURES
from ids_core.firewall import block_ip as apply_firewall_block, normalize_ip
from ids_core.correlation import correlate

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
BLOCK_MIN_ALERTS = int(os.getenv("BLOCK_MIN_ALERTS", "3"))
BLOCK_WINDOW_SECONDS = int(os.getenv("BLOCK_WINDOW_SECONDS", "60"))
BLOCK_MIN_SCORE = float(os.getenv("BLOCK_MIN_SCORE", "0.80"))
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


def has_block_evidence(ip: str) -> bool:
    """Require repeated high-scoring detections before firewall escalation."""
    since = (datetime.now(timezone.utc) - timedelta(seconds=BLOCK_WINDOW_SECONDS)).isoformat()
    with connect(DB_PATH) as conn:
        count, max_score = conn.execute(
            """SELECT COUNT(*), COALESCE(MAX(attack_prob), 0)
               FROM alerts
               WHERE source_ip = ? AND prediction = 'ATTACK' AND indexed_at >= ?""",
            (ip, since),
        ).fetchone()
    return count >= BLOCK_MIN_ALERTS and float(max_score) >= BLOCK_MIN_SCORE


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


def current_attack_runs() -> dict[str, tuple[str, bool]]:
    """Return active/recent tracked simulations keyed by attacker source IP.

    Labels alerts at creation time so they are tagged correctly despite the
    capture/inference latency. Source matching prevents a concurrent benign
    client from inheriting the attacker's label or low-risk firewall policy.
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        with connect(DB_PATH) as conn:
            rows = conn.execute(
                """SELECT source_ip, attack_type, no_block FROM attack_runs
                   WHERE julianday(start_time) <= julianday(?)
                     AND (end_time IS NULL OR julianday(?) <= julianday(end_time, '+30 seconds'))
                   ORDER BY id""",
                (now, now),
            ).fetchall()
        return {
            (row[0] or "0.0.0.0"): (row[1] or "UNKNOWN", bool(row[2]))
            for row in rows
        }
    except Exception:
        return {}


def build_events(logs, predictions, probabilities, label="UNKNOWN") -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for log_doc, prediction, probability in zip(logs, predictions, probabilities):
        ip = log_doc.get("source_ip") or "unknown"
        probability = float(probability)
        is_attack = prediction == 1
        if isinstance(label, dict):
            event_label = label.get(ip, label.get("0.0.0.0", ("UNKNOWN", False)))[0]
        else:
            event_label = label
        events.append({
            "source_log_id": log_doc["id"],
            "timestamp": log_doc.get("timestamp", now),
            "source_host": log_doc.get("source_host", "unknown"),
            "source_ip": ip,
            "destination_ip": log_doc.get("destination_ip"),
            "prediction": "ATTACK" if is_attack else "BENIGN",
            "severity": severity(probability) if is_attack else "NONE",
            "attack_prob": round(probability, 4),
            "blocked": 0,
            "indexed_at": now,
            "raw_log": json.dumps(log_doc),
            "attack_type": event_label if is_attack else "NORMAL",
        })
    return events


# Compatibility for callers/tests using the old name. It now intentionally
# returns every classification so the live stream can include benign traffic.
build_attack_alerts = build_events


def commit_batch(alerts: list[dict], cursor: int) -> None:
    with connect(DB_PATH) as conn:
        for alert in alerts:
            conn.execute(
                """INSERT OR IGNORE INTO alerts
                   (timestamp, source_host, source_ip, destination_ip, prediction, severity, attack_prob,
                    blocked, indexed_at, raw_log, attack_type, source_log_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (alert["timestamp"], alert["source_host"], alert["source_ip"],
                 alert.get("destination_ip"), alert["prediction"], alert["severity"], alert["attack_prob"],
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
    events = []
    if values is not None:
        predictions, probabilities = classify(model, values)
        active_runs = current_attack_runs()
        events = build_events(valid_logs, predictions, probabilities, active_runs)
    commit_batch(events, cursor)

    # Escalate only after repeated high-score evidence. Whitelisted/protected
    # sources remain visible in the stream but are never firewalled.
    attack_ips = {
        event["source_ip"] for event in events
        if event["prediction"] == "ATTACK"
        and not is_whitelisted(event["source_ip"])
    }
    no_block_ips = {
        ip for ip, (_, no_block) in active_runs.items() if no_block
    } if values is not None else set()
    if AUTO_BLOCK:
        for ip in sorted(attack_ips):
            if ip in no_block_ips or "0.0.0.0" in no_block_ips:
                continue
            if has_block_evidence(ip) and block_ip(
                ip,
                f"{BLOCK_MIN_ALERTS}+ model alerts/{BLOCK_WINDOW_SECONDS}s",
            ):
                with connect(DB_PATH) as conn:
                    conn.execute(
                        """UPDATE alerts SET blocked = 1 WHERE id = (
                               SELECT id FROM alerts WHERE source_ip = ?
                               ORDER BY indexed_at DESC, id DESC LIMIT 1
                           )""",
                        (ip,),
                    )
    # Objective 2: fuse network anomalies with the auth-log source per IP.
    try:
        with connect(DB_PATH) as conn:
            correlated = correlate(conn)
        if correlated:
            log.info("Correlation pass wrote %d fused alerts", correlated)
    except Exception:
        log.exception("Correlation step failed")
    attack_count = sum(event["prediction"] == "ATTACK" for event in events)
    log.info(
        "Processed %d logs; benign=%d attacks=%d cursor=%d",
        len(logs), len(events) - attack_count, attack_count, cursor,
    )
    return cursor


def run() -> None:
    init_schema(DB_PATH)
    model, scaler = load_assets()
    load_runtime_lists()
    restore_persisted_blocks()
    cursor = get_cursor()
    log.info(
        "Inference started; poll=%ss threshold=%s cursor=%s auto_block=%s block_policy=%s/%ss@%s",
        POLL_INTERVAL, THRESHOLD, cursor, AUTO_BLOCK,
        BLOCK_MIN_ALERTS, BLOCK_WINDOW_SECONDS, BLOCK_MIN_SCORE,
    )
    while True:
        try:
            cursor = process_once(model, scaler, cursor)
        except Exception:
            log.exception("Inference loop error")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
