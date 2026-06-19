"""
api/main.py
===========
OneMoney IDS — FastAPI backend.

Endpoints
---------
GET  /                    health check
POST /api/predict         run CNN on a single feature vector (threshold 0.40)
GET  /api/alerts          recent alerts (paginated, filterable)
GET  /api/stats           summary counts and top attacker IPs
GET  /api/blocked         currently blocked IP addresses
POST /api/block           manually block an IP
DELETE /api/unblock/{ip}  unblock an IP

Run:
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sqlite3
import json
import subprocess
import logging
import numpy as np
import joblib
import tensorflow as tf
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH      = os.getenv("DB_PATH",      "/data/ids.db")

THRESHOLD    = float(os.getenv("THRESHOLD", "0.40"))

MODEL_PATH   = os.getenv("MODEL_PATH",  "model/onemoney_cnn.h5")
SCALER_PATH  = os.getenv("SCALER_PATH", "model/scaler.pkl")

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

# ── Lazy singletons ───────────────────────────────────────────────────────────
_model  = None
_scaler = None


def get_model():
    global _model, _scaler
    if _model is None:
        _model  = tf.keras.models.load_model(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        log.info("Model and scaler loaded.")
    return _model, _scaler


def get_db():
    return sqlite3.connect(DB_PATH)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iptables(args: list) -> bool:
    try:
        r = subprocess.run(["iptables"] + args, capture_output=True, text=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def _apply_block(ip: str):
    """Block incoming AND outgoing traffic from/to IP"""
    try:
        # Block incoming traffic FROM this IP
        _iptables(["-I", "INPUT", "-s", ip, "-j", "DROP"])
        # Block outgoing traffic TO this IP
        _iptables(["-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        # Also block forward (in case forwarding is enabled)
        _iptables(["-I", "FORWARD", "-s", ip, "-j", "DROP"])
        _iptables(["-I", "FORWARD", "-d", ip, "-j", "DROP"])
        log.info(f"Blocked IP {ip}: INPUT, OUTPUT, and FORWARD rules added")
        return True
    except Exception as exc:
        log.error(f"Failed to block IP {ip}: {exc}")
        return False


def _remove_block(ip: str):
    """Remove all blocking rules for this IP"""
    try:
        # Remove incoming block
        _iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
        # Remove outgoing block
        _iptables(["-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        # Remove forward blocks
        _iptables(["-D", "FORWARD", "-s", ip, "-j", "DROP"])
        _iptables(["-D", "FORWARD", "-d", ip, "-j", "DROP"])
        log.info(f"Unblocked IP {ip}: All rules removed")
        return True
    except Exception as exc:
        log.error(f"Failed to unblock IP {ip}: {exc}")
        return False


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    features: dict = Field(..., description="Map of feature_name → numeric value")


class PredictResponse(BaseModel):
    prediction:   str
    attack_prob:  float
    severity:     str
    threshold:    float
    probabilities: dict


class AlertOut(BaseModel):
    timestamp:   str
    source_host: str
    source_ip:   Optional[str]
    prediction:  str
    severity:    str
    attack_prob: float
    blocked:     bool = False


class BlockRequest(BaseModel):
    ip:     str
    reason: str = "manual"


class BlockedIP(BaseModel):
    ip:         str
    reason:     str
    blocked_at: str
    active:     bool


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="OneMoney Predictive IDS API",
    description="CNN-based IDS/IPS for VMware Mobile Financial Services — HIT 800 Research",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def health():
    return {
        "status":  "running",
        "service": "OneMoney Predictive IDS API",
        "version": "2.0.0",
        "threshold": THRESHOLD,
        "time":    datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/predict", response_model=PredictResponse)
def predict(entry: PredictRequest):
    """
    Run the CNN on a single CICFlowMeter feature vector.
    Returns ATTACK if attack_prob >= threshold (0.40).
    """
    model, scaler = get_model()

    row = np.array(
        [[float(entry.features.get(f, 0.0)) for f in FEATURES]],
        dtype=np.float32
    )
    row = np.nan_to_num(row, nan=0.0, posinf=0.0, neginf=0.0)
    row_s = scaler.transform(row)
    row_c = row_s.reshape(1, len(FEATURES), 1)

    proba = model.predict(row_c, verbose=0)[0]
    if len(proba.shape) == 0 or proba.shape[0] == 1:
        attack_prob = float(proba) if len(proba.shape) == 0 else float(proba[0])
        benign_prob = 1.0 - attack_prob
    else:
        benign_prob = float(proba[0])
        attack_prob = float(proba[1])

    is_attack = attack_prob >= THRESHOLD

    sev = "NONE"
    if is_attack:
        if attack_prob >= 0.95:
            sev = "CRITICAL"
        elif attack_prob >= 0.80:
            sev = "HIGH"
        elif attack_prob >= 0.60:
            sev = "MEDIUM"
        else:
            sev = "LOW"

    return PredictResponse(
        prediction="ATTACK" if is_attack else "BENIGN",
        attack_prob=round(attack_prob, 4),
        severity=sev,
        threshold=THRESHOLD,
        probabilities={
            "BENIGN": round(benign_prob, 4),
            "ATTACK": round(attack_prob, 4),
        },
    )


@app.get("/api/alerts")
def get_alerts(
    limit:    int = Query(50, ge=1, le=500),
    skip:     int = Query(0, ge=0),
    severity: Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW|NONE"),
    hours:    int = Query(24, ge=1, le=720),
    ip:       Optional[str] = Query(None, description="Filter by source IP"),
):
    """Recent attack alerts from SQLite, newest first."""
    try:
        conn = get_db()
        c = conn.cursor()
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        where_clauses = ["indexed_at >= ?", "prediction = 'ATTACK'"]
        params = [since]

        if severity:
            where_clauses.append("severity = ?")
            params.append(severity.upper())
        if ip:
            where_clauses.append("source_ip = ?")
            params.append(ip)

        where_sql = " AND ".join(where_clauses)

        c.execute(f"SELECT COUNT(*) as count FROM alerts WHERE {where_sql}", params)
        total = c.fetchone()[0]

        c.execute(
            f"SELECT * FROM alerts WHERE {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, skip]
        )
        rows = c.fetchall()

        alerts = []
        for row in rows:
            alerts.append({
                "timestamp": row[1],
                "source_host": row[2],
                "source_ip": row[3],
                "prediction": row[4],
                "severity": row[5],
                "attack_prob": row[6],
                "blocked": bool(row[7]),
                "indexed_at": row[8],
            })

        conn.close()
        return {"total": total, "limit": limit, "skip": skip, "alerts": alerts}
    except Exception as exc:
        log.error(f"SQLite query error: {exc}")
        return {"total": 0, "limit": limit, "skip": skip, "alerts": []}


@app.get("/api/stats")
def get_stats(hours: int = Query(24, ge=1, le=720)):
    """
    Summary statistics for the dashboard.
    Returns total counts, severity breakdown, top attacker IPs.
    """
    try:
        conn = get_db()
        c = conn.cursor()
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        c.execute(
            "SELECT COUNT(*) FROM alerts WHERE indexed_at >= ? AND prediction = 'ATTACK'",
            (since,)
        )
        total_attacks = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1")
        blocked_count = c.fetchone()[0]

        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        c.execute(
            "SELECT severity, COUNT(*) as count FROM alerts WHERE indexed_at >= ? AND prediction = 'ATTACK' GROUP BY severity",
            (since,)
        )
        for row in c.fetchall():
            severity_counts[row[0]] = row[1]

        c.execute(
            "SELECT source_ip, COUNT(*) as count FROM alerts WHERE indexed_at >= ? AND prediction = 'ATTACK' GROUP BY source_ip ORDER BY count DESC LIMIT 10",
            (since,)
        )
        top_attackers = [{"ip": row[0], "count": row[1]} for row in c.fetchall()]

        conn.close()

        return {
            "period_hours":    hours,
            "total_alerts":    total_attacks,
            "blocked_ips":     blocked_count,
            "severity_counts": severity_counts,
            "top_attackers":   top_attackers,
            "threshold":       THRESHOLD,
        }
    except Exception as exc:
        log.error(f"SQLite stats error: {exc}")
        return {
            "period_hours":    hours,
            "total_alerts":    0,
            "blocked_ips":     0,
            "severity_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "top_attackers":   [],
            "threshold":       THRESHOLD,
        }


@app.get("/api/blocked", response_model=List[BlockedIP])
def get_blocked():
    """List all currently active IP blocks."""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip, reason, blocked_at, active FROM blocked_ips WHERE active = 1")
        docs = []
        for row in c.fetchall():
            docs.append({
                "ip": row[0],
                "reason": row[1],
                "blocked_at": row[2],
                "active": bool(row[3])
            })
        conn.close()
        return docs
    except Exception as exc:
        log.error(f"SQLite blocked IPs query error: {exc}")
        return []


@app.post("/api/block", response_model=BlockedIP)
def block_ip(req: BlockRequest):
    """
    Manually block an IP address via iptables and record in SQLite.
    The inference service also picks this up on its next poll.
    """
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=422, detail="IP address is required.")

    try:
        now = datetime.now(timezone.utc).isoformat()
        _apply_block(ip)

        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, active) VALUES (?, ?, ?, ?)",
            (ip, req.reason, now, 1)
        )
        conn.commit()
        conn.close()
        log.info(f"Manually blocked IP: {ip}  reason={req.reason}")

        return {
            "ip": ip,
            "reason": req.reason,
            "blocked_at": now,
            "active": True
        }
    except Exception as exc:
        log.error(f"Block IP error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to block IP")


@app.delete("/api/unblock/{ip}")
def unblock_ip(ip: str):
    """
    Remove an IP block: delete iptables rules and mark inactive in SQLite.
    """
    try:
        # Remove iptables rules first
        iptables_success = _remove_block(ip)

        # Update database
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ?", (ip,))
        if c.rowcount == 0:
            conn.close()
            log.warning(f"Unblock attempted for {ip} but not found in database")
            raise HTTPException(status_code=404, detail=f"IP {ip} not found in block list.")
        conn.commit()
        conn.close()

        log.info(f"Unblocked IP: {ip} (iptables_success={iptables_success})")
        return {
            "status": "unblocked",
            "ip": ip,
            "iptables_success": iptables_success,
            "message": "IP removed from block list" + ("" if iptables_success else " (iptables may have failed - try again)")
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"Unblock IP error: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to unblock IP: {str(exc)}")


@app.post("/api/clear-db")
def clear_database():
    """
    Clear all alerts, logs, and blocked IPs from the database.
    Also removes all iptables rules for blocked IPs.
    Used for testing - allows clean slate without restarting services.
    """
    try:
        conn = get_db()
        c = conn.cursor()

        # Get all active blocked IPs and remove them from iptables
        c.execute("SELECT ip FROM blocked_ips WHERE active = 1")
        blocked_ips = [row[0] for row in c.fetchall()]
        for ip in blocked_ips:
            _remove_block(ip)

        # Clear all tables
        c.execute("DELETE FROM alerts")
        c.execute("DELETE FROM logs")
        c.execute("DELETE FROM blocked_ips")
        conn.commit()
        conn.close()

        log.info(f"Database cleared: alerts, logs, and {len(blocked_ips)} blocked IPs deleted")
        return {
            "status": "cleared",
            "message": f"All alerts, logs, and {len(blocked_ips)} blocked IPs deleted from database"
        }
    except Exception as exc:
        log.error(f"Clear database error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to clear database")


class AttackStartRequest(BaseModel):
    attack_type: str = Field(..., description="e.g., SYN_FLOOD, SSH_BRUTE, UDP_FLOOD, ICMP_FLOOD, PORT_SCAN, UNKNOWN")
    target_ip: str = Field(..., description="Target IP address")
    source_ip: Optional[str] = Field(None, description="Attacker IP (optional)")
    intensity: str = Field("normal", description="light, normal, or heavy")


@app.post("/api/attack-start")
def log_attack_start(req: AttackStartRequest):
    """
    Log when an attack simulation starts.
    Used to automatically label alerts with attack type.
    """
    try:
        conn = get_db()
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        # Create attack_runs table if it doesn't exist
        c.execute("""
            CREATE TABLE IF NOT EXISTS attack_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                target_ip TEXT,
                source_ip TEXT,
                intensity TEXT,
                start_time TEXT,
                end_time TEXT,
                status TEXT DEFAULT 'running'
            )
        """)

        # Insert attack start record
        c.execute(
            "INSERT INTO attack_runs (attack_type, target_ip, source_ip, intensity, start_time, status) VALUES (?, ?, ?, ?, ?, ?)",
            (req.attack_type, req.target_ip, req.source_ip or "0.0.0.0", req.intensity, now, "running")
        )
        attack_id = c.lastrowid
        conn.commit()
        conn.close()

        log.info(f"Attack started: ID={attack_id} Type={req.attack_type} Target={req.target_ip} Intensity={req.intensity}")
        return {
            "status": "recorded",
            "attack_id": attack_id,
            "message": f"Attack {req.attack_type} started"
        }
    except Exception as exc:
        log.error(f"Attack start logging error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to log attack start")


class AttackEndRequest(BaseModel):
    attack_id: int = Field(..., description="ID returned from attack-start")
    packets_sent: int = Field(0, description="Number of packets sent")


class WhitelistIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to whitelist")
    reason: str = Field("manual", description="Reason for whitelisting")


class WhitelistIP(BaseModel):
    ip: str
    reason: str
    added_at: str
    active: bool


@app.post("/api/attack-end")
def log_attack_end(req: AttackEndRequest):
    """
    Log when an attack simulation ends.
    Automatically labels all alerts in the time window with the attack type.
    """
    try:
        conn = get_db()
        c = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        # Get attack details
        c.execute("SELECT attack_type, start_time, target_ip, source_ip FROM attack_runs WHERE id = ?", (req.attack_id,))
        attack = c.fetchone()
        if not attack:
            conn.close()
            raise HTTPException(status_code=404, detail=f"Attack ID {req.attack_id} not found")

        attack_type, start_time, target_ip, source_ip = attack

        # Mark attack as ended
        c.execute(
            "UPDATE attack_runs SET end_time = ?, status = ? WHERE id = ?",
            (now, "completed", req.attack_id)
        )

        # Auto-label alerts within time window
        # Alerts within 30 seconds after attack start are labeled with this attack type
        c.execute("""
            UPDATE alerts
            SET attack_type = ?
            WHERE indexed_at BETWEEN ? AND datetime(?, '+30 seconds')
            AND (source_ip = ? OR source_ip LIKE ? || '%')
        """, (attack_type, start_time, start_time, source_ip, source_ip.rsplit('.', 1)[0]))

        labeled_count = c.rowcount
        conn.commit()
        conn.close()

        log.info(f"Attack ended: ID={req.attack_id} Type={attack_type} Labeled={labeled_count} alerts Packets={req.packets_sent}")
        return {
            "status": "recorded",
            "attack_id": req.attack_id,
            "alerts_labeled": labeled_count,
            "message": f"Attack {attack_type} ended, {labeled_count} alerts labeled"
        }
    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"Attack end logging error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to log attack end")


@app.get("/api/whitelist", response_model=List[WhitelistIP])
def get_whitelist():
    """List all whitelisted IPs"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT ip, reason, added_at, active FROM whitelist WHERE active = 1")
        docs = []
        for row in c.fetchall():
            docs.append({
                "ip": row[0],
                "reason": row[1],
                "added_at": row[2],
                "active": bool(row[3])
            })
        conn.close()
        return docs
    except Exception as exc:
        log.error(f"Whitelist query error: {exc}")
        return []


@app.post("/api/whitelist", response_model=WhitelistIP)
def add_whitelist(req: WhitelistIPRequest):
    """Add an IP to whitelist (won't be flagged as attack)"""
    ip = req.ip.strip()
    if not ip:
        raise HTTPException(status_code=422, detail="IP address is required")

    try:
        now = datetime.now(timezone.utc).isoformat()
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO whitelist (ip, reason, added_at, active) VALUES (?, ?, ?, ?)",
            (ip, req.reason, now, 1)
        )
        conn.commit()
        conn.close()
        log.info(f"Added IP to whitelist: {ip}  reason={req.reason}")

        return {
            "ip": ip,
            "reason": req.reason,
            "added_at": now,
            "active": True
        }
    except Exception as exc:
        log.error(f"Whitelist add error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to add IP to whitelist")


@app.delete("/api/whitelist/{ip}")
def remove_whitelist(ip: str):
    """Remove an IP from whitelist"""
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("UPDATE whitelist SET active = 0 WHERE ip = ?", (ip,))
        if c.rowcount == 0:
            conn.close()
            raise HTTPException(status_code=404, detail=f"IP {ip} not found in whitelist")
        conn.commit()
        conn.close()
        log.info(f"Removed IP from whitelist: {ip}")
        return {"status": "removed", "ip": ip}
    except HTTPException:
        raise
    except Exception as exc:
        log.error(f"Whitelist remove error: {exc}")
        raise HTTPException(status_code=500, detail="Failed to remove IP from whitelist")
