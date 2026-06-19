"""Multi-source anomaly correlation (Objective 2).

Fuses two independent anomaly signals per source IP within a time window:

  * Network source  -> the CNN attack probability (already ML), from `alerts`.
  * Auth-log source -> an unsupervised anomaly score over failed-login
                       behaviour (IsolationForest, with a robust z-score
                       fallback when there is too little data), from `log_events`.

The two per-source scores are combined with a late-fusion rule into a single
`fused_score`; an IP is flagged `correlated` when *both* sources are anomalous,
which is a far stronger signal than either alone and is what we escalate on.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone

import numpy as np

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # sklearn always present in this project, but stay defensive
    IsolationForest = None

# Late-fusion weights and the per-source thresholds that define "anomalous".
NETWORK_WEIGHT = 0.6
LOG_WEIGHT = 0.4
NETWORK_THRESHOLD = 0.50
LOG_THRESHOLD = 0.50
MIN_SAMPLES_FOR_MODEL = 12


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def score_log_anomalies(rows: list[dict]) -> dict[str, float]:
    """Return {source_ip: anomaly_score in [0,1]} for auth-log behaviour.

    Each row provides per-IP/window features (failed_logins, distinct_users).
    Uses IsolationForest when there are enough samples; otherwise falls back to
    a robust z-score on failed-login counts so the system still works cold.
    """
    if not rows:
        return {}

    features = np.array(
        [[float(r["failed_logins"]), float(r["distinct_users"])] for r in rows],
        dtype=np.float64,
    )
    ips = [r["source_ip"] for r in rows]

    # Cold-start / small-sample fallback. A relative z-score alone cannot flag
    # the common lab case where one attacking IP is the entire sample, so blend
    # it with an absolute failed-login signal that rises smoothly toward 1.
    if IsolationForest is None or len(rows) < MIN_SAMPLES_FOR_MODEL:
        counts = features[:, 0]
        median = float(np.median(counts))
        mad = float(np.median(np.abs(counts - median))) or 1.0
        scores = {}
        for ip, count, distinct_users in zip(ips, counts, features[:, 1]):
            z = 0.6745 * (count - median) / mad  # robust z
            absolute = 1.0 - math.exp(-(count + distinct_users) / 5.0)
            scores[ip] = max(scores.get(ip, 0.0), _sigmoid(z - 1.5), absolute)
        return scores

    # Unsupervised model: lower decision_function => more anomalous.
    model = IsolationForest(contamination="auto", random_state=42)
    model.fit(features)
    raw = -model.decision_function(features)  # higher => more anomalous
    lo, hi = float(raw.min()), float(raw.max())
    span = (hi - lo) or 1.0
    scores: dict[str, float] = {}
    for ip, value in zip(ips, raw):
        normalized = (float(value) - lo) / span
        scores[ip] = max(scores.get(ip, 0.0), normalized)
    return scores


def correlate(conn, window_seconds: int = 120) -> int:
    """Fuse network + auth-log anomalies per IP and persist correlated alerts.

    Returns the number of correlated_alerts rows written.
    """
    since = _iso_since(window_seconds)

    # Network anomaly per IP: strongest recent CNN attack probability.
    net_rows = conn.execute(
        """SELECT source_ip, MAX(attack_prob) AS score
           FROM alerts
           WHERE indexed_at >= ? AND prediction = 'ATTACK'
           GROUP BY source_ip""",
        (since,),
    ).fetchall()
    network = {ip: float(score) for ip, score in net_rows}

    # Auth-log features per IP within the same window.
    log_rows = [
        {"source_ip": ip, "failed_logins": fl, "distinct_users": du}
        for ip, fl, du in conn.execute(
            """SELECT source_ip, SUM(failed_logins), MAX(distinct_users)
               FROM log_events
               WHERE indexed_at >= ?
               GROUP BY source_ip""",
            (since,),
        ).fetchall()
    ]
    log_scores = score_log_anomalies(log_rows)
    log_counts = {r["source_ip"]: r["failed_logins"] for r in log_rows}

    now = datetime.now(timezone.utc).isoformat()
    written = 0
    for ip in set(network) | set(log_scores):
        net = network.get(ip, 0.0)
        log = log_scores.get(ip, 0.0)
        fused = NETWORK_WEIGHT * net + LOG_WEIGHT * log
        both = net >= NETWORK_THRESHOLD and log >= LOG_THRESHOLD
        # Correlated evidence reinforces confidence beyond either source alone.
        if both:
            fused = min(1.0, fused + 0.15)
        detail = json.dumps({
            "network_score": round(net, 4),
            "log_score": round(log, 4),
            "failed_logins": log_counts.get(ip, 0),
            "sources": [s for s, present in (("network", net > 0), ("auth_log", log > 0)) if present],
        })
        conn.execute(
            """INSERT INTO correlated_alerts
               (source_ip, network_score, log_score, fused_score, correlated, detail, window_start, indexed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ip, round(net, 4), round(log, 4), round(fused, 4), 1 if both else 0, detail, since, now),
        )
        written += 1
    return written


def _iso_since(seconds: int) -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
