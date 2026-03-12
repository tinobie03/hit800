"""
api/main.py
===========
FastAPI backend — serves alert data to the React dashboard.

Endpoints:
  GET  /                      — health check
  GET  /api/alerts            — recent alerts (paginated)
  GET  /api/alerts/summary    — counts by severity and prediction
  GET  /api/alerts/timeline   — alert counts over time (for charts)
  GET  /api/metrics           — model evaluation metrics
  POST /api/predict           — run CNN on a single log entry (demo)

Run with:
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import logging
import numpy as np
import joblib
import tensorflow as tf
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from elasticsearch import Elasticsearch
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# ── Logging ──────────────────────────────────────────────
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────
ES_HOST      = os.getenv("ES_HOST",    "http://localhost:9200")
MONGO_URI    = os.getenv("MONGO_URI",  "mongodb://localhost:27017")
MONGO_DB     = os.getenv("MONGO_DB",   "ids_db")
ALERT_COLL   = os.getenv("ALERT_COLL", "alerts")
ALERT_INDEX  = os.getenv("ALERT_INDEX","ids-alerts")
BEST_MODEL   = "data/models/cnn_ids_best.h5"
SCALER_PATH  = "data/processed/scaler.pkl"
FEATURE_COLS = "data/processed/feature_cols.npy"

# ── App setup ────────────────────────────────────────────
app = FastAPI(
    title="Predictive IDS API",
    description="CNN-based Intrusion Detection System for VMware MFS Environments",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # restrict to dashboard domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Lazy-load model, scaler, clients ─────────────────────
_model   = None
_scaler  = None
_feats   = None
_es      = None
_mongo   = None


def get_model():
    global _model, _scaler, _feats
    if _model is None:
        _model  = tf.keras.models.load_model(BEST_MODEL)
        _scaler = joblib.load(SCALER_PATH)
        _feats  = np.load(FEATURE_COLS, allow_pickle=True).tolist()
    return _model, _scaler, _feats


def get_es() -> Elasticsearch:
    global _es
    if _es is None:
        _es = Elasticsearch(ES_HOST)
    return _es


def get_mongo():
    global _mongo
    if _mongo is None:
        client = MongoClient(MONGO_URI)
        _mongo = client[MONGO_DB][ALERT_COLL]
    return _mongo


# ── Pydantic schemas ─────────────────────────────────────
class LogEntry(BaseModel):
    """Single log entry for on-demand prediction."""
    features: dict   # field_name: value pairs


class AlertOut(BaseModel):
    timestamp  : str
    source_host: str
    source_ip  : Optional[str]
    prediction : str
    severity   : str
    confidence : float


# ── Routes ───────────────────────────────────────────────

@app.get("/")
def health():
    return {
        "status" : "running",
        "service": "Predictive IDS API",
        "version": "1.0.0",
        "time"   : datetime.now(timezone.utc).isoformat()
    }


@app.get("/api/alerts", response_model=List[AlertOut])
def get_alerts(
    limit    : int = Query(50, ge=1, le=500),
    severity : Optional[str] = Query(None, description="CRITICAL|HIGH|MEDIUM|LOW"),
    hours    : int = Query(24, ge=1, le=168, description="Last N hours"),
):
    """
    Return recent alerts from MongoDB.
    Filter by severity and time window.
    """
    coll = get_mongo()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    query: dict = {"indexed_at": {"$gte": since.isoformat()}}
    if severity:
        query["severity"] = severity.upper()

    docs = list(
        coll.find(query, {"_id": 0})
            .sort("timestamp", -1)
            .limit(limit)
    )
    return docs


@app.get("/api/alerts/summary")
def get_summary(hours: int = Query(24, ge=1, le=168)):
    """Alert counts grouped by severity and prediction class."""
    coll  = get_mongo()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    pipeline = [
        {"$match": {"indexed_at": {"$gte": since.isoformat()}}},
        {"$group": {
            "_id"  : {"severity": "$severity", "prediction": "$prediction"},
            "count": {"$sum": 1}
        }}
    ]
    results = list(coll.aggregate(pipeline))

    # Also get ES total
    es = get_es()
    try:
        es_total = es.count(index=ALERT_INDEX)["count"]
    except Exception:
        es_total = -1

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
    total_attacks   = 0
    total_benign    = 0

    for r in results:
        sev  = r["_id"].get("severity", "NONE")
        pred = r["_id"].get("prediction", "BENIGN")
        cnt  = r["count"]
        severity_counts[sev] = severity_counts.get(sev, 0) + cnt
        if pred == "ATTACK":
            total_attacks += cnt
        else:
            total_benign  += cnt

    return {
        "period_hours"   : hours,
        "total_attacks"  : total_attacks,
        "total_benign"   : total_benign,
        "severity_counts": severity_counts,
        "es_index_total" : es_total,
    }


@app.get("/api/alerts/timeline")
def get_timeline(
    hours     : int = Query(24, ge=1, le=168),
    bucket_min: int = Query(60, description="Bucket size in minutes"),
):
    """
    Alert counts bucketed by time interval — used to draw the timeline chart.
    Returns list of {time, attack_count, benign_count}.
    """
    coll  = get_mongo()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    pipeline = [
        {"$match": {"indexed_at": {"$gte": since.isoformat()}}},
        {"$project": {
            "prediction": 1,
            "bucket": {
                "$dateToString": {
                    "format": "%Y-%m-%dT%H:00:00Z",
                    "date"  : {"$toDate": "$timestamp"}
                }
            }
        }},
        {"$group": {
            "_id"         : {"bucket": "$bucket", "prediction": "$prediction"},
            "count"       : {"$sum": 1}
        }},
        {"$sort": {"_id.bucket": 1}}
    ]

    results = list(coll.aggregate(pipeline))
    buckets: dict = {}
    for r in results:
        b    = r["_id"]["bucket"]
        pred = r["_id"]["prediction"]
        cnt  = r["count"]
        if b not in buckets:
            buckets[b] = {"time": b, "attack_count": 0, "benign_count": 0}
        if pred == "ATTACK":
            buckets[b]["attack_count"] += cnt
        else:
            buckets[b]["benign_count"] += cnt

    return list(buckets.values())


@app.get("/api/metrics")
def get_metrics():
    """Return saved evaluation metrics from logs/model_comparison.csv."""
    import pandas as pd
    csv_path = "logs/model_comparison.csv"
    if not os.path.exists(csv_path):
        raise HTTPException(status_code=404,
                            detail="Model comparison not found. Run model/evaluate.py first.")
    df = pd.read_csv(csv_path)
    return df.to_dict(orient="records")


@app.post("/api/predict")
def predict_single(entry: LogEntry):
    """
    Run CNN on a single log entry (for demo / manual testing).
    Body: {"features": {"col1": val1, "col2": val2, ...}}
    """
    model, scaler, feature_cols = get_model()

    row = [float(entry.features.get(col, 0.0)) for col in feature_cols]
    X   = np.array([row], dtype=np.float32)
    X_s = scaler.transform(X)
    X_c = X_s.reshape(1, 1, len(feature_cols))

    proba      = model.predict(X_c, verbose=0)[0]
    pred_class = int(np.argmax(proba))
    confidence = float(np.max(proba))

    return {
        "prediction"  : "ATTACK" if pred_class == 1 else "BENIGN",
        "confidence"  : round(confidence, 4),
        "probabilities": {
            "BENIGN": round(float(proba[0]), 4),
            "ATTACK": round(float(proba[1]), 4)
        }
    }
