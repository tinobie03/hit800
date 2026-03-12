"""
inference_service.py
====================
Live intrusion detection service.

What it does every POLL_INTERVAL seconds:
  1. Queries Elasticsearch for new log entries (since last run)
  2. Extracts and normalizes features using the saved scaler
  3. Runs the CNN model to classify each log entry
  4. Writes alerts back to Elasticsearch index 'ids-alerts'
  5. Persists alerts to MongoDB

Run with:
  python -m inference.inference_service

Prerequisites:
  - docker-compose up -d   (ELK + MongoDB running)
  - CNN model trained and saved to data/models/cnn_ids_best.h5
  - Scaler saved to data/processed/scaler.pkl
"""

import os
import time
import logging
import numpy as np
import joblib
import tensorflow as tf
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

# ── Logging ──────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/inference.log")
    ]
)
log = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────
ES_HOST         = os.getenv("ES_HOST",         "http://localhost:9200")
MONGO_URI       = os.getenv("MONGO_URI",        "mongodb://localhost:27017")
MONGO_DB        = os.getenv("MONGO_DB",         "ids_db")
ALERT_COLL      = os.getenv("ALERT_COLL",       "alerts")
SOURCE_INDEX    = os.getenv("SOURCE_INDEX",     "logs-*")     # Logstash writes here
ALERT_INDEX     = os.getenv("ALERT_INDEX",      "ids-alerts") # CNN writes here
POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "10"))       # seconds between polls
BATCH_SIZE      = int(os.getenv("BATCH_SIZE",    "500"))

BEST_MODEL      = "data/models/cnn_ids_best.h5"
SCALER_PATH     = "data/processed/scaler.pkl"
FEATURE_COLS    = "data/processed/feature_cols.npy"

CLASS_NAMES     = {0: "BENIGN", 1: "ATTACK"}
SEVERITY_MAP    = {
    (1, 0.95): "CRITICAL",
    (1, 0.80): "HIGH",
    (1, 0.60): "MEDIUM",
    (1, 0.00): "LOW",
    (0, 0.00): "NONE",
}


def get_severity(pred_class: int, confidence: float) -> str:
    if pred_class == 0:
        return "NONE"
    if confidence >= 0.95:
        return "CRITICAL"
    if confidence >= 0.80:
        return "HIGH"
    if confidence >= 0.60:
        return "MEDIUM"
    return "LOW"


def load_model_and_scaler():
    log.info("Loading CNN model and scaler...")
    model  = tf.keras.models.load_model(BEST_MODEL)
    scaler = joblib.load(SCALER_PATH)
    feature_cols = np.load(FEATURE_COLS, allow_pickle=True).tolist()
    log.info(f"Model loaded: {BEST_MODEL}")
    log.info(f"Scaler loaded: {SCALER_PATH}")
    log.info(f"Expecting {len(feature_cols)} features")
    return model, scaler, feature_cols


def connect_elasticsearch() -> Elasticsearch:
    es = Elasticsearch(ES_HOST)
    if not es.ping():
        raise ConnectionError(f"Cannot reach Elasticsearch at {ES_HOST}")
    log.info(f"Connected to Elasticsearch: {ES_HOST}")
    return es


def connect_mongodb():
    client = MongoClient(MONGO_URI)
    db     = client[MONGO_DB]
    coll   = db[ALERT_COLL]
    log.info(f"Connected to MongoDB: {MONGO_URI}/{MONGO_DB}")
    return coll


def ensure_alert_index(es: Elasticsearch):
    """Create ids-alerts index with mapping if it doesn't exist."""
    if not es.indices.exists(index=ALERT_INDEX):
        es.indices.create(index=ALERT_INDEX, body={
            "mappings": {
                "properties": {
                    "timestamp"   : {"type": "date"},
                    "source_host" : {"type": "keyword"},
                    "prediction"  : {"type": "keyword"},
                    "severity"    : {"type": "keyword"},
                    "confidence"  : {"type": "float"},
                    "raw_log"     : {"type": "object", "enabled": False},
                }
            }
        })
        log.info(f"Created Elasticsearch index: {ALERT_INDEX}")


def fetch_new_logs(es: Elasticsearch, last_timestamp: str) -> list:
    """Fetch documents from Elasticsearch newer than last_timestamp."""
    query = {
        "query": {
            "range": {"@timestamp": {"gt": last_timestamp}}
        },
        "size": BATCH_SIZE,
        "sort": [{"@timestamp": "asc"}]
    }
    resp = es.search(index=SOURCE_INDEX, body=query)
    hits = resp["hits"]["hits"]
    log.info(f"Fetched {len(hits)} new log entries from Elasticsearch.")
    return hits


def extract_features(hits: list, feature_cols: list,
                     scaler) -> tuple:
    """
    Extract numeric feature matrix from ES documents.
    Returns (X_scaled, docs) where X_scaled is (n, 1, features) shaped.
    """
    rows = []
    valid_hits = []
    for hit in hits:
        src = hit["_source"]
        try:
            row = [float(src.get(col, 0.0)) for col in feature_cols]
            rows.append(row)
            valid_hits.append(hit)
        except (ValueError, TypeError):
            continue   # skip malformed log entries

    if not rows:
        return None, []

    X = np.array(rows, dtype=np.float32)
    X_scaled = scaler.transform(X)
    X_cnn    = X_scaled.reshape(X_scaled.shape[0], 1, X_scaled.shape[1])
    return X_cnn, valid_hits


def build_alert_docs(hits: list, y_pred: np.ndarray,
                     y_proba: np.ndarray) -> list:
    """Build alert documents to index into Elasticsearch and MongoDB."""
    alerts = []
    now = datetime.now(timezone.utc).isoformat()
    for hit, pred_class, proba in zip(hits, y_pred, y_proba):
        src        = hit["_source"]
        confidence = float(np.max(proba))
        severity   = get_severity(int(pred_class), confidence)

        alert = {
            "timestamp"   : src.get("@timestamp", now),
            "source_host" : src.get("host", {}).get("name", "unknown"),
            "source_ip"   : src.get("source", {}).get("ip", "unknown"),
            "prediction"  : CLASS_NAMES[int(pred_class)],
            "severity"    : severity,
            "confidence"  : round(confidence, 4),
            "raw_log"     : src,
            "indexed_at"  : now,
        }
        alerts.append(alert)
    return alerts


def push_alerts_to_elasticsearch(es: Elasticsearch, alerts: list):
    """Bulk index alerts into ids-alerts."""
    if not alerts:
        return
    actions = [
        {"_index": ALERT_INDEX, "_source": a}
        for a in alerts
    ]
    success, failed = helpers.bulk(es, actions, raise_on_error=False)
    log.info(f"Elasticsearch: {success} alerts indexed, {len(failed)} failed.")


def push_alerts_to_mongodb(coll, alerts: list):
    """Insert alerts into MongoDB."""
    if not alerts:
        return
    coll.insert_many(alerts)
    log.info(f"MongoDB: {len(alerts)} alerts inserted.")


def run_inference_loop():
    """
    Main loop — polls Elasticsearch for new logs, classifies them,
    and pushes alerts to Elasticsearch + MongoDB.
    """
    model, scaler, feature_cols = load_model_and_scaler()
    es   = connect_elasticsearch()
    coll = connect_mongodb()

    ensure_alert_index(es)

    # Start from 1 minute ago on first run
    last_timestamp = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z"
    )
    attack_count = 0

    log.info(f"Inference service started. Polling every {POLL_INTERVAL}s...")
    log.info(f"Source index: {SOURCE_INDEX}  →  Alert index: {ALERT_INDEX}")

    while True:
        try:
            # 1. Fetch new logs
            hits = fetch_new_logs(es, last_timestamp)

            if hits:
                # Update timestamp cursor
                last_timestamp = hits[-1]["_source"].get(
                    "@timestamp", last_timestamp
                )

                # 2. Extract + preprocess features
                X_cnn, valid_hits = extract_features(hits, feature_cols, scaler)

                if X_cnn is not None:
                    # 3. Run CNN inference
                    y_proba     = model.predict(X_cnn, verbose=0)
                    y_pred      = np.argmax(y_proba, axis=1)

                    attack_count += int(np.sum(y_pred == 1))
                    benign_count  = int(np.sum(y_pred == 0))

                    log.info(f"Classified {len(y_pred)} entries | "
                             f"ATTACK: {np.sum(y_pred==1)} | "
                             f"BENIGN: {benign_count} | "
                             f"Total attacks detected: {attack_count}")

                    # 4. Build alert documents
                    alerts = build_alert_docs(valid_hits, y_pred, y_proba)

                    # Filter — only push actual attacks to alert indices
                    attack_alerts = [a for a in alerts if a["prediction"] == "ATTACK"]

                    # 5. Push to stores
                    push_alerts_to_elasticsearch(es, attack_alerts)
                    push_alerts_to_mongodb(coll, attack_alerts)

        except Exception as exc:
            log.error(f"Inference loop error: {exc}", exc_info=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run_inference_loop()
