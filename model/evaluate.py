"""Evaluate the deployed sigmoid model using the canonical 76-feature test set."""

import json
import os
import time
from pathlib import Path

import joblib
import numpy as np
import tensorflow as tf
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "data" / "processed"
MODEL = ROOT / "model" / "onemoney_cnn.h5"
SCALER = ROOT / "model" / "scaler.pkl"
THRESHOLD = float(os.getenv("THRESHOLD", "0.50"))


def run_evaluation() -> dict:
    X = np.load(PROCESSED / "X_test.npy")
    y = np.load(PROCESSED / "y_test.npy")
    model = tf.keras.models.load_model(MODEL)
    scaler = joblib.load(SCALER)
    if X.shape[1] != scaler.n_features_in_ or tuple(model.input_shape[1:]) != (X.shape[1], 1):
        raise RuntimeError("Model, scaler, and processed feature dimensions do not match")
    X = X.reshape(-1, X.shape[1], 1)
    model.predict(X[:10], verbose=0)
    started = time.perf_counter()
    probability = model.predict(X, verbose=0).reshape(-1)
    latency = (time.perf_counter() - started) * 1000 / len(X)
    prediction = (probability >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, prediction).ravel()
    results = {
        "accuracy": round(accuracy_score(y, prediction), 4),
        "precision": round(precision_score(y, prediction, zero_division=0), 4),
        "attack_recall": round(recall_score(y, prediction, zero_division=0), 4),
        "false_pos_rate": round(fp / (fp + tn), 4),
        "f1_score": round(f1_score(y, prediction, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y, probability), 4),
        "latency_ms_per_sample": round(latency, 4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        "threshold": THRESHOLD,
        "test_samples": len(y),
    }
    (ROOT / "logs" / "evaluate.json").write_text(json.dumps(results, indent=2) + "\n")
    print(classification_report(y, prediction, target_names=["BENIGN", "ATTACK"]))
    print(json.dumps(results, indent=2))
    return results


if __name__ == "__main__":
    run_evaluation()
