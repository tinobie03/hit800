"""
evaluate.py
===========
Full evaluation of the trained CNN model.

Produces:
  - Accuracy, Precision, Recall, F1-score, False Positive Rate
  - Detection Latency (ms per sample)
  - Confusion matrix heatmap (logs/confusion_matrix.png)
  - Classification report
  - Comparison table vs baseline (Random Forest)

Run with:
  python -m model.evaluate
"""

import os
import time
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import tensorflow as tf
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/evaluate.log")
    ]
)

PROCESSED_DIR = "data/processed"
MODELS_DIR    = "data/models"
BEST_MODEL    = os.path.join(MODELS_DIR, "cnn_ids_best.h5")
RF_MODEL      = os.path.join(MODELS_DIR, "random_forest_baseline.pkl")


def load_test_data():
    X_test = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    y_test = np.load(os.path.join(PROCESSED_DIR, "y_test.npy"))
    return X_test, y_test


def compute_detection_latency(model, X_test, n_warmup: int = 10) -> float:
    """Measure average inference time per sample in milliseconds."""
    # Warm-up
    _ = model.predict(X_test[:n_warmup], verbose=0)

    start = time.perf_counter()
    _ = model.predict(X_test, verbose=0)
    elapsed_ms = (time.perf_counter() - start) * 1000
    latency_per_sample = elapsed_ms / len(X_test)
    return latency_per_sample


def false_positive_rate(y_true, y_pred) -> float:
    """FPR = FP / (FP + TN)"""
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        return fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return None


def plot_confusion_matrix(y_true, y_pred, title: str, save_path: str):
    cm = confusion_matrix(y_true, y_pred)
    labels = ["BENIGN", "ATTACK"]
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                xticklabels=labels, yticklabels=labels)
    plt.title(title)
    plt.xlabel("Predicted"); plt.ylabel("Actual")
    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close()
    log.info(f"Confusion matrix saved → {save_path}")


def train_rf_baseline(X_train, y_train):
    """Train a Random Forest baseline for comparison."""
    log.info("Training Random Forest baseline...")
    # RF needs 2D input — squeeze timestep dimension
    X_2d = X_train.reshape(X_train.shape[0], -1)
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_2d, y_train)
    joblib.dump(rf, RF_MODEL)
    log.info(f"RF model saved → {RF_MODEL}")
    return rf


def run_evaluation():
    os.makedirs("logs", exist_ok=True)

    # Load data
    X_test, y_test = load_test_data()
    X_train = np.load(os.path.join(PROCESSED_DIR, "X_train.npy"))
    y_train = np.load(os.path.join(PROCESSED_DIR, "y_train.npy"))

    # ── CNN Evaluation ──────────────────────────────────────
    log.info("Loading CNN model...")
    cnn = tf.keras.models.load_model(BEST_MODEL)

    y_pred_proba = cnn.predict(X_test, verbose=0)
    y_pred_cnn   = np.argmax(y_pred_proba, axis=1)

    cnn_latency = compute_detection_latency(cnn, X_test)

    cnn_metrics = {
        "Model"     : "CNN (Proposed)",
        "Accuracy"  : round(accuracy_score(y_test, y_pred_cnn), 4),
        "Precision" : round(precision_score(y_test, y_pred_cnn, zero_division=0), 4),
        "Recall"    : round(recall_score(y_test, y_pred_cnn, zero_division=0), 4),
        "F1-Score"  : round(f1_score(y_test, y_pred_cnn, zero_division=0), 4),
        "FPR"       : round(false_positive_rate(y_test, y_pred_cnn), 4),
        "ROC-AUC"   : round(roc_auc_score(y_test, y_pred_proba[:, 1]), 4),
        "Latency(ms/sample)": round(cnn_latency, 4),
    }

    plot_confusion_matrix(y_test, y_pred_cnn,
                          "CNN IDS — Confusion Matrix",
                          "logs/cnn_confusion_matrix.png")

    log.info("\nCNN Classification Report:\n" +
             classification_report(y_test, y_pred_cnn,
                                   target_names=["BENIGN", "ATTACK"]))

    # ── Random Forest Baseline ──────────────────────────────
    X_test_2d = X_test.reshape(X_test.shape[0], -1)

    if os.path.exists(RF_MODEL):
        rf = joblib.load(RF_MODEL)
    else:
        rf = train_rf_baseline(X_train, y_train)

    start = time.perf_counter()
    y_pred_rf = rf.predict(X_test_2d)
    rf_latency = ((time.perf_counter() - start) * 1000) / len(X_test)

    rf_metrics = {
        "Model"     : "Random Forest (Baseline)",
        "Accuracy"  : round(accuracy_score(y_test, y_pred_rf), 4),
        "Precision" : round(precision_score(y_test, y_pred_rf, zero_division=0), 4),
        "Recall"    : round(recall_score(y_test, y_pred_rf, zero_division=0), 4),
        "F1-Score"  : round(f1_score(y_test, y_pred_rf, zero_division=0), 4),
        "FPR"       : round(false_positive_rate(y_test, y_pred_rf), 4),
        "ROC-AUC"   : round(roc_auc_score(y_test, y_pred_rf), 4),
        "Latency(ms/sample)": round(rf_latency, 4),
    }

    plot_confusion_matrix(y_test, y_pred_rf,
                          "Random Forest — Confusion Matrix",
                          "logs/rf_confusion_matrix.png")

    # ── Comparison Table ────────────────────────────────────
    results = pd.DataFrame([cnn_metrics, rf_metrics])
    results_path = "logs/model_comparison.csv"
    results.to_csv(results_path, index=False)

    log.info("\n" + "=" * 60)
    log.info("MODEL COMPARISON")
    log.info("=" * 60)
    log.info("\n" + results.to_string(index=False))
    log.info("=" * 60)
    log.info(f"Results saved → {results_path}")


if __name__ == "__main__":
    run_evaluation()
