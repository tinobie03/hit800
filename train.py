"""
train.py
=========
Loads preprocessed data from data/processed/, builds and trains
the 1D-CNN binary classifier, saves model and training artifacts
to model/ and logs/.

Architecture
------------
Input (76,1)
  → Conv1D(64, kernel=3, relu, same)
  → MaxPooling1D(2)
  → Dropout(0.3)
  → Conv1D(128, kernel=3, relu, same)
  → MaxPooling1D(2)
  → Dropout(0.3)
  → GlobalAveragePooling1D()
  → Dense(64, relu)
  → Dropout(0.4)
  → Dense(1, sigmoid)

Run
---
  python train.py
"""

import os
import sys
import json
import pickle
import logging
import time
import numpy as np
from pathlib import Path

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/train.log", mode="w"),
    ]
)
log = logging.getLogger("train")

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR  = Path(__file__).resolve().parent
PROC_DIR  = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "model"
LOG_DIR   = BASE_DIR / "logs"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── Hyperparameters ────────────────────────────────────────────────────────
EPOCHS      = 20
BATCH_SIZE  = 128
PATIENCE    = 4          # early stopping patience
LR          = 1e-3       # initial learning rate
THRESHOLD   = 0.5        # sigmoid decision threshold


def load_processed():
    log.info(f"Loading preprocessed data from {PROC_DIR}/")
    required = ["X_train.npy","X_val.npy","X_test.npy",
                "y_train.npy","y_val.npy","y_test.npy","scaler.pkl"]
    for f in required:
        if not (PROC_DIR / f).exists():
            log.error(f"Missing: {PROC_DIR / f}")
            log.error("Run  python preprocessing/preprocess.py  first.")
            sys.exit(1)

    X_train = np.load(PROC_DIR / "X_train.npy")
    X_val   = np.load(PROC_DIR / "X_val.npy")
    X_test  = np.load(PROC_DIR / "X_test.npy")
    y_train = np.load(PROC_DIR / "y_train.npy")
    y_val   = np.load(PROC_DIR / "y_val.npy")
    y_test  = np.load(PROC_DIR / "y_test.npy")

    log.info(f"  Train : {X_train.shape}  ATTACK={y_train.sum()}")
    log.info(f"  Val   : {X_val.shape}    ATTACK={y_val.sum()}")
    log.info(f"  Test  : {X_test.shape}   ATTACK={y_test.sum()}")

    # Read class weights
    cw_path = PROC_DIR / "class_weights.txt"
    class_weight = {0: 1.0, 1: 1.0}
    if cw_path.exists():
        lines = cw_path.read_text().strip().splitlines()
        class_weight[0] = float(lines[0].split(":")[1].strip())
        class_weight[1] = float(lines[1].split(":")[1].strip())
        log.info(f"  Class weights — BENIGN: {class_weight[0]:.4f}  ATTACK: {class_weight[1]:.4f}")

    return X_train, X_val, X_test, y_train, y_val, y_test, class_weight


def reshape_for_cnn(X_train, X_val, X_test):
    """Reshape (samples, features) → (samples, features, 1) for Conv1D."""
    return (
        X_train.reshape(-1, X_train.shape[1], 1),
        X_val.reshape(-1,   X_val.shape[1],   1),
        X_test.reshape(-1,  X_test.shape[1],  1),
    )


def build_model(input_length: int):
    import tensorflow as tf
    from tensorflow.keras import layers, models

    log.info(f"Building 1D-CNN  (input shape: ({input_length}, 1))")

    model = models.Sequential([
        layers.Input(shape=(input_length, 1)),

        # Block 1
        layers.Conv1D(64, kernel_size=3, activation="relu", padding="same"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),

        # Block 2
        layers.Conv1D(128, kernel_size=3, activation="relu", padding="same"),
        layers.MaxPooling1D(pool_size=2),
        layers.Dropout(0.3),

        # Classification head
        layers.GlobalAveragePooling1D(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.4),
        layers.Dense(1, activation="sigmoid"),
    ])

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=LR),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            tf.keras.metrics.AUC(name="auc"),
            tf.keras.metrics.Precision(name="precision"),
            tf.keras.metrics.Recall(name="recall"),
        ],
    )

    model.summary(print_fn=log.info)
    return model


def train(model, X_train, y_train, X_val, y_val, class_weight):
    import tensorflow as tf

    log.info(f"Training  (epochs={EPOCHS}, batch={BATCH_SIZE})")

    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_auc",
            patience=PATIENCE,
            restore_best_weights=True,
            mode="max",
            verbose=1,
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=2,
            min_lr=1e-6,
            verbose=1,
        ),
        tf.keras.callbacks.TensorBoard(
            log_dir=str(LOG_DIR / "tensorboard"),
            histogram_freq=1,
        ),
    ]

    t0 = time.time()
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weight,
        callbacks=callbacks,
        verbose=1,
    )
    elapsed = time.time() - t0
    log.info(f"Training finished in {elapsed:.1f}s  ({elapsed/60:.1f} min)")
    return history


def evaluate(model, X_test, y_test):
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 roc_auc_score, f1_score)

    log.info("Evaluating on held-out test set...")
    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob >= THRESHOLD).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    auc  = roc_auc_score(y_test, y_prob)
    f1   = f1_score(y_test, y_pred)
    acc  = (tp + tn) / len(y_test)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    report = classification_report(
        y_test, y_pred, target_names=["BENIGN", "ATTACK"], digits=4
    )

    log.info("\n" + "─" * 55)
    log.info("  EVALUATION RESULTS")
    log.info("─" * 55)
    log.info(f"  Accuracy         : {acc:.4f}  ({acc*100:.2f}%)")
    log.info(f"  Attack Recall    : {recall:.4f}  (detection rate)")
    log.info(f"  False Pos Rate   : {fpr*100:.2f}%")
    log.info(f"  F1 Score         : {f1:.4f}")
    log.info(f"  ROC-AUC          : {auc:.4f}")
    log.info(f"  Confusion Matrix : TN={tn}  FP={fp}  FN={fn}  TP={tp}")
    log.info("─" * 55)
    log.info("\n" + report)

    # Save evaluation results as JSON for the API to serve
    results = {
        "accuracy":       round(acc,    4),
        "attack_recall":  round(recall, 4),
        "false_pos_rate": round(fpr,    4),
        "f1_score":       round(f1,     4),
        "roc_auc":        round(auc,    4),
        "confusion_matrix": {"TN": int(tn), "FP": int(fp),
                              "FN": int(fn), "TP": int(tp)},
        "threshold":      THRESHOLD,
        "test_samples":   len(y_test),
    }
    eval_path = LOG_DIR / "evaluate.json"
    with open(eval_path, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"  Evaluation results saved → {eval_path}")

    return results


def save_model(model, history):
    model_path = MODEL_DIR / "onemoney_cnn.h5"
    model.save(str(model_path))
    log.info(f"Model saved → {model_path}")

    # Save training history
    hist_path = LOG_DIR / "training_history.json"
    with open(hist_path, "w") as f:
        json.dump({k: [float(v) for v in vals]
                   for k, vals in history.history.items()}, f, indent=2)
    log.info(f"Training history saved → {hist_path}")

    # Also copy scaler next to model for easy access by inference service
    import shutil
    scaler_src = PROC_DIR / "scaler.pkl"
    scaler_dst = MODEL_DIR / "scaler.pkl"
    shutil.copy(scaler_src, scaler_dst)
    log.info(f"Scaler copied → {scaler_dst}")


def plot_training(history):
    """Save training curves as PNG (optional — requires matplotlib)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        fig.suptitle("Training History — OneMoney 1D-CNN", fontsize=13)

        for ax, metric, title in [
            (axes[0], ("loss", "val_loss"),         "Loss"),
            (axes[1], ("auc",  "val_auc"),           "AUC"),
        ]:
            for key, label, color in [
                (metric[0], "Train", "#1D9E75"),
                (metric[1], "Val",   "#E24B4A"),
            ]:
                if key in history.history:
                    ax.plot(history.history[key], label=label, color=color, linewidth=2)
            ax.set_title(title)
            ax.set_xlabel("Epoch")
            ax.legend()
            ax.grid(alpha=0.3)

        plt.tight_layout()
        out = LOG_DIR / "training_curves.png"
        plt.savefig(out, dpi=150, bbox_inches="tight")
        plt.close()
        log.info(f"Training curves saved → {out}")
    except ImportError:
        log.info("matplotlib not installed — skipping training curve plot")


if __name__ == "__main__":
    log.info("=" * 55)
    log.info("  OneMoney IDS — CNN Training")
    log.info("=" * 55)

    # 1. Load
    X_train, X_val, X_test, y_train, y_val, y_test, class_weight = load_processed()

    # 2. Reshape for Conv1D
    X_train, X_val, X_test = reshape_for_cnn(X_train, X_val, X_test)
    log.info(f"Reshaped → train:{X_train.shape}  val:{X_val.shape}  test:{X_test.shape}")

    # 3. Build
    model = build_model(input_length=X_train.shape[1])

    # 4. Train
    history = train(model, X_train, y_train, X_val, y_val, class_weight)

    # 5. Evaluate
    evaluate(model, X_test, y_test)

    # 6. Save
    save_model(model, history)
    plot_training(history)

    log.info("=" * 55)
    log.info("  Done. Model ready at model/onemoney_cnn.h5")
    log.info("=" * 55)