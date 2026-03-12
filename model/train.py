"""
train.py
========
Trains the CNN model on preprocessed CICIDS2017 data.

Run with:
  python -m model.train

Outputs:
  data/models/cnn_ids_best.h5   — best model weights
  data/models/cnn_ids_final.h5  — final model after all epochs
  logs/training_history.npy     — loss/accuracy arrays for plotting
"""

import os
import logging
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf
from model.cnn_model import build_cnn, get_callbacks

# ── Logging ──────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/train.log")
    ]
)
log = logging.getLogger(__name__)

# ── Config ───────────────────────────────────────────────
PROCESSED_DIR  = "data/processed"
MODELS_DIR     = "data/models"
BEST_MODEL     = os.path.join(MODELS_DIR, "cnn_ids_best.h5")
FINAL_MODEL    = os.path.join(MODELS_DIR, "cnn_ids_final.h5")
HISTORY_FILE   = "logs/training_history.npy"

EPOCHS         = 50
BATCH_SIZE     = 256
LEARNING_RATE  = 0.001
NUM_CLASSES    = 2       # 2 = binary (BENIGN / ATTACK)


def load_processed_data():
    """Load preprocessed numpy arrays from data/processed/."""
    log.info("Loading preprocessed data...")
    X_train = np.load(os.path.join(PROCESSED_DIR, "X_train.npy"))
    X_val   = np.load(os.path.join(PROCESSED_DIR, "X_val.npy"))
    X_test  = np.load(os.path.join(PROCESSED_DIR, "X_test.npy"))
    y_train = np.load(os.path.join(PROCESSED_DIR, "y_train.npy"))
    y_val   = np.load(os.path.join(PROCESSED_DIR, "y_val.npy"))
    y_test  = np.load(os.path.join(PROCESSED_DIR, "y_test.npy"))
    log.info(f"X_train: {X_train.shape} | X_val: {X_val.shape} | X_test: {X_test.shape}")
    return X_train, X_val, X_test, y_train, y_val, y_test


def plot_training_history(history, save_dir: str = "logs"):
    """Save loss and accuracy plots from training history."""
    os.makedirs(save_dir, exist_ok=True)
    hist = history.history

    # Loss curve
    plt.figure(figsize=(10, 4))
    plt.subplot(1, 2, 1)
    plt.plot(hist["loss"],     label="Train Loss")
    plt.plot(hist["val_loss"], label="Val Loss")
    plt.title("CNN Training Loss")
    plt.xlabel("Epoch"); plt.ylabel("Loss")
    plt.legend(); plt.grid(True)

    # Accuracy curve
    plt.subplot(1, 2, 2)
    plt.plot(hist["accuracy"],     label="Train Accuracy")
    plt.plot(hist["val_accuracy"], label="Val Accuracy")
    plt.title("CNN Training Accuracy")
    plt.xlabel("Epoch"); plt.ylabel("Accuracy")
    plt.legend(); plt.grid(True)

    plt.tight_layout()
    fig_path = os.path.join(save_dir, "training_curves.png")
    plt.savefig(fig_path, dpi=150)
    plt.close()
    log.info(f"Training curves saved → {fig_path}")


def run_training():
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Load data
    X_train, X_val, X_test, y_train, y_val, y_test = load_processed_data()

    # 2. Infer dimensions
    num_features = X_train.shape[2]   # shape is (samples, 1, features)
    log.info(f"num_features={num_features}  |  num_classes={NUM_CLASSES}")

    # 3. Build model
    model = build_cnn(num_features=num_features,
                      num_classes=NUM_CLASSES,
                      learning_rate=LEARNING_RATE)

    # 4. Class weights (handle any residual imbalance after SMOTE)
    unique, counts = np.unique(y_train, return_counts=True)
    total = len(y_train)
    class_weights = {int(k): total / (len(unique) * v)
                     for k, v in zip(unique, counts)}
    log.info(f"Class weights: {class_weights}")

    # 5. Train
    log.info("Starting training...")
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=EPOCHS,
        batch_size=BATCH_SIZE,
        class_weight=class_weights,
        callbacks=get_callbacks(BEST_MODEL),
        verbose=1
    )

    # 6. Save final model
    model.save(FINAL_MODEL)
    log.info(f"Final model saved → {FINAL_MODEL}")

    # 7. Save history
    np.save(HISTORY_FILE, history.history)
    log.info(f"Training history saved → {HISTORY_FILE}")

    # 8. Plot curves
    plot_training_history(history)

    # 9. Quick test-set evaluation
    log.info("Evaluating on test set...")
    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    log.info(f"Test Loss: {loss:.4f}  |  Test Accuracy: {acc:.4f}")

    log.info("Training complete.")
    return model, history


if __name__ == "__main__":
    run_training()
