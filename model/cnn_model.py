"""
cnn_model.py
============
Defines the 1D-CNN architecture for intrusion detection.

Architecture (matches your journal paper, Figure 2):
  Input (1, num_features)
    → Conv1D(64, kernel=3, padding='same') + ReLU
    → Conv1D(128, kernel=3, padding='same') + ReLU
    → MaxPooling1D(pool_size=1)
    → Dropout(0.3)
    → Flatten
    → Dense(128, ReLU)
    → Dropout(0.3)
    → Dense(num_classes, Softmax)

For binary classification: num_classes = 2
"""

import tensorflow as tf
from tensorflow.keras import Sequential, Input
from tensorflow.keras.layers import (
    Conv1D, MaxPooling1D, Flatten, Dense, Dropout, BatchNormalization
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import (
    EarlyStopping, ModelCheckpoint, ReduceLROnPlateau, TensorBoard
)
import logging
import os

log = logging.getLogger(__name__)


def build_cnn(num_features: int, num_classes: int = 2,
              learning_rate: float = 0.001) -> tf.keras.Model:
    """
    Build and compile the 1D-CNN model.

    Args:
        num_features : Number of input features (columns after preprocessing)
        num_classes  : 2 for binary (BENIGN/ATTACK), >2 for multi-class
        learning_rate: Adam optimizer learning rate

    Returns:
        Compiled Keras model
    """
    model = Sequential([
        Input(shape=(1, num_features)),                    # (timestep=1, features)

        # ── Block 1 ─────────────────────────────────────
        Conv1D(filters=64, kernel_size=1,
               activation="relu", padding="same",
               name="conv1"),
        BatchNormalization(name="bn1"),

        # ── Block 2 ─────────────────────────────────────
        Conv1D(filters=128, kernel_size=1,
               activation="relu", padding="same",
               name="conv2"),
        BatchNormalization(name="bn2"),
        MaxPooling1D(pool_size=1, name="pool"),
        Dropout(0.3, name="dropout1"),

        # ── Classifier head ─────────────────────────────
        Flatten(name="flatten"),
        Dense(128, activation="relu", name="dense1"),
        Dropout(0.3, name="dropout2"),
        Dense(num_classes, activation="softmax", name="output"),
    ], name="CNN_IDS")

    model.compile(
        optimizer=Adam(learning_rate=learning_rate),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )

    log.info("CNN model built:")
    model.summary(print_fn=log.info)
    return model


def get_callbacks(model_save_path: str, log_dir: str = "logs/tensorboard"):
    """
    Return standard training callbacks.
    - EarlyStopping     : stop if val_loss doesn't improve for 5 epochs
    - ModelCheckpoint   : save best weights automatically
    - ReduceLROnPlateau : halve LR if val_loss stalls for 3 epochs
    - TensorBoard       : training curves (optional: tensorboard --logdir logs/tensorboard)
    """
    os.makedirs(log_dir, exist_ok=True)
    return [
        EarlyStopping(
            monitor="val_loss", patience=5,
            restore_best_weights=True, verbose=1
        ),
        ModelCheckpoint(
            filepath=model_save_path,
            monitor="val_loss", save_best_only=True, verbose=1
        ),
        ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=3,
            min_lr=1e-6, verbose=1
        ),
        TensorBoard(log_dir=log_dir, histogram_freq=1)
    ]
