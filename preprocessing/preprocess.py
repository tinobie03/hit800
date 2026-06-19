"""
preprocessing/preprocess.py
============================
Reads OneMoney_Training_v3_10k.csv from data/raw/,
cleans, scales, splits, and writes outputs to data/processed/.

Outputs
-------
data/processed/
  X_train.npy        training features  (numpy array)
  X_val.npy          validation features
  X_test.npy         test features
  y_train.npy        training labels (0=BENIGN, 1=ATTACK)
  y_val.npy          validation labels
  y_test.npy         test labels
  scaler.pkl         fitted StandardScaler
  feature_names.txt  ordered list of feature columns used
  class_weights.txt  class weight values for imbalanced training

Run
---
  python preprocessing/preprocess.py
"""

import os
import sys
import pickle
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from ids_core.features import FEATURES

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/preprocess.log", mode="w"),
    ]
)
log = logging.getLogger("preprocess")

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
RAW_DIR    = BASE_DIR / "data" / "raw"
PROC_DIR   = BASE_DIR / "data" / "processed"
PROC_DIR.mkdir(parents=True, exist_ok=True)

DATASET_FILE = RAW_DIR / "OneMoney_Training_v3_10k.csv"

# ── Config ─────────────────────────────────────────────────────────────────
TEST_SIZE  = 0.20   # 20% test
VAL_SIZE   = 0.10   # 10% validation (from remaining 80%)
RANDOM_SEED = 42


def load_data() -> pd.DataFrame:
    log.info(f"Loading base dataset: {DATASET_FILE}")
    if not DATASET_FILE.exists():
        log.error(f"Dataset not found at {DATASET_FILE}")
        log.error("Place OneMoney_Training_v3_10k.csv in data/raw/ and retry.")
        sys.exit(1)

    files = [DATASET_FILE, *sorted(RAW_DIR.glob("Live_*.csv"))]
    frames = []
    for path in files:
        frame = pd.read_csv(path)
        missing = [column for column in [*FEATURES, "Label"] if column not in frame.columns]
        if missing:
            raise ValueError(f"{path} is missing required columns: {missing}")
        frames.append(frame[[*FEATURES, "Label"]])
        log.info("  %s: %,d rows", path.name, len(frame))
    df = pd.concat(frames, ignore_index=True)
    log.info(f"Loaded {len(df):,} rows x {len(df.columns)} columns")

    label_counts = df["Label"].value_counts()
    for label, count in label_counts.items():
        log.info(f"  {label}: {count:,} rows  ({count/len(df)*100:.1f}%)")

    return df


def clean(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    log.info("Cleaning features...")

    # Verify all feature columns exist
    missing = [f for f in FEATURES if f not in df.columns]
    if missing:
        log.error(f"Missing columns in dataset: {missing}")
        sys.exit(1)

    X = df[FEATURES].copy()

    # Replace inf values
    inf_count = np.isinf(X.values).sum()
    if inf_count > 0:
        log.info(f"  Replacing {inf_count:,} inf values with NaN")
        X.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Fill NaN with column median
    nan_count = X.isna().sum().sum()
    if nan_count > 0:
        log.info(f"  Filling {nan_count:,} NaN values with column medians")
        X.fillna(X.median(), inplace=True)

    # Encode labels: ATTACK=1, BENIGN=0
    y = (df["Label"].str.upper() == "ATTACK").astype(int).values

    log.info(f"  Features shape : {X.shape}")
    log.info(f"  BENIGN (0)     : {(y==0).sum():,}")
    log.info(f"  ATTACK (1)     : {(y==1).sum():,}")

    return X.values.astype(np.float32), y


def split(X: np.ndarray, y: np.ndarray):
    log.info(f"Splitting: {int((1-TEST_SIZE-VAL_SIZE)*100)}% train / "
             f"{int(VAL_SIZE*100)}% val / {int(TEST_SIZE*100)}% test")

    # First split off test set
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    # Then split val from remaining
    val_ratio = VAL_SIZE / (1 - TEST_SIZE)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=val_ratio, random_state=RANDOM_SEED, stratify=y_tv
    )

    log.info(f"  Train : {len(X_train):,} rows")
    log.info(f"  Val   : {len(X_val):,}   rows")
    log.info(f"  Test  : {len(X_test):,}  rows")

    return X_train, X_val, X_test, y_train, y_val, y_test


def scale(X_train, X_val, X_test):
    log.info("Fitting StandardScaler on training set only...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)
    X_test  = scaler.transform(X_test)
    log.info(f"  Scaler mean range : [{scaler.mean_.min():.3f}, {scaler.mean_.max():.3f}]")
    log.info(f"  Scaler std  range : [{scaler.scale_.min():.3f}, {scaler.scale_.max():.3f}]")
    return X_train, X_val, X_test, scaler


def save_outputs(X_train, X_val, X_test, y_train, y_val, y_test, scaler):
    log.info(f"Saving outputs to {PROC_DIR}/")

    np.save(PROC_DIR / "X_train.npy", X_train)
    np.save(PROC_DIR / "X_val.npy",   X_val)
    np.save(PROC_DIR / "X_test.npy",  X_test)
    np.save(PROC_DIR / "y_train.npy", y_train)
    np.save(PROC_DIR / "y_val.npy",   y_val)
    np.save(PROC_DIR / "y_test.npy",  y_test)

    scaler_path = PROC_DIR / "scaler.pkl"
    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)

    feat_path = PROC_DIR / "feature_names.txt"
    with open(feat_path, "w") as f:
        f.write("\n".join(FEATURES))

    # Compute and save class weights (useful for imbalanced training)
    classes = np.array([0, 1])
    weights = compute_class_weight("balanced", classes=classes, y=y_train)
    cw_path = PROC_DIR / "class_weights.txt"
    with open(cw_path, "w") as f:
        f.write(f"BENIGN (0): {weights[0]:.4f}\n")
        f.write(f"ATTACK (1): {weights[1]:.4f}\n")

    log.info("  Saved files:")
    for p in sorted(PROC_DIR.iterdir()):
        size = p.stat().st_size
        log.info(f"    {p.name:<25}  {size/1024:.1f} KB")


def run_preprocessing(binary: bool = True):
    log.info("=" * 50)
    log.info("  OneMoney IDS — Preprocessing Pipeline")
    log.info("=" * 50)

    df = load_data()
    X, y = clean(df)
    X_train, X_val, X_test, y_train, y_val, y_test = split(X, y)
    X_train, X_val, X_test, scaler = scale(X_train, X_val, X_test)
    save_outputs(X_train, X_val, X_test, y_train, y_val, y_test, scaler)

    log.info("=" * 50)
    log.info("  Preprocessing complete.")
    log.info(f"  Input shape  : ({X_train.shape[1]},) features")
    log.info(f"  CNN input    : ({X_train.shape[1]}, 1) after reshape in training")
    log.info("=" * 50)


if __name__ == "__main__":
    run_preprocessing(binary=True)
