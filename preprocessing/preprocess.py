"""
preprocess.py
=============
Loads and preprocesses the CICIDS2017 dataset for CNN training.

Steps:
  1. Load all CSV files from data/raw/
  2. Clean: drop nulls, infinite values, duplicate rows
  3. Encode labels (BENIGN=0, all attacks=1 for binary; or multi-class)
  4. Normalize features with MinMaxScaler
  5. Handle class imbalance with SMOTE
  6. Reshape into (samples, 1, features) tensors for 1D-CNN
  7. Save processed arrays and scaler to data/processed/

Usage:
  python -m preprocessing.preprocess
"""

import os
import glob
import logging
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from imblearn.over_sampling import SMOTE
from tqdm import tqdm

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/preprocess.log")
    ]
)
log = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────
RAW_DIR       = "data/raw"
PROCESSED_DIR = "data/processed"
SCALER_PATH   = os.path.join(PROCESSED_DIR, "scaler.pkl")
ENCODER_PATH  = os.path.join(PROCESSED_DIR, "label_encoder.pkl")

# ── CICIDS2017 label mapping ───────────────────────────────
# All non-BENIGN rows are attacks (binary classification)
BINARY_MAP = {
    "BENIGN": 0,
    # Everything else maps to 1 (attack) — handled in code
}

# Multi-class labels present in CICIDS2017
ATTACK_LABELS = [
    "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye",
    "FTP-Patator", "SSH-Patator", "DoS slowloris",
    "DoS Slowhttptest", "Bot", "Web Attack – Brute Force",
    "Web Attack – XSS", "Infiltration",
    "Web Attack – Sql Injection", "Heartbleed"
]

# Columns to drop (non-feature)
DROP_COLS = [" Destination Port", "Flow ID", " Source IP",
             " Source Port", " Destination IP", " Timestamp"]


def load_raw_csvs(raw_dir: str) -> pd.DataFrame:
    """Load all CICIDS2017 CSV files from raw_dir into one DataFrame."""
    csv_files = glob.glob(os.path.join(raw_dir, "*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{raw_dir}'.\n"
            "Please download CICIDS2017 from:\n"
            "  https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "and place the CSV files in data/raw/"
        )
    log.info(f"Found {len(csv_files)} CSV file(s) in {raw_dir}")
    frames = []
    for f in tqdm(csv_files, desc="Loading CSVs"):
        df = pd.read_csv(f, low_memory=False)
        frames.append(df)
        log.info(f"  Loaded {f}: {df.shape}")
    combined = pd.concat(frames, ignore_index=True)
    log.info(f"Combined dataset shape: {combined.shape}")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Remove nulls, infinite values, duplicates, and useless columns."""
    log.info("Cleaning dataset...")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Drop non-feature columns that exist
    cols_to_drop = [c for c in DROP_COLS if c.strip() in df.columns]
    df = df.drop(columns=cols_to_drop, errors="ignore")

    initial_rows = len(df)

    # Replace infinite values with NaN then drop
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    # Drop duplicate rows
    df = df.drop_duplicates()

    log.info(f"Rows after cleaning: {len(df)} (removed {initial_rows - len(df)})")
    return df


def encode_labels(df: pd.DataFrame, binary: bool = True):
    """
    Encode the Label column.
    binary=True  → BENIGN=0, any attack=1
    binary=False → multi-class integer encoding
    """
    label_col = "Label"
    if label_col not in df.columns:
        raise ValueError("Column 'Label' not found. Check your dataset.")

    if binary:
        df["label_encoded"] = df[label_col].apply(
            lambda x: 0 if str(x).strip().upper() == "BENIGN" else 1
        )
        log.info(f"Binary label distribution:\n{df['label_encoded'].value_counts()}")
        return df, None
    else:
        le = LabelEncoder()
        df["label_encoded"] = le.fit_transform(df[label_col].str.strip())
        log.info(f"Multi-class labels: {list(le.classes_)}")
        return df, le


def scale_features(X_train, X_val, X_test):
    """Fit MinMaxScaler on training set, apply to all splits."""
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)
    X_test  = scaler.transform(X_test)
    log.info("Features scaled with MinMaxScaler.")
    return X_train, X_val, X_test, scaler


def apply_smote(X_train, y_train):
    """Apply SMOTE to oversample minority attack class."""
    log.info(f"Before SMOTE — class distribution: {np.bincount(y_train)}")
    sm = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X_train, y_train)
    log.info(f"After SMOTE  — class distribution: {np.bincount(y_res)}")
    return X_res, y_res


def reshape_for_cnn(X):
    """Reshape 2D (samples, features) → 3D (samples, 1, features) for 1D-CNN."""
    return X.reshape(X.shape[0], 1, X.shape[1])


def run_preprocessing(binary: bool = True):
    """Full preprocessing pipeline. Call this to prepare data for training."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    # 1. Load
    df = load_raw_csvs(RAW_DIR)

    # 2. Clean
    df = clean(df)

    # 3. Encode labels
    df, label_encoder = encode_labels(df, binary=binary)

    # 4. Split features / labels
    feature_cols = [c for c in df.columns if c not in ["Label", "label_encoded"]]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label_encoded"].values.astype(np.int32)

    log.info(f"Feature matrix shape: {X.shape} | Labels shape: {y.shape}")

    # 5. Train / Val / Test split  (70 / 15 / 15)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    # 6. Scale
    X_train, X_val, X_test, scaler = scale_features(X_train, X_val, X_test)

    # 7. SMOTE on training set only
    X_train, y_train = apply_smote(X_train, y_train)

    # 8. Reshape for CNN  (samples, 1, features)
    X_train = reshape_for_cnn(X_train)
    X_val   = reshape_for_cnn(X_val)
    X_test  = reshape_for_cnn(X_test)

    # 9. Save to disk
    np.save(os.path.join(PROCESSED_DIR, "X_train.npy"), X_train)
    np.save(os.path.join(PROCESSED_DIR, "X_val.npy"),   X_val)
    np.save(os.path.join(PROCESSED_DIR, "X_test.npy"),  X_test)
    np.save(os.path.join(PROCESSED_DIR, "y_train.npy"), y_train)
    np.save(os.path.join(PROCESSED_DIR, "y_val.npy"),   y_val)
    np.save(os.path.join(PROCESSED_DIR, "y_test.npy"),  y_test)
    np.save(os.path.join(PROCESSED_DIR, "feature_cols.npy"),
            np.array(feature_cols))

    joblib.dump(scaler, SCALER_PATH)
    if label_encoder:
        joblib.dump(label_encoder, ENCODER_PATH)

    log.info("=" * 50)
    log.info("Preprocessing complete.")
    log.info(f"  Train : {X_train.shape}  |  y_train: {y_train.shape}")
    log.info(f"  Val   : {X_val.shape}    |  y_val:   {y_val.shape}")
    log.info(f"  Test  : {X_test.shape}   |  y_test:  {y_test.shape}")
    log.info(f"  Scaler saved → {SCALER_PATH}")
    log.info("=" * 50)

    return X_train, X_val, X_test, y_train, y_val, y_test, scaler


if __name__ == "__main__":
    run_preprocessing(binary=True)
