#!/usr/bin/env python3
"""
classifier.py
=============
PQCRecon — TLS 1.3 Session Classifier
======================================
Trains and evaluates a Decision Tree classifier for TLS 1.3 sessions.

ARCHITECTURE PHILOSOPHY:
  - COMPREHENSIVE TRAINING: The model is trained on a "Registry Ground Truth" 
    dataset generated directly from the lookup tables (IANA/NIST), ensuring 
    every known PQC algorithm is covered regardless of whether it's in the PCAPs.
  - PRIMARY discriminators: IANA group IDs (ke_pqc) and NIST OIDs (cert_pqc).
  - SECONDARY: Byte-size features and chain length.

Usage:
    python3 classification/classifier.py --train feature-extract/training_data.csv
"""

import argparse
import os
import sys
import warnings
from pathlib import Path
from typing import Optional, Dict, Any, List

import joblib
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier, plot_tree

warnings.filterwarnings("ignore")
matplotlib.use("Agg")  # Headless backend

# ---------------------------------------------------------------------------
# Default Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent

DEFAULT_TRAIN_CSV = PROJECT_ROOT / "feature-extract" / "training_data.csv"
MODEL_PATH = SCRIPT_DIR / "pqcrecon_model.pkl"
LOOKUPS_PATH = SCRIPT_DIR / "pqcrecon_lookups.pkl"
TREE_PNG_PATH = SCRIPT_DIR / "decision_tree.png"

# ---------------------------------------------------------------------------
# Authoritative Registry Metadata (for Comprehensive Training)
# ---------------------------------------------------------------------------

KEM_METADATA = {
    # PQC Hybrids (Final FIPS 203)
    0x11eb: {"name": "X25519MLKEM512",     "pqc": True,  "size": 832},
    0x11ec: {"name": "X25519MLKEM768",     "pqc": True,  "size": 1220},
    0x11ed: {"name": "SecP256r1MLKEM768",  "pqc": True,  "size": 1216},
    0x11ee: {"name": "SecP384r1MLKEM1024", "pqc": True,  "size": 1600},
    
    # PQC Hybrids (Draft Kyber)
    0x6399: {"name": "X25519Kyber768Draft", "pqc": True,  "size": 1220},
    0x639a: {"name": "P256Kyber768Draft",   "pqc": True,  "size": 1216},
    0x639b: {"name": "X25519Kyber512Draft", "pqc": True,  "size": 832},
    0x639c: {"name": "P256Kyber512Draft",   "pqc": True,  "size": 832},

    # Pure PQC
    0x0200: {"name": "ML-KEM-512",      "pqc": True,  "size": 800},
    0x0201: {"name": "ML-KEM-768",      "pqc": True,  "size": 1184},
    0x0202: {"name": "ML-KEM-1024",     "pqc": True,  "size": 1568},

    # Classical
    0x001d: {"name": "X25519",          "pqc": False, "size": 32},
    0x0017: {"name": "SecP256r1",       "pqc": False, "size": 65},
    0x0018: {"name": "SecP384r1",       "pqc": False, "size": 97},
}

CERT_METADATA = {
    # ML-DSA
    "2.16.840.1.101.3.4.3.17": {"name": "ML-DSA-44",   "pqc": True,  "pubkey": 1312, "sig": 2420},
    "2.16.840.1.101.3.4.3.18": {"name": "ML-DSA-65",   "pqc": True,  "pubkey": 1952, "sig": 3309},
    "2.16.840.1.101.3.4.3.19": {"name": "ML-DSA-87",   "pqc": True,  "pubkey": 2592, "sig": 4627},
    # SLH-DSA
    "2.16.840.1.101.3.4.3.20": {"name": "SLH-DSA-128s","pqc": True,  "pubkey": 32,   "sig": 8080},
    "2.16.840.1.101.3.4.3.21": {"name": "SLH-DSA-128f","pqc": True,  "pubkey": 32,   "sig": 17088},
    "2.16.840.1.101.3.4.3.26": {"name": "SLH-DSA-128s-SHAKE", "pqc": True, "pubkey": 32, "sig": 8080},
    # Classical
    "1.2.840.113549.1.1.11":   {"name": "RSA-2048",    "pqc": False, "pubkey": 270,  "sig": 256},
    "1.2.840.10045.4.3.2":     {"name": "ECDSA-P256",  "pqc": False, "pubkey": 65,   "sig": 71},
    "1.3.101.112":             {"name": "Ed25519",     "pqc": False, "pubkey": 32,   "sig": 64},
}

PQC_KEM_GROUP_IDS = {k for k, v in KEM_METADATA.items() if v["pqc"]}
CLASSICAL_KEM_GROUP_IDS = {k for k, v in KEM_METADATA.items() if not v["pqc"]}

PQC_CERT_OIDS = {k for k, v in CERT_METADATA.items() if v["pqc"]}
CLASSICAL_CERT_OIDS = {k for k, v in CERT_METADATA.items() if not v["pqc"]}

FEATURE_NAMES = [
    "ke_pqc",
    "cert_pqc",
    "key_share_size",
    "leaf_cert_pubkey_size",
    "leaf_cert_sig_size",
    "cert_chain_length"
]

# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Transform raw data into the feature matrix X."""
    df = df.copy()

    def parse_hex(val):
        if pd.isna(val): return None
        if isinstance(val, (int, np.integer)): return int(val)
        s = str(val).strip()
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError:
            return None

    df["group_id"] = df["supported_group_id"].apply(parse_hex)
    
    size_cols = ["key_share_size", "leaf_cert_pubkey_size", "leaf_cert_sig_size", "cert_chain_length"]
    for col in size_cols:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    # These binary flags are the PRIMARY discriminators. 
    # Because they use the lookup sets, they generalize to algorithms not in training_data.csv.
    df["ke_pqc"] = df["group_id"].apply(lambda g: 1 if g in PQC_KEM_GROUP_IDS else 0)
    df["cert_pqc"] = df["leaf_cert_oid"].apply(lambda o: 1 if str(o).strip() in PQC_CERT_OIDS else 0)

    return df[FEATURE_NAMES]

def derive_label(ke_pqc: int, cert_pqc: int) -> str:
    if ke_pqc == 0 and cert_pqc == 0: return "Classical"
    if ke_pqc == 1 and cert_pqc == 0: return "KE-PQC"
    if ke_pqc == 0 and cert_pqc == 1: return "Cert-PQC"
    return "Full-PQC"

# ---------------------------------------------------------------------------
# Comprehensive Data Generation
# ---------------------------------------------------------------------------

def generate_registry_ground_truth() -> pd.DataFrame:
    """
    Creates a comprehensive training dataset covering ALL possible combinations
    of KEMs and Certificates in our authoritative lookup tables.
    """
    rows = []
    for kem_id, kem_info in KEM_METADATA.items():
        for cert_oid, cert_info in CERT_METADATA.items():
            label = derive_label(1 if kem_info["pqc"] else 0, 1 if cert_info["pqc"] else 0)
            rows.append({
                "supported_group_id": hex(kem_id),
                "leaf_cert_oid": cert_oid,
                "key_share_size": kem_info["size"],
                "leaf_cert_pubkey_size": cert_info["pubkey"],
                "leaf_cert_sig_size": cert_info["sig"],
                "cert_chain_length": 1,
                "label": label,
                "filename": f"SYNTHETIC_{kem_info['name']}_{cert_info['name']}"
            })
    return pd.DataFrame(rows)

# ---------------------------------------------------------------------------
# Core Logic
# ---------------------------------------------------------------------------

def run_train(csv_path: Optional[Path]):
    print("\n[TRAIN] Building Comprehensive Registry Dataset...")
    df_registry = generate_registry_ground_truth()
    
    if csv_path and csv_path.exists():
        print(f"  + Merging real-world data from {csv_path}...")
        df_real = pd.read_csv(csv_path)
        # Combine synthetic + real data to ensure maximum coverage and real-world noise handling
        df_combined = pd.concat([df_registry, df_real], ignore_index=True)
    else:
        print("  [INFO] No real training data found. Training on Registry Ground Truth only.")
        df_combined = df_registry

    X = engineer_features(df_combined)
    y = df_combined["label"]

    # max_depth=4 is enough to learn the 4-class registry mapping perfectly
    clf = DecisionTreeClassifier(random_state=42, max_depth=4)
    clf.fit(X, y)

    joblib.dump(clf, MODEL_PATH)
    joblib.dump({
        "PQC_KEM_GROUP_IDS": PQC_KEM_GROUP_IDS,
        "PQC_CERT_OIDS": PQC_CERT_OIDS
    }, LOOKUPS_PATH)
    
    print(f"  ✓ Model trained on {len(df_combined)} rows and saved to {MODEL_PATH}")
    
    print("\n  FEATURE IMPORTANCES:")
    imps = clf.feature_importances_
    for name, imp in sorted(zip(FEATURE_NAMES, imps), key=lambda x: x[1], reverse=True):
        print(f"    {name:<25}: {imp:.4f}")

    plt.figure(figsize=(15, 8))
    plot_tree(clf, feature_names=FEATURE_NAMES, class_names=clf.classes_, filled=True, rounded=True)
    plt.savefig(TREE_PNG_PATH, dpi=200)
    print(f"  ✓ Updated tree visualization saved to {TREE_PNG_PATH}")
    return clf

def run_test(csv_path: Path):
    if not MODEL_PATH.exists():
        print(f"  [ERROR] No trained model found. Run training first.")
        return

    print(f"\n[TEST] Evaluating data from {csv_path}...")
    clf = joblib.load(MODEL_PATH)
    df_raw = pd.read_csv(csv_path)
    X = engineer_features(df_raw)
    y_true = df_raw["label"]
    y_pred = clf.predict(X)

    print("\n  CLASSIFICATION REPORT:")
    print(classification_report(y_true, y_pred))
    acc = (y_true == y_pred).mean() * 100
    print(f"  FINAL ACCURACY: {acc:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQCRecon Classifier")
    parser.add_argument("--train", type=Path, help="Path to training CSV")
    parser.add_argument("--test", type=Path, help="Path to test CSV")
    args = parser.parse_args()

    try:
        # Default behavior: Always train on comprehensive registry + local csv if it exists
        train_path = args.train if args.train else (DEFAULT_TRAIN_CSV if DEFAULT_TRAIN_CSV.exists() else None)
        run_train(train_path)
        
        # If test specified, or if we just trained on the default csv, run a self-test report
        if args.test:
            run_test(args.test)
        elif train_path:
            run_test(train_path)
    except Exception as e:
        print(f"\n[FATAL ERROR] {e}")
        sys.exit(1)
