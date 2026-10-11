#!/usr/bin/env python3
"""
ML Model Training - NIDS Pipeline
Trains a Random Forest classifier to detect malicious network traffic.
Portfolio project - NIDS ML Pipeline
"""

import os
import json
import pickle
from datetime import datetime

import pandas as pd
from scapy.all import rdpcap, IP, TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

PCAP_FILE = "nids_ml/data/simulated_traffic.pcap"
MODEL_FILE = "nids_ml/models/nids_model.pkl"
METRICS_FILE = "nids_ml/logs/model_metrics.json"


def is_nimda_worm(packet):
    """Check if a packet carries the Nimda worm signature."""
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload)
        return b"GET /scripts/root.exe" in payload
    return False


def extract_features(packet):
    """
    Extract ML-friendly features from a single packet.
    Returns a dict of numeric features + label.
    """
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    features = {
        "packet_size": len(packet),
        "ttl": ip_layer.ttl,
        "ip_len": ip_layer.len,
        "protocol": ip_layer.proto,
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        features.update({
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "tcp_flags": int(tcp.flags),
            "payload_size": len(bytes(tcp.payload)),
        })
    else:
        features.update({
            "src_port": 0,
            "dst_port": 0,
            "tcp_flags": 0,
            "payload_size": 0,
        })

    # Label: 1 = malicious, 0 = normal
    features["label"] = 1 if is_nimda_worm(packet) else 0

    return features


def load_dataset(pcap_file):
    """Read packets from .pcap and convert to a pandas DataFrame."""
    if not os.path.exists(pcap_file):
        print(f"[-] Error: {pcap_file} not found.")
        print(f"    Run simulate_traffic.py first.")
        return None

    print(f"[*] Reading packets from {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Total packets: {len(packets)}")

    rows = []
    for packet in packets:
        features = extract_features(packet)
        if features:
            rows.append(features)

    df = pd.DataFrame(rows)
    print(f"[*] Extracted features from {len(df)} packets")
    print(f"[*] Malicious: {(df['label'] == 1).sum()}")
    print(f"[*] Normal:    {(df['label'] == 0).sum()}")

    return df


def train_model(df):
    """Train a Random Forest classifier and return metrics + model."""
    # Separate features and label
    X = df.drop("label", axis=1)
    y = df["label"]

    # Split into training (80%) and testing (20%)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\n[*] Training set: {len(X_train)} samples")
    print(f"[*] Test set:     {len(X_test)} samples")
    print(f"[*] Training Random Forest classifier...\n")

    # Train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42
    )
    model.fit(X_train, y_train)

    # Predict on the test set
    y_pred = model.predict(X_test)

    # Calculate metrics
    metrics = {
        "trained_at": datetime.now().isoformat(),
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, y_pred, zero_division=0), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "feature_importance": dict(zip(
            X.columns.tolist(),
            [round(v, 4) for v in model.feature_importances_.tolist()]
        ))
    }

    return model, metrics


def print_report(metrics):
    """Print a human-readable report."""
    print("=" * 55)
    print("MODEL PERFORMANCE REPORT")
    print("=" * 55)
    print(f"Accuracy:   {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision:  {metrics['precision'] * 100:.2f}%")
    print(f"Recall:     {metrics['recall'] * 100:.2f}%")
    print(f"F1 Score:   {metrics['f1_score'] * 100:.2f}%")
    print("\nConfusion Matrix:")
    print("                 Predicted")
    print("              Normal  Malicious")
    cm = metrics["confusion_matrix"]
    print(f"Actual Normal    {cm[0][0]:>4}    {cm[0][1]:>4}")
    print(f"       Malicious {cm[1][0]:>4}    {cm[1][1]:>4}")
    print("\nTop Feature Importances:")
    sorted_features = sorted(
        metrics["feature_importance"].items(),
        key=lambda x: x[1],
        reverse=True
    )
    for name, importance in sorted_features[:5]:
        print(f"  {name:<15} {importance * 100:.2f}%")
    print("=" * 55)


def save_model(model, metrics):
    """Save the trained model and metrics to disk."""
    os.makedirs(os.path.dirname(MODEL_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(METRICS_FILE), exist_ok=True)

    with open(MODEL_FILE, "wb") as f:
        pickle.dump(model, f)
    print(f"\n[+] Model saved to:   {MODEL_FILE}")

    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"[+] Metrics saved to: {METRICS_FILE}")


if __name__ == "__main__":
    df = load_dataset(PCAP_FILE)
    if df is None or df.empty:
        exit(1)

    model, metrics = train_model(df)
    print_report(metrics)
    save_model(model, metrics)
