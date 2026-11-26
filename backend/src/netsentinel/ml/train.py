"""CLI training and evaluation harness (leakage-free splits, full security metrics)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder

from netsentinel.ml.features import FEATURE_COLUMNS, feature_schema_hash, normalize_attack_label
from netsentinel.ml.models import (
    DetectionBundle,
    build_isolation_forest_pipeline,
    build_supervised_pipeline,
    compute_anomaly_scores,
)


def evaluate_bundle(
    bundle: DetectionBundle,
    X_test: np.ndarray,
    y_test_labels: list[str],
) -> dict[str, Any]:
    y_true = bundle.label_encoder.transform(y_test_labels)
    probs = bundle.sup_pipeline.predict_proba(X_test)
    y_pred = np.argmax(probs, axis=1)

    benign_idx = (
        int(bundle.label_encoder.transform(["benign"])[0])
        if "benign" in bundle.label_encoder.classes_
        else 0
    )
    y_true_bin = (y_true != benign_idx).astype(int)
    attack_prob = 1.0 - probs[:, benign_idx]

    benign_mask = y_true_bin == 0
    fp = int(np.sum((y_pred != benign_idx) & benign_mask))
    tn = int(np.sum((y_pred == benign_idx) & benign_mask))
    fpr = fp / max(fp + tn, 1)

    iso_scores = compute_anomaly_scores(bundle.iso_pipeline, X_test)

    metrics: dict[str, Any] = {
        "precision_weighted": round(float(precision_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "recall_weighted": round(float(recall_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        "fpr": round(float(fpr), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "classes": bundle.label_encoder.classes_.tolist(),
        "feature_schema_hash": feature_schema_hash(),
    }
    if len(np.unique(y_true_bin)) > 1:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true_bin, attack_prob)), 4)
        metrics["pr_auc"] = round(float(average_precision_score(y_true_bin, attack_prob)), 4)
        metrics["iso_roc_auc"] = round(float(roc_auc_score(y_true_bin, iso_scores)), 4)
    return metrics


def train_from_dataframe(
    df: pd.DataFrame,
    *,
    label_col: str = "Label",
    algorithm: str = "xgboost",
    output_dir: str = "./artifacts",
) -> dict[str, Any]:
    """Time/order-preserving 70/15/15 split to prevent temporal data leakage."""
    clean = df.copy()
    clean.columns = [c.strip() for c in clean.columns]
    clean = clean.replace([np.inf, -np.inf], np.nan)
    for col in FEATURE_COLUMNS:
        if col not in clean.columns:
            clean[col] = 0.0
    clean["canonical_label"] = clean[label_col].astype(str).map(normalize_attack_label)

    n = len(clean)
    n_train = int(n * 0.70)
    n_val = int(n * 0.85)
    train_df = clean.iloc[:n_train]
    val_df = clean.iloc[n_train:n_val]
    test_df = clean.iloc[n_val:]

    le = LabelEncoder()
    y_train = le.fit_transform(train_df["canonical_label"])
    X_train = train_df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    X_train_benign = train_df[train_df["canonical_label"] == "benign"][FEATURE_COLUMNS].to_numpy(
        dtype=np.float64
    )

    iso = build_isolation_forest_pipeline()
    iso.fit(X_train_benign if len(X_train_benign) > 10 else X_train)

    sup = build_supervised_pipeline(algorithm="xgboost" if algorithm == "xgboost" else "random_forest")
    sup.fit(X_train, y_train)

    # Calibrate anomaly threshold on validation benign traffic targeting FPR <= 3%
    val_benign = val_df[val_df["canonical_label"] == "benign"][FEATURE_COLUMNS].to_numpy(
        dtype=np.float64
    )
    threshold = 0.60
    if len(val_benign) >= 20:
        val_scores = compute_anomaly_scores(iso, val_benign)
        threshold = float(np.quantile(val_scores, 0.97))

    bundle = DetectionBundle(
        iso_pipeline=iso,
        sup_pipeline=sup,
        label_encoder=le,
        anomaly_threshold=round(threshold, 4),
    )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    artifact_file = out_path / f"netsentinel_{algorithm}_bundle.joblib"
    bundle.save(str(artifact_file))

    known_test = test_df[test_df["canonical_label"].isin(set(le.classes_))]
    X_test = known_test[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
    metrics = evaluate_bundle(bundle, X_test, known_test["canonical_label"].tolist())
    metrics["artifact_path"] = str(artifact_file)
    metrics["anomaly_threshold"] = bundle.anomaly_threshold
    (out_path / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train NetSentinel AI ML detection bundle")
    parser.add_argument("--csv", required=True, help="Path to labeled flow CSV (e.g. CIC-IDS2017)")
    parser.add_argument("--label-col", default="Label")
    parser.add_argument("--algorithm", choices=["xgboost", "random_forest"], default="xgboost")
    parser.add_argument("--output-dir", default="./artifacts")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    metrics = train_from_dataframe(
        df, label_col=args.label_col, algorithm=args.algorithm, output_dir=args.output_dir
    )
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
