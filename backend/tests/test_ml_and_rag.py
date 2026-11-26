"""Unit tests for ML epistemic discipline, leakage-free training, and Hybrid RAG RRF/eval."""

from __future__ import annotations

import tempfile

import numpy as np
import pandas as pd

from netsentinel.ml.features import FEATURE_COLUMNS
from netsentinel.ml.models import resolve_classification_tier
from netsentinel.ml.train import train_from_dataframe
from netsentinel.rag.retriever import reciprocal_rank_fusion


def test_unsupervised_anomaly_never_returns_confirmed_malicious():
    tier = resolve_classification_tier(
        anomaly_score=0.99,
        anomaly_threshold=0.60,
        predicted_class="benign",
        supervised_confidence=0.95,
    )
    assert tier == "anomalous"

    susp = resolve_classification_tier(
        anomaly_score=0.20,
        anomaly_threshold=0.60,
        predicted_class="port_scan",
        supervised_confidence=0.88,
    )
    assert susp == "suspicious"


def test_ml_training_harness_metrics():
    rng = np.random.default_rng(7)
    rows = []
    for i in range(120):
        is_attack = i % 3 == 0
        row = {c: float(rng.uniform(1, 10)) for c in FEATURE_COLUMNS}
        if is_attack:
            row["syn_flag_count"] = float(rng.uniform(80, 200))
            row["flow_pkts_per_sec"] = float(rng.uniform(500, 1500))
            row["Label"] = "PortScan"
        else:
            row["Label"] = "BENIGN"
        rows.append(row)

    df = pd.DataFrame(rows)
    with tempfile.TemporaryDirectory() as tmpdir:
        metrics = train_from_dataframe(df, algorithm="random_forest", output_dir=tmpdir)
        assert "macro_f1" in metrics
        assert "pr_auc" in metrics
        assert "roc_auc" in metrics
        assert "fpr" in metrics
        assert "confusion_matrix" in metrics


def test_reciprocal_rank_fusion_combines_dense_and_lexical():
    dense = {"doc_a": 1, "doc_b": 2, "doc_c": 3}
    lexical = {"doc_b": 1, "doc_d": 2}
    fused = reciprocal_rank_fusion(dense, lexical, k=60)
    assert fused["doc_b"] > fused["doc_a"]
    assert fused["doc_b"] > fused["doc_d"]
