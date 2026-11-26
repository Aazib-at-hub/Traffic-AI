"""Isolation Forest, XGBoost/RandomForest classifiers, SHAP explainability, and tier resolver."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, RobustScaler

from netsentinel.ml.features import FEATURE_COLUMNS

ClassificationTier = Literal["benign", "anomalous", "suspicious"]


def resolve_classification_tier(
    *,
    anomaly_score: float,
    anomaly_threshold: float,
    predicted_class: str,
    supervised_confidence: float,
    supervised_threshold: float = 0.65,
) -> ClassificationTier:
    """Deterministic epistemic tier resolver.

    CRITICAL INVARIANT (SRS FR-012):
    - Unsupervised anomaly alone can ONLY produce 'anomalous', NEVER 'confirmed_malicious'.
    - Supervised attack classification above threshold produces 'suspicious'.
    - Automated ML pipelines NEVER emit 'confirmed_malicious'.
    """
    if predicted_class != "benign" and supervised_confidence >= supervised_threshold:
        return "suspicious"
    if anomaly_score >= anomaly_threshold:
        return "anomalous"
    return "benign"


def build_isolation_forest_pipeline(random_state: int = 42) -> Pipeline:
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=100,
                    contamination=0.05,
                    random_state=random_state,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def build_supervised_pipeline(
    algorithm: Literal["xgboost", "random_forest"] = "xgboost",
    random_state: int = 42,
) -> Pipeline:
    if algorithm == "xgboost":
        try:
            from xgboost import XGBClassifier

            clf: Any = XGBClassifier(
                n_estimators=120,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                eval_metric="mlogloss",
                random_state=random_state,
                n_jobs=-1,
            )
        except ImportError:
            clf = RandomForestClassifier(
                n_estimators=120, class_weight="balanced", random_state=random_state, n_jobs=-1
            )
    else:
        clf = RandomForestClassifier(
            n_estimators=120, class_weight="balanced", random_state=random_state, n_jobs=-1
        )
    return Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", RobustScaler()),
            ("model", clf),
        ]
    )


@dataclass
class DetectionBundle:
    iso_pipeline: Pipeline
    sup_pipeline: Pipeline
    label_encoder: LabelEncoder
    anomaly_threshold: float = 0.55
    supervised_threshold: float = 0.60

    def save(self, path: str) -> None:
        joblib.dump(
            {
                "iso_pipeline": self.iso_pipeline,
                "sup_pipeline": self.sup_pipeline,
                "label_encoder": self.label_encoder,
                "anomaly_threshold": self.anomaly_threshold,
                "supervised_threshold": self.supervised_threshold,
                "feature_columns": FEATURE_COLUMNS,
            },
            path,
        )

    @classmethod
    def load(cls, path: str) -> DetectionBundle:
        obj = joblib.load(path)
        return cls(
            iso_pipeline=obj["iso_pipeline"],
            sup_pipeline=obj["sup_pipeline"],
            label_encoder=obj["label_encoder"],
            anomaly_threshold=float(obj.get("anomaly_threshold", 0.60)),
            supervised_threshold=float(obj.get("supervised_threshold", 0.65)),
        )


def compute_anomaly_scores(iso_pipeline: Pipeline, X: np.ndarray) -> np.ndarray:
    """Convert IsolationForest decision_function into normalized [0, 1] anomaly score."""
    raw = iso_pipeline.decision_function(X)
    # raw < 0 indicates IsolationForest outlier; 8.0 slope cleanly separates inliers (<0.5) from outliers (>0.5)
    scores = 1.0 / (1.0 + np.exp(8.0 * raw))
    return np.clip(scores, 0.0, 1.0)


def compute_shap_top_k(
    sup_pipeline: Pipeline,
    X_row: np.ndarray,
    class_idx: int,
    top_k: int = 8,
) -> list[dict[str, Any]]:
    """Compute SHAP TreeExplainer top-K attributions with deterministic z-score fallback."""
    X_2d = X_row.reshape(1, -1)
    X_trans = sup_pipeline[:-1].transform(X_2d)
    model = sup_pipeline.named_steps["model"]

    try:
        import shap

        explainer = shap.TreeExplainer(model)
        vals = explainer.shap_values(X_trans)
        if isinstance(vals, list):
            arr = np.asarray(vals[min(class_idx, len(vals) - 1)])[0]
        elif getattr(vals, "ndim", 0) == 3:
            arr = np.asarray(vals)[0, :, min(class_idx, vals.shape[2] - 1)]
        else:
            arr = np.asarray(vals)[0]
    except Exception:
        # Deterministic scaled-feature contribution fallback if SHAP cannot run on model
        importances = getattr(model, "feature_importances_", np.ones(len(FEATURE_COLUMNS)))
        arr = X_trans[0] * np.asarray(importances)

    items = [
        {
            "feature": FEATURE_COLUMNS[i],
            "value": round(float(X_row[i]), 4),
            "shap_value": round(float(arr[i]), 6),
        }
        for i in range(len(FEATURE_COLUMNS))
    ]
    items.sort(key=lambda item: abs(item["shap_value"]), reverse=True)
    return items[:top_k]


def generate_synthetic_bootstrap_bundle(random_state: int = 42) -> DetectionBundle:
    """Train a lightweight baseline bundle on synthetic network flow profiles for local dev/demo.

    Production deployments should train on CIC-IDS2017 / UNSW-NB15 / CSE-CIC-IDS2018 via ml.train.
    """
    rng = np.random.default_rng(random_state)
    n_benign, n_scan, n_dos, n_brute = 300, 80, 80, 80

    def _benign(n: int) -> np.ndarray:
        X = np.zeros((n, len(FEATURE_COLUMNS)), dtype=np.float64)
        X[:, 0] = rng.uniform(50, 5000, n)        # duration_ms
        X[:, 1] = rng.integers(5, 40, n)          # fwd_packets
        X[:, 2] = rng.integers(5, 40, n)          # bwd_packets
        X[:, 3] = rng.uniform(1500, 45000, n)     # bytes_total
        X[:, 4] = rng.uniform(100, 1200, n)       # pkt_len_mean
        X[:, 5] = rng.uniform(20, 300, n)         # pkt_len_std
        X[:, 6] = rng.uniform(500, 50000, n)      # flow_bytes_per_sec
        X[:, 7] = rng.uniform(2, 60, n)           # flow_pkts_per_sec
        X[:, 8] = rng.uniform(10, 200, n)         # iat_mean_ms
        X[:, 9] = rng.uniform(5, 80, n)           # iat_std_ms
        X[:, 10] = rng.integers(1, 3, n)          # syn
        X[:, 11] = rng.integers(5, 35, n)         # ack
        X[:, 12] = rng.integers(0, 2, n)          # fin
        X[:, 13] = 0                              # rst
        X[:, 14] = rng.integers(1, 10, n)         # psh
        X[:, 15] = rng.uniform(0.5, 2.0, n)       # fwd_bwd_ratio
        X[:, 16] = rng.choice([80, 443, 53], n)   # dst_port
        X[:, 17] = 0.0                            # dst_port_bucket
        X[:, 18] = 6.0                            # protocol_num
        return X

    def _port_scan(n: int) -> np.ndarray:
        X = _benign(n)
        X[:, 0] = rng.uniform(1, 30, n)
        X[:, 1] = rng.integers(1, 4, n)
        X[:, 2] = rng.integers(0, 2, n)
        X[:, 3] = rng.uniform(60, 240, n)
        X[:, 7] = rng.uniform(100, 2000, n)
        X[:, 10] = rng.integers(1, 6, n)
        X[:, 11] = rng.integers(0, 2, n)
        X[:, 13] = rng.integers(1, 4, n)
        X[:, 15] = rng.uniform(2.0, 10.0, n)
        X[:, 16] = rng.integers(1, 65000, n)
        X[:, 17] = 1.0
        return X

    def _dos(n: int) -> np.ndarray:
        X = _benign(n)
        X[:, 0] = rng.uniform(500, 15000, n)
        X[:, 1] = rng.integers(200, 2000, n)
        X[:, 2] = rng.integers(0, 15, n)
        X[:, 3] = rng.uniform(150000, 2000000, n)
        X[:, 6] = rng.uniform(100000, 5000000, n)
        X[:, 7] = rng.uniform(200, 5000, n)
        X[:, 10] = rng.integers(50, 500, n)
        X[:, 15] = rng.uniform(15.0, 200.0, n)
        return X

    def _brute(n: int) -> np.ndarray:
        X = _benign(n)
        X[:, 1] = rng.integers(30, 150, n)
        X[:, 2] = rng.integers(20, 100, n)
        X[:, 10] = rng.integers(10, 60, n)
        X[:, 13] = rng.integers(5, 30, n)
        X[:, 16] = rng.choice([22, 21, 3389], n)
        return X

    X_benign = _benign(n_benign)
    X_all = np.vstack([X_benign, _port_scan(n_scan), _dos(n_dos), _brute(n_brute)])
    y_all = (
        ["benign"] * n_benign
        + ["port_scan"] * n_scan
        + ["dos_ddos"] * n_dos
        + ["brute_force"] * n_brute
    )

    le = LabelEncoder()
    y_enc = le.fit_transform(y_all)

    iso = build_isolation_forest_pipeline(random_state)
    iso.fit(X_benign)

    sup = build_supervised_pipeline("random_forest", random_state)
    sup.fit(X_all, y_enc)

    return DetectionBundle(iso_pipeline=iso, sup_pipeline=sup, label_encoder=le)
