"""ML inference, SHAP persistence, model registration, and alert generation service."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import numpy as np
from sqlalchemy.orm import Session

from netsentinel.core.errors import NotFoundError
from netsentinel.core.storage import get_storage
from netsentinel.db.audit import record_audit
from netsentinel.db.models import Alert, DetectionResult, ModelVersion, NetworkFlow, TrafficDataset
from netsentinel.ml.features import extract_feature_matrix, feature_schema_hash
from netsentinel.ml.models import (
    DetectionBundle,
    compute_anomaly_scores,
    compute_shap_top_k,
    generate_synthetic_bootstrap_bundle,
    resolve_classification_tier,
)

_CACHED_BUNDLES: dict[str, DetectionBundle] = {}


def ensure_default_model_version(db: Session) -> ModelVersion:
    existing = (
        db.query(ModelVersion)
        .filter(ModelVersion.stage == "active")
        .order_by(ModelVersion.created_at.desc())
        .first()
    )
    if existing is not None:
        return existing

    bundle = generate_synthetic_bootstrap_bundle()
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp_path = tmp.name
    bundle.save(tmp_path)
    artifact_bytes = Path(tmp_path).read_bytes()
    Path(tmp_path).unlink(missing_ok=True)

    storage_key = "models/netsentinel-baseline/v0.1.0/bundle.joblib"
    get_storage().put_bytes(storage_key, artifact_bytes)

    mv = ModelVersion(
        name="netsentinel-baseline-ensemble",
        model_type="xgboost",
        version="0.1.0-bootstrap",
        stage="active",
        artifact_storage_key=storage_key,
        feature_schema_hash=feature_schema_hash(),
        training_dataset_ref="synthetic-bootstrap (replace with CIC-IDS2017/UNSW-NB15)",
        hyperparameters={"isolation_forest_trees": 100, "classifier": "random_forest"},
        metrics={"note": "Bootstrap dev model — train on public datasets for benchmark metrics"},
        threshold_config={
            "anomaly_threshold": bundle.anomaly_threshold,
            "supervised_threshold": bundle.supervised_threshold,
        },
    )
    db.add(mv)
    db.commit()
    db.refresh(mv)
    _CACHED_BUNDLES[mv.id] = bundle
    return mv


def _load_bundle(mv: ModelVersion) -> DetectionBundle:
    if mv.id in _CACHED_BUNDLES:
        return _CACHED_BUNDLES[mv.id]
    raw = get_storage().get_bytes(mv.artifact_storage_key)
    with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
        tmp.write(raw)
        tmp_path = tmp.name
    bundle = DetectionBundle.load(tmp_path)
    Path(tmp_path).unlink(missing_ok=True)
    _CACHED_BUNDLES[mv.id] = bundle
    return bundle


def run_dataset_detection(
    db: Session,
    *,
    organization_id: str,
    dataset_id: str,
    user_id: str | None = None,
    model_version_id: str | None = None,
    compute_shap: bool = True,
    shap_top_k: int = 8,
) -> dict[str, Any]:
    dataset = (
        db.query(TrafficDataset)
        .filter(
            TrafficDataset.id == dataset_id,
            TrafficDataset.organization_id == organization_id,
        )
        .first()
    )
    if dataset is None:
        raise NotFoundError("TrafficDataset")

    mv = (
        db.get(ModelVersion, model_version_id)
        if model_version_id
        else ensure_default_model_version(db)
    )
    if mv is None:
        raise NotFoundError("ModelVersion")

    flows = (
        db.query(NetworkFlow)
        .filter(
            NetworkFlow.dataset_id == dataset_id,
            NetworkFlow.organization_id == organization_id,
        )
        .all()
    )
    if not flows:
        return {"dataset_id": dataset_id, "flows_evaluated": 0, "alerts_created": 0}

    bundle = _load_bundle(mv)
    X = extract_feature_matrix([f.feature_vector for f in flows])
    anomaly_scores = compute_anomaly_scores(bundle.iso_pipeline, X)
    probs = bundle.sup_pipeline.predict_proba(X)
    pred_indices = np.argmax(probs, axis=1)
    pred_labels = bundle.label_encoder.inverse_transform(pred_indices)

    alerts_created = 0
    anomalous_count = 0
    suspicious_count = 0

    for i, flow in enumerate(flows):
        a_score = round(float(anomaly_scores[i]), 4)
        p_idx = int(pred_indices[i])
        p_label = str(pred_labels[i])
        conf = round(float(probs[i, p_idx]), 4)

        tier = resolve_classification_tier(
            anomaly_score=a_score,
            anomaly_threshold=bundle.anomaly_threshold,
            predicted_class=p_label,
            supervised_confidence=conf,
            supervised_threshold=bundle.supervised_threshold,
        )

        shap_vals: list[dict[str, Any]] = []
        if compute_shap and tier in ("anomalous", "suspicious"):
            shap_vals = compute_shap_top_k(bundle.sup_pipeline, X[i], p_idx, top_k=shap_top_k)

        det = DetectionResult(
            organization_id=organization_id,
            flow_id=flow.id,
            model_version_id=mv.id,
            anomaly_score=a_score,
            predicted_class=p_label,
            confidence=conf,
            classification_tier=tier,
            shap_values=shap_vals,
        )
        db.add(det)
        db.flush()

        if tier in ("anomalous", "suspicious"):
            if tier == "anomalous":
                anomalous_count += 1
                sev = "medium" if a_score >= 0.75 else "low"
                title = f"Anomalous flow detected: {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}"
            else:
                suspicious_count += 1
                sev = "critical" if conf >= 0.90 else "high"
                title = f"Suspicious {p_label} activity: {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}"

            alert = Alert(
                organization_id=organization_id,
                dataset_id=dataset_id,
                detection_result_id=det.id,
                title=title[:200],
                summary=(
                    f"Protocol={flow.protocol}, anomaly_score={a_score}, "
                    f"predicted_class={p_label} (confidence={conf}). "
                    "Automated ML signal requires analyst validation."
                ),
                severity=sev,
                classification_tier=tier,
                status="open",
            )
            db.add(alert)
            alerts_created += 1

    record_audit(
        db,
        action="detection.completed",
        resource_type="traffic_dataset",
        organization_id=organization_id,
        actor_user_id=user_id,
        actor_type="user" if user_id else "system",
        resource_id=dataset_id,
        metadata={
            "model_version_id": mv.id,
            "flows_evaluated": len(flows),
            "anomalous_count": anomalous_count,
            "suspicious_count": suspicious_count,
            "alerts_created": alerts_created,
        },
    )
    db.commit()
    return {
        "dataset_id": dataset_id,
        "model_version_id": mv.id,
        "flows_evaluated": len(flows),
        "anomalous_count": anomalous_count,
        "suspicious_count": suspicious_count,
        "alerts_created": alerts_created,
    }
