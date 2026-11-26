"""PCAP upload, dataset processing, flow retrieval, and ML detection/SHAP endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from netsentinel.auth.deps import AuthContext, require_roles
from netsentinel.core.errors import NotFoundError
from netsentinel.core.security import ALL_ORG_ROLES, ANALYST_AND_ABOVE, ML_ROLES
from netsentinel.db.models import DetectionResult, NetworkFlow, TrafficDataset
from netsentinel.db.session import get_db
from netsentinel.ingestion.service import process_dataset_flows, upload_pcap_dataset
from netsentinel.ml.service import run_dataset_detection

router = APIRouter(tags=["Datasets, Flows & Detection"])


class ProcessRequest(BaseModel):
    flow_timeout_seconds: int = Field(default=120, ge=10, le=3600)
    auto_run_detection: bool = True
    extraction_engine: str = "scapy"


class DetectRequest(BaseModel):
    model_version_id: str | None = None
    compute_shap: bool = True
    shap_top_k: int = Field(default=8, ge=1, le=19)


@router.post("/datasets/upload", status_code=201)
async def upload_dataset(
    file: UploadFile = File(...),
    name: str = Form(..., min_length=3, max_length=120),
    description: str = Form(default=""),
    tags: str = Form(default="[]"),
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    raw = await file.read()
    try:
        parsed_tags = json.loads(tags) if tags else []
    except json.JSONDecodeError:
        parsed_tags = []
    ds = upload_pcap_dataset(
        db,
        organization_id=ctx.organization_id,
        user_id=ctx.user_id,
        filename=file.filename or "capture.pcap",
        data=raw,
        name=name,
        description=description,
        tags=parsed_tags if isinstance(parsed_tags, list) else [],
    )
    return {
        "dataset_id": ds.id,
        "organization_id": ds.organization_id,
        "name": ds.name,
        "file_size_bytes": ds.file_size_bytes,
        "sha256": ds.sha256,
        "status": ds.status,
        "created_at": ds.created_at.isoformat(),
    }


@router.get("/datasets")
def list_datasets(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(TrafficDataset)
        .filter(TrafficDataset.organization_id == ctx.organization_id)
        .order_by(desc(TrafficDataset.created_at))
        .all()
    )
    return {
        "items": [
            {
                "dataset_id": d.id,
                "name": d.name,
                "description": d.description,
                "file_size_bytes": d.file_size_bytes,
                "sha256": d.sha256,
                "status": d.status,
                "progress_pct": d.progress_pct,
                "packet_count": d.packet_count,
                "flow_count": d.flow_count,
                "tags": d.tags,
                "created_at": d.created_at.isoformat(),
            }
            for d in rows
        ]
    }


@router.post("/datasets/{dataset_id}/process", status_code=202)
def process_dataset(
    dataset_id: str,
    payload: ProcessRequest = ProcessRequest(),
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    ds = process_dataset_flows(
        db,
        organization_id=ctx.organization_id,
        dataset_id=dataset_id,
        flow_timeout_seconds=payload.flow_timeout_seconds,
    )
    det_summary = None
    if payload.auto_run_detection and ds.status == "completed":
        det_summary = run_dataset_detection(
            db,
            organization_id=ctx.organization_id,
            dataset_id=dataset_id,
            user_id=ctx.user_id,
        )
    return {
        "dataset_id": ds.id,
        "job_id": f"job_{uuid.uuid4().hex[:12]}",
        "status": ds.status,
        "flow_count": ds.flow_count,
        "detection": det_summary,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/datasets/{dataset_id}/status")
def dataset_status(
    dataset_id: str,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    ds = (
        db.query(TrafficDataset)
        .filter(
            TrafficDataset.id == dataset_id,
            TrafficDataset.organization_id == ctx.organization_id,
        )
        .first()
    )
    if ds is None:
        raise NotFoundError("TrafficDataset")
    return {
        "dataset_id": ds.id,
        "status": ds.status,
        "progress_pct": ds.progress_pct,
        "packet_count": ds.packet_count,
        "flow_count": ds.flow_count,
        "error_message": ds.error_message,
        "completed_at": ds.completed_at.isoformat() if ds.completed_at else None,
    }


@router.get("/datasets/{dataset_id}/flows")
def list_flows(
    dataset_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    protocol: str | None = None,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    q = db.query(NetworkFlow).filter(
        NetworkFlow.dataset_id == dataset_id,
        NetworkFlow.organization_id == ctx.organization_id,
    )
    if src_ip:
        q = q.filter(NetworkFlow.src_ip == src_ip)
    if dst_ip:
        q = q.filter(NetworkFlow.dst_ip == dst_ip)
    if dst_port is not None:
        q = q.filter(NetworkFlow.dst_port == dst_port)
    if protocol:
        q = q.filter(NetworkFlow.protocol == protocol.upper())

    total = q.count()
    flows = q.order_by(desc(NetworkFlow.start_time)).offset((page - 1) * page_size).limit(page_size).all()

    flow_ids = [f.id for f in flows]
    latest_dets: dict[str, DetectionResult] = {}
    if flow_ids:
        for det in (
            db.query(DetectionResult)
            .filter(
                DetectionResult.flow_id.in_(flow_ids),
                DetectionResult.organization_id == ctx.organization_id,
            )
            .all()
        ):
            latest_dets[det.flow_id] = det

    return {
        "items": [
            {
                "flow_id": f.id,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "start_time": f.start_time.isoformat(),
                "duration_ms": f.duration_ms,
                "fwd_packets": f.fwd_packets,
                "bwd_packets": f.bwd_packets,
                "bytes_total": f.bytes_total,
                "latest_classification_tier": (
                    latest_dets[f.id].classification_tier if f.id in latest_dets else "benign"
                ),
                "latest_anomaly_score": (
                    latest_dets[f.id].anomaly_score if f.id in latest_dets else 0.0
                ),
                "detection_id": latest_dets[f.id].id if f.id in latest_dets else None,
            }
            for f in flows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.post("/datasets/{dataset_id}/detect", status_code=202)
def detect_dataset(
    dataset_id: str,
    payload: DetectRequest = DetectRequest(),
    ctx: AuthContext = Depends(require_roles(ML_ROLES)),
    db: Session = Depends(get_db),
):
    summary = run_dataset_detection(
        db,
        organization_id=ctx.organization_id,
        dataset_id=dataset_id,
        user_id=ctx.user_id,
        model_version_id=payload.model_version_id,
        compute_shap=payload.compute_shap,
        shap_top_k=payload.shap_top_k,
    )
    return {
        "job_id": f"det_{uuid.uuid4().hex[:12]}",
        "status": "completed",
        **summary,
    }


@router.get("/detections/{detection_id}/explain")
def explain_detection(
    detection_id: str,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    det = (
        db.query(DetectionResult)
        .filter(
            DetectionResult.id == detection_id,
            DetectionResult.organization_id == ctx.organization_id,
        )
        .first()
    )
    if det is None:
        raise NotFoundError("DetectionResult")
    return {
        "detection_id": det.id,
        "flow_id": det.flow_id,
        "model_version_id": det.model_version_id,
        "classification_tier": det.classification_tier,
        "anomaly_score": det.anomaly_score,
        "predicted_class": det.predicted_class,
        "confidence": det.confidence,
        "shap_features": det.shap_values,
    }
