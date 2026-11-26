"""Dataset upload and asynchronous PCAP processing service."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from netsentinel.core.config import get_settings
from netsentinel.core.errors import NotFoundError
from netsentinel.core.storage import get_storage
from netsentinel.db.audit import record_audit
from netsentinel.db.models import NetworkFlow, TrafficDataset
from netsentinel.ingestion.flow_extractor import extract_flows_from_pcap
from netsentinel.ingestion.pcap_validator import validate_pcap_bytes


def upload_pcap_dataset(
    db: Session,
    *,
    organization_id: str,
    user_id: str,
    filename: str,
    data: bytes,
    name: str,
    description: str = "",
    tags: list[str] | None = None,
) -> TrafficDataset:
    sha256 = validate_pcap_bytes(data, filename)
    settings = get_settings()
    dataset = TrafficDataset(
        organization_id=organization_id,
        uploaded_by=user_id,
        name=name,
        description=description,
        storage_bucket=settings.s3_bucket_name if settings.storage_backend == "s3" else "local",
        storage_key="",
        file_size_bytes=len(data),
        sha256=sha256,
        status="uploaded",
        tags=tags or [],
    )
    db.add(dataset)
    db.flush()

    ext = ".pcapng" if filename.lower().endswith(".pcapng") else ".pcap"
    storage_key = f"orgs/{organization_id}/datasets/{dataset.id}/{sha256}{ext}"
    get_storage().put_bytes(storage_key, data, content_type="application/vnd.tcpdump.pcap")
    dataset.storage_key = storage_key

    record_audit(
        db,
        action="dataset.uploaded",
        resource_type="traffic_dataset",
        organization_id=organization_id,
        actor_user_id=user_id,
        resource_id=dataset.id,
        metadata={"filename": filename, "size_bytes": len(data), "sha256": sha256},
    )
    db.commit()
    db.refresh(dataset)
    return dataset


def process_dataset_flows(
    db: Session,
    *,
    organization_id: str,
    dataset_id: str,
    flow_timeout_seconds: int = 120,
) -> TrafficDataset:
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

    dataset.status = "processing"
    dataset.progress_pct = 10
    dataset.error_message = None
    db.commit()

    try:
        raw_bytes = get_storage().get_bytes(dataset.storage_key)
        packet_count, flow_records = extract_flows_from_pcap(
            raw_bytes, flow_timeout_seconds=flow_timeout_seconds
        )
        dataset.progress_pct = 70
        db.flush()

        # Replace existing flows on re-process
        db.query(NetworkFlow).filter(
            NetworkFlow.dataset_id == dataset.id,
            NetworkFlow.organization_id == organization_id,
        ).delete()

        flow_objs = [
            NetworkFlow(
                organization_id=organization_id,
                dataset_id=dataset.id,
                **rec,
            )
            for rec in flow_records
        ]
        if flow_objs:
            db.bulk_save_objects(flow_objs)

        dataset.packet_count = packet_count
        dataset.flow_count = len(flow_objs)
        dataset.progress_pct = 100
        dataset.status = "completed"
        dataset.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(dataset)
        return dataset
    except Exception as exc:
        dataset.status = "failed"
        dataset.error_message = str(exc)[:500]
        db.commit()
        raise
