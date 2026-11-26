"""Celery application with dedicated queues (q_ingestion, q_ml, q_rag, q_agents)."""

from __future__ import annotations

from celery import Celery

from netsentinel.core.config import get_settings
from netsentinel.db.session import SessionLocal
from netsentinel.ingestion.service import process_dataset_flows
from netsentinel.ml.service import run_dataset_detection

settings = get_settings()

celery_app = Celery(
    "netsentinel",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)
celery_app.conf.update(
    task_always_eager=settings.celery_task_always_eager,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    task_routes={
        "netsentinel.workers.extract_flows_task": {"queue": "q_ingestion"},
        "netsentinel.workers.run_detection_task": {"queue": "q_ml"},
    },
)


@celery_app.task(name="netsentinel.workers.extract_flows_task", bind=True, max_retries=3)
def extract_flows_task(
    self,
    organization_id: str,
    dataset_id: str,
    flow_timeout_seconds: int = 120,
    auto_run_detection: bool = False,
) -> dict:
    with SessionLocal() as db:
        ds = process_dataset_flows(
            db,
            organization_id=organization_id,
            dataset_id=dataset_id,
            flow_timeout_seconds=flow_timeout_seconds,
        )
        result = {"dataset_id": ds.id, "status": ds.status, "flow_count": ds.flow_count}
        if auto_run_detection and ds.status == "completed":
            det = run_dataset_detection(db, organization_id=organization_id, dataset_id=dataset_id)
            result["detection"] = det
        return result


@celery_app.task(name="netsentinel.workers.run_detection_task", bind=True, max_retries=3)
def run_detection_task(
    self,
    organization_id: str,
    dataset_id: str,
    user_id: str | None = None,
    model_version_id: str | None = None,
    compute_shap: bool = True,
    shap_top_k: int = 8,
) -> dict:
    with SessionLocal() as db:
        return run_dataset_detection(
            db,
            organization_id=organization_id,
            dataset_id=dataset_id,
            user_id=user_id,
            model_version_id=model_version_id,
            compute_shap=compute_shap,
            shap_top_k=shap_top_k,
        )
