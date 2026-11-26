"""Alerts, Incidents, LangGraph Investigations, HITL Approvals, RAG Search, Reports & Analytics."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from netsentinel.agents.graph import execute_incident_investigation
from netsentinel.auth.deps import AuthContext, require_roles
from netsentinel.core.errors import ConflictError, ForbiddenError, NotFoundError
from netsentinel.core.security import (
    ADMIN_ROLES,
    ALL_ORG_ROLES,
    ANALYST_AND_ABOVE,
    RESPONDER_AND_ABOVE,
)
from netsentinel.core.storage import get_storage
from netsentinel.db.audit import record_audit
from netsentinel.db.models import (
    AgentRun,
    Alert,
    AuditLog,
    EvidenceItem,
    Incident,
    IncidentAlert,
    Investigation,
    ModelVersion,
    NetworkFlow,
    Recommendation,
    SecurityDocument,
    TrafficDataset,
)
from netsentinel.db.session import get_db
from netsentinel.incidents.reporting import generate_incident_report
from netsentinel.rag.retriever import hybrid_search, ingest_security_document

router = APIRouter(tags=["SOC Operations, RAG & Investigations"])


class AlertPatchRequest(BaseModel):
    status: Literal["open", "triaging", "escalated", "resolved", "false_positive"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    assigned_to: str | None = None
    analyst_note: str | None = None


class IncidentCreateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "high"
    alert_ids: list[str] = Field(default_factory=list)


class IncidentVerdictRequest(BaseModel):
    verdict: Literal["pending", "benign", "anomalous", "suspicious", "confirmed_malicious", "false_positive"]
    status: Literal["open", "investigating", "contained", "closed"] | None = None


class ApprovalRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=3, max_length=1000)


class ThreatIntelSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    source_types: list[str] | None = None
    top_k: int = Field(default=5, ge=1, le=20)
    use_reranker: bool = True


class ThreatIntelIngestRequest(BaseModel):
    source_type: str = "internal_kb"
    external_id: str = Field(min_length=2, max_length=100)
    title: str = Field(min_length=3, max_length=255)
    content: str = Field(min_length=10)
    source_url: str = ""


class ReportCreateRequest(BaseModel):
    format: Literal["markdown", "json"] = "markdown"
    anonymize_ips: bool = False


# --- Alerts ---
@router.get("/alerts")
def list_alerts(
    status: str | None = None,
    classification_tier: str | None = None,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.organization_id == ctx.organization_id)
    if status:
        q = q.filter(Alert.status == status)
    if classification_tier:
        q = q.filter(Alert.classification_tier == classification_tier)
    rows = q.order_by(desc(Alert.created_at)).limit(200).all()
    return {
        "items": [
            {
                "alert_id": a.id,
                "dataset_id": a.dataset_id,
                "detection_result_id": a.detection_result_id,
                "title": a.title,
                "summary": a.summary,
                "severity": a.severity,
                "classification_tier": a.classification_tier,
                "status": a.status,
                "assigned_to": a.assigned_to,
                "analyst_note": a.analyst_note,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
    }


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    payload: AlertPatchRequest,
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == ctx.organization_id)
        .first()
    )
    if alert is None:
        raise NotFoundError("Alert")

    if payload.status is not None:
        alert.status = payload.status
    if payload.severity is not None:
        alert.severity = payload.severity
    if payload.assigned_to is not None:
        alert.assigned_to = payload.assigned_to
    if payload.analyst_note is not None:
        alert.analyst_note = payload.analyst_note

    record_audit(
        db,
        action="alert.updated",
        resource_type="alert",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        resource_id=alert.id,
        metadata=payload.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(alert)
    return {
        "alert_id": alert.id,
        "status": alert.status,
        "severity": alert.severity,
        "classification_tier": alert.classification_tier,
        "detection_result_id": alert.detection_result_id,
        "updated_at": alert.updated_at.isoformat(),
    }


# --- Incidents ---
@router.post("/incidents", status_code=201)
def create_incident(
    payload: IncidentCreateRequest,
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    inc = Incident(
        organization_id=ctx.organization_id,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        created_by=ctx.user_id,
    )
    db.add(inc)
    db.flush()

    for aid in payload.alert_ids:
        alert = (
            db.query(Alert)
            .filter(Alert.id == aid, Alert.organization_id == ctx.organization_id)
            .first()
        )
        if alert is not None:
            db.add(IncidentAlert(incident_id=inc.id, alert_id=alert.id, linked_by=ctx.user_id))
            alert.status = "escalated"

    record_audit(
        db,
        action="incident.created",
        resource_type="incident",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        resource_id=inc.id,
        metadata={"alert_count": len(payload.alert_ids)},
    )
    db.commit()
    db.refresh(inc)
    return {
        "incident_id": inc.id,
        "title": inc.title,
        "severity": inc.severity,
        "status": inc.status,
        "verdict": inc.verdict,
        "created_at": inc.created_at.isoformat(),
    }


@router.get("/incidents")
def list_incidents(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Incident)
        .filter(Incident.organization_id == ctx.organization_id)
        .order_by(desc(Incident.created_at))
        .all()
    )
    return {
        "items": [
            {
                "incident_id": i.id,
                "title": i.title,
                "description": i.description,
                "severity": i.severity,
                "status": i.status,
                "verdict": i.verdict,
                "created_at": i.created_at.isoformat(),
            }
            for i in rows
        ]
    }


@router.patch("/incidents/{incident_id}/verdict")
def set_incident_verdict(
    incident_id: str,
    payload: IncidentVerdictRequest,
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    if payload.verdict == "confirmed_malicious" and ctx.role not in RESPONDER_AND_ABOVE:
        raise ForbiddenError("Only incident_responder or org_admin can set confirmed_malicious verdict")

    inc = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == ctx.organization_id)
        .first()
    )
    if inc is None:
        raise NotFoundError("Incident")

    inc.verdict = payload.verdict
    if payload.status:
        inc.status = payload.status
    record_audit(
        db,
        action="incident.verdict_updated",
        resource_type="incident",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        resource_id=inc.id,
        metadata={"verdict": inc.verdict, "status": inc.status},
    )
    db.commit()
    return {"incident_id": inc.id, "verdict": inc.verdict, "status": inc.status}


# --- Multi-Agent Investigations & HITL Approval ---
@router.post("/incidents/{incident_id}/investigations", status_code=202)
def start_investigation(
    incident_id: str,
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    inv = execute_incident_investigation(
        db,
        organization_id=ctx.organization_id,
        incident_id=incident_id,
        triggered_by=ctx.user_id,
    )
    return {
        "investigation_id": inv.id,
        "incident_id": inv.incident_id,
        "status": inv.status,
        "validation_status": inv.validation_status,
        "created_at": inv.started_at.isoformat(),
    }


@router.get("/investigations")
def list_investigations(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(Investigation)
        .filter(Investigation.organization_id == ctx.organization_id)
        .order_by(desc(Investigation.started_at))
        .all()
    )
    return {
        "items": [
            {
                "investigation_id": inv.id,
                "incident_id": inv.incident_id,
                "status": inv.status,
                "validation_status": inv.validation_status,
                "revision_count": inv.revision_count,
                "executive_summary": inv.executive_summary,
                "started_at": inv.started_at.isoformat(),
                "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
            }
            for inv in rows
        ]
    }


@router.get("/investigations/{investigation_id}")
def get_investigation(
    investigation_id: str,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    inv = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.organization_id == ctx.organization_id,
        )
        .first()
    )
    if inv is None:
        raise NotFoundError("Investigation")

    runs = (
        db.query(AgentRun)
        .filter(AgentRun.investigation_id == inv.id)
        .order_by(AgentRun.step_order.asc())
        .all()
    )
    evidence = db.query(EvidenceItem).filter(EvidenceItem.investigation_id == inv.id).all()
    recs = db.query(Recommendation).filter(Recommendation.investigation_id == inv.id).all()

    return {
        "investigation_id": inv.id,
        "incident_id": inv.incident_id,
        "status": inv.status,
        "validation_status": inv.validation_status,
        "revision_count": inv.revision_count,
        "executive_summary": inv.executive_summary,
        "hypothesis": inv.hypothesis,
        "langfuse_trace_id": inv.langfuse_trace_id,
        "state_snapshot": inv.state_snapshot,
        "agent_runs": [
            {
                "id": r.id,
                "agent_name": r.agent_name,
                "step_order": r.step_order,
                "attempt_number": r.attempt_number,
                "status": r.status,
                "latency_ms": r.latency_ms,
                "token_usage": r.token_usage,
                "output_payload": r.output_payload,
            }
            for r in runs
        ],
        "evidence_items": [
            {
                "id": e.id,
                "evidence_type": e.evidence_type,
                "reference_id": e.reference_id,
                "claim_text": e.claim_text,
                "validation_verdict": e.validation_verdict,
                "validator_notes": e.validator_notes,
            }
            for e in evidence
        ],
        "recommendations": [
            {
                "id": rec.id,
                "title": rec.title,
                "category": rec.category,
                "priority": rec.priority,
                "description": rec.description,
                "risk_impact": rec.risk_impact,
                "supporting_evidence_ids": rec.supporting_evidence_ids,
                "approval_status": rec.approval_status,
                "decision_rationale": rec.decision_rationale,
            }
            for rec in recs
        ],
    }


@router.post("/investigations/{investigation_id}/recommendations/{recommendation_id}/approve")
def decide_recommendation(
    investigation_id: str,
    recommendation_id: str,
    payload: ApprovalRequest,
    ctx: AuthContext = Depends(require_roles(RESPONDER_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    rec = (
        db.query(Recommendation)
        .filter(
            Recommendation.id == recommendation_id,
            Recommendation.investigation_id == investigation_id,
            Recommendation.organization_id == ctx.organization_id,
        )
        .first()
    )
    if rec is None:
        raise NotFoundError("Recommendation")
    if rec.approval_status != "pending_approval":
        raise ConflictError(f"Recommendation already {rec.approval_status}")

    rec.approval_status = payload.decision
    rec.decided_by = ctx.user_id
    rec.decision_rationale = payload.rationale
    rec.decided_at = datetime.now(timezone.utc)

    record_audit(
        db,
        action=f"recommendation.{payload.decision}",
        resource_type="recommendation",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        resource_id=rec.id,
        metadata={"investigation_id": investigation_id, "rationale": payload.rationale},
    )
    db.commit()
    return {
        "recommendation_id": rec.id,
        "approval_status": rec.approval_status,
        "decided_by": rec.decided_by,
        "decided_at": rec.decided_at.isoformat() if rec.decided_at else None,
    }


# --- Threat Intelligence RAG ---
@router.post("/threat-intel/search")
def search_threat_intel(
    payload: ThreatIntelSearchRequest,
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    return hybrid_search(
        db,
        query=payload.query,
        organization_id=ctx.organization_id,
        source_types=payload.source_types,
        top_k=payload.top_k,
        use_reranker=payload.use_reranker,
    )


@router.post("/threat-intel/documents", status_code=201)
def add_threat_intel_doc(
    payload: ThreatIntelIngestRequest,
    ctx: AuthContext = Depends(require_roles(ADMIN_ROLES)),
    db: Session = Depends(get_db),
):
    doc = ingest_security_document(
        db,
        source_type=payload.source_type,
        external_id=payload.external_id,
        title=payload.title,
        content=payload.content,
        source_url=payload.source_url,
        organization_id=ctx.organization_id,
    )
    return {"document_id": doc.id, "external_id": doc.external_id, "title": doc.title}


@router.get("/threat-intel/documents")
def list_threat_intel_docs(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    docs = (
        db.query(SecurityDocument)
        .filter(
            (SecurityDocument.organization_id.is_(None))
            | (SecurityDocument.organization_id == ctx.organization_id)
        )
        .order_by(desc(SecurityDocument.ingested_at))
        .all()
    )
    return {
        "items": [
            {
                "document_id": d.id,
                "source_type": d.source_type,
                "external_id": d.external_id,
                "title": d.title,
                "source_url": d.source_url,
                "ingested_at": d.ingested_at.isoformat(),
            }
            for d in docs
        ]
    }


# --- Reports ---
@router.post("/incidents/{incident_id}/reports", status_code=201)
def create_report(
    incident_id: str,
    payload: ReportCreateRequest = ReportCreateRequest(),
    ctx: AuthContext = Depends(require_roles(ANALYST_AND_ABOVE)),
    db: Session = Depends(get_db),
):
    res = generate_incident_report(
        db,
        organization_id=ctx.organization_id,
        incident_id=incident_id,
        fmt=payload.format,
        anonymize_ips=payload.anonymize_ips,
    )
    record_audit(
        db,
        action="report.generated",
        resource_type="incident",
        organization_id=ctx.organization_id,
        actor_user_id=ctx.user_id,
        resource_id=incident_id,
        metadata={"report_id": res["report_id"], "format": payload.format},
    )
    db.commit()
    return res


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    ext: str = Query(default="md"),
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
):
    key = f"orgs/{ctx.organization_id}/reports/{report_id}.{ext}"
    try:
        data = get_storage().get_bytes(key)
    except Exception as exc:
        raise NotFoundError("Report") from exc
    return PlainTextResponse(content=data.decode("utf-8"))


# --- Dashboard Overview, Models, Audit Logs ---
@router.get("/dashboard/overview")
def dashboard_overview(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    org_id = ctx.organization_id
    datasets_count = db.query(TrafficDataset).filter(TrafficDataset.organization_id == org_id).count()
    flows_count = db.query(NetworkFlow).filter(NetworkFlow.organization_id == org_id).count()
    open_alerts = (
        db.query(Alert).filter(Alert.organization_id == org_id, Alert.status == "open").count()
    )
    incidents_count = db.query(Incident).filter(Incident.organization_id == org_id).count()
    investigations_count = (
        db.query(Investigation).filter(Investigation.organization_id == org_id).count()
    )

    proto_rows = (
        db.query(NetworkFlow.protocol, func.count(NetworkFlow.id))
        .filter(NetworkFlow.organization_id == org_id)
        .group_by(NetworkFlow.protocol)
        .all()
    )
    tier_rows = (
        db.query(Alert.classification_tier, func.count(Alert.id))
        .filter(Alert.organization_id == org_id)
        .group_by(Alert.classification_tier)
        .all()
    )

    return {
        "kpis": {
            "datasets_count": datasets_count,
            "flows_count": flows_count,
            "open_alerts": open_alerts,
            "incidents_count": incidents_count,
            "investigations_count": investigations_count,
        },
        "protocol_distribution": [{"protocol": p, "count": c} for p, c in proto_rows],
        "alert_tier_distribution": [{"tier": t, "count": c} for t, c in tier_rows],
    }


@router.get("/models")
def list_models(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    rows = db.query(ModelVersion).order_by(desc(ModelVersion.created_at)).all()
    return {
        "items": [
            {
                "id": m.id,
                "name": m.name,
                "model_type": m.model_type,
                "version": m.version,
                "stage": m.stage,
                "training_dataset_ref": m.training_dataset_ref,
                "metrics": m.metrics,
                "threshold_config": m.threshold_config,
                "created_at": m.created_at.isoformat(),
            }
            for m in rows
        ]
    }


@router.get("/audit-logs")
def list_audit_logs(
    ctx: AuthContext = Depends(require_roles(ALL_ORG_ROLES)),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == ctx.organization_id)
        .order_by(desc(AuditLog.created_at))
        .limit(150)
        .all()
    )
    return {
        "items": [
            {
                "id": a.id,
                "actor_type": a.actor_type,
                "actor_user_id": a.actor_user_id,
                "action": a.action,
                "resource_type": a.resource_type,
                "resource_id": a.resource_id,
                "metadata": a.audit_metadata,
                "created_at": a.created_at.isoformat(),
            }
            for a in rows
        ]
    }
