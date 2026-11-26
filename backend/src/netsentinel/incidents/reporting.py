"""Structured Incident Report generator (Markdown and JSON) with optional IP anonymization."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from netsentinel.core.errors import NotFoundError
from netsentinel.core.storage import get_storage
from netsentinel.db.models import (
    Alert,
    EvidenceItem,
    Incident,
    IncidentAlert,
    Investigation,
    Recommendation,
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _anonymize_text(text: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        digest = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()[:8]
        return f"anon-ip-{digest}"

    return _IPV4_RE.sub(_repl, text)


def generate_incident_report(
    db: Session,
    *,
    organization_id: str,
    incident_id: str,
    fmt: str = "markdown",
    anonymize_ips: bool = False,
) -> dict[str, Any]:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == organization_id)
        .first()
    )
    if incident is None:
        raise NotFoundError("Incident")

    alerts = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == incident_id, Alert.organization_id == organization_id)
        .all()
    )
    latest_inv = (
        db.query(Investigation)
        .filter(Investigation.incident_id == incident_id, Investigation.organization_id == organization_id)
        .order_by(Investigation.started_at.desc())
        .first()
    )
    evidence = (
        db.query(EvidenceItem).filter(EvidenceItem.investigation_id == latest_inv.id).all()
        if latest_inv
        else []
    )
    recs = (
        db.query(Recommendation).filter(Recommendation.investigation_id == latest_inv.id).all()
        if latest_inv
        else []
    )

    report_id = f"rpt_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(timezone.utc).isoformat()

    payload: dict[str, Any] = {
        "report_id": report_id,
        "generated_at": created_at,
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "verdict": incident.verdict,
        },
        "alerts": [
            {"id": a.id, "title": a.title, "tier": a.classification_tier, "severity": a.severity}
            for a in alerts
        ],
        "investigation": {
            "id": latest_inv.id if latest_inv else None,
            "validation_status": latest_inv.validation_status if latest_inv else "none",
            "executive_summary": latest_inv.executive_summary if latest_inv else "",
            "hypothesis": latest_inv.hypothesis if latest_inv else "",
        },
        "evidence": [
            {
                "type": e.evidence_type,
                "reference_id": e.reference_id,
                "claim": e.claim_text,
                "verdict": e.validation_verdict,
            }
            for e in evidence
        ],
        "recommendations": [
            {
                "title": r.title,
                "category": r.category,
                "priority": r.priority,
                "approval_status": r.approval_status,
                "description": r.description,
            }
            for r in recs
        ],
    }

    if fmt == "json":
        content = json.dumps(payload, indent=2)
        ext = "json"
        mime = "application/json"
    else:
        lines = [
            f"# Incident Report: {incident.title}",
            f"- **Report ID:** `{report_id}`",
            f"- **Incident ID:** `{incident.id}`",
            f"- **Severity:** `{incident.severity}` | **Status:** `{incident.status}` | **Verdict:** `{incident.verdict}`",
            f"- **Generated At:** {created_at}",
            "",
            "## Executive Summary",
            payload["investigation"]["executive_summary"] or "No investigation executed yet.",
            "",
            "## Hypothesis",
            payload["investigation"]["hypothesis"] or "Pending analysis.",
            "",
            "## Verified Evidence",
        ]
        for e in payload["evidence"]:
            lines.append(
                f"- **[{e['verdict'].upper()}]** ({e['type']} `{e['reference_id']}`): {e['claim']}"
            )
        lines.append("")
        lines.append("## Recommendations (Human Approval Required)")
        for r in payload["recommendations"]:
            lines.append(
                f"- **[{r['approval_status']}]** ({r['priority'].upper()} / {r['category']}) **{r['title']}**: {r['description']}"
            )
        content = "\n".join(lines) + "\n"
        ext = "md"
        mime = "text/markdown"

    if anonymize_ips:
        content = _anonymize_text(content)

    storage_key = f"orgs/{organization_id}/reports/{report_id}.{ext}"
    get_storage().put_bytes(storage_key, content.encode("utf-8"), content_type=mime)

    return {
        "report_id": report_id,
        "incident_id": incident.id,
        "format": fmt,
        "storage_key": storage_key,
        "download_url": f"/api/v1/reports/{report_id}/download?ext={ext}",
        "content_preview": content[:1200],
        "created_at": created_at,
    }
