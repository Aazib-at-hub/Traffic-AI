"""Controlled 5-Agent LangGraph Investigation Workflow with deterministic Evidence Validator."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

try:
    from langgraph.graph import END, StateGraph
except ImportError:  # pragma: no cover — lightweight compatible runner when langgraph is absent
    END = "__end__"

    class _CompiledFallback:
        def __init__(self, nodes, entry, edges, cond_edges):
            self._nodes = nodes
            self._entry = entry
            self._edges = edges
            self._cond_edges = cond_edges

        def invoke(self, state):
            cur = dict(state)
            node_name = self._entry
            steps = 0
            while node_name != END and steps < 25:
                steps += 1
                update = self._nodes[node_name](cur)
                if update:
                    cur.update(update)
                if node_name in self._cond_edges:
                    router, mapping = self._cond_edges[node_name]
                    nxt = router(cur)
                    node_name = mapping.get(nxt, END)
                else:
                    node_name = self._edges.get(node_name, END)
            return cur

    class StateGraph:  # type: ignore[no-redef]
        def __init__(self, _state_type):
            self._nodes = {}
            self._entry = ""
            self._edges = {}
            self._cond_edges = {}

        def add_node(self, name, fn):
            self._nodes[name] = fn

        def set_entry_point(self, name):
            self._entry = name

        def add_edge(self, src, dst):
            self._edges[src] = dst

        def add_conditional_edges(self, src, router, mapping):
            self._cond_edges[src] = (router, mapping)

        def compile(self):
            return _CompiledFallback(self._nodes, self._entry, self._edges, self._cond_edges)
from sqlalchemy.orm import Session

from netsentinel.agents.llm import LLMAdapter, wrap_untrusted_data
from netsentinel.agents.schemas import (
    ClaimCitation,
    ClaimValidationVerdict,
    CoordinatorOutput,
    DetectionAnalystOutput,
    InvestigationState,
    RecommendationProposal,
    ResponseAdvisorOutput,
    ThreatIntelOutput,
    ValidatorOutput,
)
from netsentinel.core.errors import NotFoundError
from netsentinel.core.telemetry import create_langfuse_trace_id
from netsentinel.db.audit import record_audit
from netsentinel.db.models import (
    AgentRun,
    Alert,
    DetectionResult,
    DocumentChunk,
    EvidenceItem,
    Incident,
    IncidentAlert,
    Investigation,
    NetworkFlow,
    Recommendation,
)
from netsentinel.rag.retriever import hybrid_search, seed_default_security_knowledge

MAX_REVISIONS = 2


def _verify_reference_id_deterministic(
    db: Session,
    *,
    organization_id: str,
    evidence_type: str,
    reference_id: str,
) -> tuple[bool, str]:
    """Deterministic DB verification independent of any LLM provider (SRS SEC-008)."""
    if evidence_type == "network_flow":
        row = (
            db.query(NetworkFlow)
            .filter(NetworkFlow.id == reference_id, NetworkFlow.organization_id == organization_id)
            .first()
        )
        return (row is not None, f"Flow {row.src_ip}->{row.dst_ip}:{row.dst_port}" if row else "Flow ID not found")
    if evidence_type == "detection_result":
        row = (
            db.query(DetectionResult)
            .filter(
                DetectionResult.id == reference_id,
                DetectionResult.organization_id == organization_id,
            )
            .first()
        )
        return (
            row is not None,
            f"Detection tier={row.classification_tier}, class={row.predicted_class}" if row else "Detection ID not found",
        )
    if evidence_type == "document_chunk":
        row = db.query(DocumentChunk).filter(DocumentChunk.id == reference_id).first()
        return (row is not None, f"Chunk {row.section_header}" if row else "RAG chunk ID not found")
    if evidence_type == "historical_incident":
        row = (
            db.query(Incident)
            .filter(Incident.id == reference_id, Incident.organization_id == organization_id)
            .first()
        )
        return (row is not None, f"Incident {row.title}" if row else "Incident ID not found")
    return False, "Unsupported evidence_type"


def _build_investigation_graph(db: Session, llm: LLMAdapter):
    def detection_analyst_node(state: InvestigationState) -> dict[str, Any]:
        t0 = time.perf_counter()
        dets = state["detection_summaries"]
        flows = state["flow_summaries"]

        tiers = {d["classification_tier"] for d in dets}
        epistemic: Any = "suspicious" if "suspicious" in tiers else "anomalous"
        classes = sorted({d["predicted_class"] for d in dets if d["predicted_class"] != "benign"})
        ports = sorted({f["dst_port"] for f in flows})

        observations = [
            f"Analyzed {len(flows)} flow(s) and {len(dets)} ML detection result(s).",
            f"Observed classification tier: {epistemic} (anomaly detection alone does not prove compromise).",
        ]
        if classes:
            observations.append(f"Supervised classifier indicated potential attack families: {', '.join(classes)}.")
        indicators = [
            f"{f['src_ip']} -> {f['dst_ip']}:{f['dst_port']}/{f['protocol']} (bytes={f['bytes_total']})"
            for f in flows[:5]
        ]
        queries = []
        for cls in classes:
            queries.append(f"{cls.replace('_', ' ')} network attack MITRE ATT&CK mitigation")
        if 22 in ports:
            queries.append("SSH port 22 brute force CVE OpenSSH T1110")
        if not queries:
            queries.append("network anomaly port scan T1046 investigation playbook")

        fallback = DetectionAnalystOutput(
            observations=observations,
            key_indicators=indicators,
            epistemic_tier=epistemic,
            search_queries=queries[:3],
        ).model_dump()

        prompt = wrap_untrusted_data("ml_detections_and_flows", {"detections": dets, "flows": flows})
        raw, usage = llm.generate_json(
            system_prompt=(
                "You are the Detection Analyst Agent. Interpret ML scores and SHAP attributions. "
                "Never claim anomaly detection alone proves malicious activity. Output strict JSON."
            ),
            user_prompt=prompt,
            fallback_payload=fallback,
        )
        try:
            validated = DetectionAnalystOutput.model_validate(raw).model_dump()
        except Exception:
            validated = fallback

        run_log = {
            "agent_name": "Detection Analyst Agent",
            "step_order": len(state["agent_run_logs"]) + 1,
            "attempt_number": 1,
            "status": "completed",
            "input_payload": {"flow_count": len(flows), "detection_count": len(dets)},
            "output_payload": validated,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "token_usage": usage,
        }
        return {
            "detection_analysis": validated,
            "agent_run_logs": state["agent_run_logs"] + [run_log],
        }

    def threat_intel_node(state: InvestigationState) -> dict[str, Any]:
        t0 = time.perf_counter()
        analysis = state["detection_analysis"] or {}
        queries = analysis.get("search_queries") or ["network anomaly MITRE ATT&CK"]

        seen: dict[str, dict[str, Any]] = {}
        for q in queries[:3]:
            res = hybrid_search(
                db,
                query=q,
                organization_id=state["organization_id"],
                top_k=4,
                use_reranker=True,
            )
            for item in res["results"]:
                seen[item["chunk_id"]] = item

        chunks = sorted(seen.values(), key=lambda x: x["rerank_score"], reverse=True)[:6]
        techniques = sorted({c["external_id"] for c in chunks if c["source_type"] == "mitre_attack"})
        cves = sorted({c["external_id"] for c in chunks if c["source_type"] == "cve"})

        summary = ThreatIntelOutput(
            matched_techniques=techniques,
            matched_cves=cves,
            cited_chunk_ids=[c["chunk_id"] for c in chunks],
        ).model_dump()

        run_log = {
            "agent_name": "Threat Intelligence Agent",
            "step_order": len(state["agent_run_logs"]) + 1,
            "attempt_number": 1,
            "status": "completed",
            "input_payload": {"queries": queries[:3]},
            "output_payload": summary,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }
        return {
            "threat_intel_chunks": chunks,
            "threat_intel_summary": summary,
            "agent_run_logs": state["agent_run_logs"] + [run_log],
        }

    def coordinator_node(state: InvestigationState) -> dict[str, Any]:
        t0 = time.perf_counter()
        dets = state["detection_summaries"]
        flows = state["flow_summaries"]
        chunks = state["threat_intel_chunks"]
        analysis = state["detection_analysis"] or {}

        claims: list[ClaimCitation] = []
        for d in dets[:3]:
            claims.append(
                ClaimCitation(
                    claim_text=(
                        f"ML detection classified flow as {d['classification_tier']} "
                        f"(class={d['predicted_class']}, anomaly_score={d['anomaly_score']})."
                    ),
                    evidence_type="detection_result",
                    reference_id=d["detection_result_id"],
                    excerpt=f"class={d['predicted_class']}, confidence={d['confidence']}",
                )
            )
        for f in flows[:2]:
            claims.append(
                ClaimCitation(
                    claim_text=(
                        f"Observed network flow {f['src_ip']} -> {f['dst_ip']}:{f['dst_port']} "
                        f"({f['protocol']}, {f['bytes_total']} bytes)."
                    ),
                    evidence_type="network_flow",
                    reference_id=f["flow_id"],
                    excerpt=f"fwd={f['fwd_packets']}, bwd={f['bwd_packets']}",
                )
            )
        for c in chunks[:3]:
            claims.append(
                ClaimCitation(
                    claim_text=f"Matched threat intelligence reference {c['external_id']}: {c['title']}.",
                    evidence_type="document_chunk",
                    reference_id=c["chunk_id"],
                    excerpt=c["content"][:180],
                )
            )

        tier = analysis.get("epistemic_tier", "anomalous")
        fallback = CoordinatorOutput(
            executive_summary=(
                f"Correlated {len(dets)} ML detection(s) ({tier}) across {len(flows)} flow(s) "
                f"with {len(chunks)} security intelligence reference(s). Human analyst review required."
            ),
            hypothesis=(
                f"Traffic exhibits {tier} behavior aligned with retrieved intelligence "
                f"({', '.join(c['external_id'] for c in chunks[:3]) or 'general baseline deviation'})."
            ),
            timeline=[
                f"Flow telemetry recorded across {len(flows)} bidirectional session(s).",
                f"ML engine flagged {len(dets)} detection result(s) as {tier}.",
                f"Hybrid RAG retrieved {len(chunks)} contextual intelligence chunk(s).",
            ],
            claims_with_citations=claims,
            confidence="medium" if tier == "suspicious" else "low",
        ).model_dump()

        user_prompt = wrap_untrusted_data(
            "correlation_context",
            {
                "analysis": analysis,
                "chunks": [{"chunk_id": c["chunk_id"], "external_id": c["external_id"], "title": c["title"]} for c in chunks],
                "validator_feedback": (state.get("validation_result") or {}).get("revision_feedback", ""),
            },
        )
        raw, usage = llm.generate_json(
            system_prompt=(
                "You are the Investigation Coordinator Agent. Correlate ML evidence and RAG intel. "
                "Attach exact reference_ids to every claim. Never state confirmed compromise without human sign-off."
            ),
            user_prompt=user_prompt,
            fallback_payload=fallback,
        )
        try:
            validated = CoordinatorOutput.model_validate(raw).model_dump()
        except Exception:
            validated = fallback

        run_log = {
            "agent_name": "Investigation Coordinator Agent",
            "step_order": len(state["agent_run_logs"]) + 1,
            "attempt_number": state["revision_count"] + 1,
            "status": "completed",
            "input_payload": {"revision_count": state["revision_count"]},
            "output_payload": validated,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "token_usage": usage,
        }
        return {
            "correlation_report": validated,
            "agent_run_logs": state["agent_run_logs"] + [run_log],
        }

    def response_advisor_node(state: InvestigationState) -> dict[str, Any]:
        t0 = time.perf_counter()
        chunks = state["threat_intel_chunks"]
        dets = state["detection_summaries"]
        evidence_ids = [d["detection_result_id"] for d in dets[:2]] + [c["chunk_id"] for c in chunks[:2]]

        proposals = [
            RecommendationProposal(
                title="Validate Source Host & Correlate Endpoint Logs",
                category="monitoring",
                priority="high",
                description=(
                    "Inspect source host process activity and authentication logs corresponding to the "
                    "flagged network flows before applying network-level blocks."
                ),
                risk_impact="Low operational impact (read-only verification).",
                supporting_evidence_ids=evidence_ids,
            ),
            RecommendationProposal(
                title="Prepare Approval-Gated Firewall Rate-Limit / ACL Rule",
                category="containment",
                priority="medium",
                description=(
                    "If analyst confirms unauthorized scanning or brute-force traffic, apply temporary "
                    "ingress rate-limiting or source IP block on perimeter firewall after responder approval."
                ),
                risk_impact="Medium operational impact — verify source IP is not an authorized scanner or NAT gateway.",
                supporting_evidence_ids=evidence_ids,
            ),
        ]
        fallback = ResponseAdvisorOutput(recommendations=proposals).model_dump()
        raw, usage = llm.generate_json(
            system_prompt=(
                "You are the Response Advisor Agent. Propose proportional, reversible mitigation steps. "
                "You CANNOT execute any actions. Every recommendation requires human approval."
            ),
            user_prompt=wrap_untrusted_data("correlation_report", state["correlation_report"]),
            fallback_payload=fallback,
        )
        try:
            validated = ResponseAdvisorOutput.model_validate(raw).model_dump()
        except Exception:
            validated = fallback

        run_log = {
            "agent_name": "Response Advisor Agent",
            "step_order": len(state["agent_run_logs"]) + 1,
            "attempt_number": state["revision_count"] + 1,
            "status": "completed",
            "input_payload": {"claim_count": len((state["correlation_report"] or {}).get("claims_with_citations", []))},
            "output_payload": validated,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "token_usage": usage,
        }
        return {
            "recommendations": validated["recommendations"],
            "agent_run_logs": state["agent_run_logs"] + [run_log],
        }

    def evidence_validator_node(state: InvestigationState) -> dict[str, Any]:
        t0 = time.perf_counter()
        report = state["correlation_report"] or {}
        claims = report.get("claims_with_citations", [])

        verdicts: list[ClaimValidationVerdict] = []
        unsupported: list[str] = []

        for claim in claims:
            exists, note = _verify_reference_id_deterministic(
                db,
                organization_id=state["organization_id"],
                evidence_type=claim["evidence_type"],
                reference_id=claim["reference_id"],
            )
            if exists:
                verdicts.append(
                    ClaimValidationVerdict(
                        claim_text=claim["claim_text"],
                        reference_id=claim["reference_id"],
                        evidence_type=claim["evidence_type"],
                        validation_verdict="supported",
                        validator_notes=f"Deterministic verification passed: {note}",
                    )
                )
            else:
                unsupported.append(claim["claim_text"])
                verdicts.append(
                    ClaimValidationVerdict(
                        claim_text=claim["claim_text"],
                        reference_id=claim["reference_id"],
                        evidence_type=claim["evidence_type"],
                        validation_verdict="unsupported",
                        validator_notes=f"Deterministic verification failed: {note}",
                    )
                )

        if not claims:
            overall: Any = "flagged"
            feedback = "No cited claims provided."
        elif unsupported:
            overall = "needs_revision" if state["revision_count"] < MAX_REVISIONS else "flagged"
            feedback = f"{len(unsupported)} claim(s) failed deterministic reference ID verification."
        else:
            overall = "verified"
            feedback = "All cited claims verified against PostgreSQL records and RAG chunks."

        val_out = ValidatorOutput(
            overall_status=overall,
            claim_verdicts=verdicts,
            unsupported_claims=unsupported,
            revision_feedback=feedback,
        ).model_dump()

        new_rev = state["revision_count"] + (1 if overall == "needs_revision" else 0)
        final_status: Any = (
            "completed"
            if overall == "verified"
            else ("completed_flagged" if overall == "flagged" else "running")
        )

        run_log = {
            "agent_name": "Evidence Validator Agent",
            "step_order": len(state["agent_run_logs"]) + 1,
            "attempt_number": state["revision_count"] + 1,
            "status": "completed",
            "input_payload": {"claims_checked": len(claims)},
            "output_payload": val_out,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "token_usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }
        return {
            "validation_result": val_out,
            "revision_count": new_rev,
            "status": final_status,
            "agent_run_logs": state["agent_run_logs"] + [run_log],
        }

    def route_after_validation(state: InvestigationState) -> str:
        val = state.get("validation_result") or {}
        if val.get("overall_status") == "needs_revision" and state["revision_count"] <= MAX_REVISIONS:
            return "InvestigationCoordinator"
        return END

    graph = StateGraph(InvestigationState)
    graph.add_node("DetectionAnalyst", detection_analyst_node)
    graph.add_node("ThreatIntelligence", threat_intel_node)
    graph.add_node("InvestigationCoordinator", coordinator_node)
    graph.add_node("ResponseAdvisor", response_advisor_node)
    graph.add_node("EvidenceValidator", evidence_validator_node)

    graph.set_entry_point("DetectionAnalyst")
    graph.add_edge("DetectionAnalyst", "ThreatIntelligence")
    graph.add_edge("ThreatIntelligence", "InvestigationCoordinator")
    graph.add_edge("InvestigationCoordinator", "ResponseAdvisor")
    graph.add_edge("ResponseAdvisor", "EvidenceValidator")
    graph.add_conditional_edges(
        "EvidenceValidator",
        route_after_validation,
        {"InvestigationCoordinator": "InvestigationCoordinator", END: END},
    )
    return graph.compile()


def execute_incident_investigation(
    db: Session,
    *,
    organization_id: str,
    incident_id: str,
    triggered_by: str,
) -> Investigation:
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == organization_id)
        .first()
    )
    if incident is None:
        raise NotFoundError("Incident")

    # Ensure baseline security intel is seeded if RAG table is empty
    if db.query(DocumentChunk).count() == 0:
        seed_default_security_knowledge(db)

    linked = (
        db.query(Alert)
        .join(IncidentAlert, IncidentAlert.alert_id == Alert.id)
        .filter(IncidentAlert.incident_id == incident_id, Alert.organization_id == organization_id)
        .all()
    )

    detection_summaries: list[dict[str, Any]] = []
    flow_summaries: list[dict[str, Any]] = []
    seen_flows: set[str] = set()

    for alert in linked:
        det = db.get(DetectionResult, alert.detection_result_id)
        if det is None:
            continue
        detection_summaries.append(
            {
                "detection_result_id": det.id,
                "flow_id": det.flow_id,
                "anomaly_score": det.anomaly_score,
                "predicted_class": det.predicted_class,
                "confidence": det.confidence,
                "classification_tier": det.classification_tier,
                "shap_values": det.shap_values[:5],
            }
        )
        if det.flow_id not in seen_flows:
            flow = db.get(NetworkFlow, det.flow_id)
            if flow is not None:
                seen_flows.add(flow.id)
                flow_summaries.append(
                    {
                        "flow_id": flow.id,
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "src_port": flow.src_port,
                        "dst_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "bytes_total": flow.bytes_total,
                        "fwd_packets": flow.fwd_packets,
                        "bwd_packets": flow.bwd_packets,
                    }
                )

    inv = Investigation(
        organization_id=organization_id,
        incident_id=incident_id,
        triggered_by=triggered_by,
        status="running",
        validation_status="pending",
    )
    db.add(inv)
    db.flush()
    inv.langfuse_trace_id = create_langfuse_trace_id(inv.id)
    db.commit()

    initial_state: InvestigationState = {
        "investigation_id": inv.id,
        "organization_id": organization_id,
        "incident_id": incident_id,
        "alert_ids": [a.id for a in linked],
        "flow_summaries": flow_summaries,
        "detection_summaries": detection_summaries,
        "detection_analysis": None,
        "threat_intel_chunks": [],
        "threat_intel_summary": None,
        "correlation_report": None,
        "recommendations": [],
        "validation_result": None,
        "revision_count": 0,
        "agent_run_logs": [],
        "errors": [],
        "status": "running",
    }

    compiled = _build_investigation_graph(db, LLMAdapter())
    final_state = compiled.invoke(initial_state)

    report = final_state.get("correlation_report") or {}
    val = final_state.get("validation_result") or {}

    inv.status = "completed" if final_state["status"] in ("completed", "completed_flagged") else "failed"
    inv.executive_summary = report.get("executive_summary", "")
    inv.hypothesis = report.get("hypothesis", "")
    inv.validation_status = val.get("overall_status", "flagged")
    inv.revision_count = int(final_state.get("revision_count", 0))
    inv.state_snapshot = {
        "detection_analysis": final_state.get("detection_analysis"),
        "threat_intel_summary": final_state.get("threat_intel_summary"),
        "timeline": report.get("timeline", []),
        "confidence": report.get("confidence", "low"),
    }
    inv.completed_at = datetime.now(timezone.utc)

    for run in final_state.get("agent_run_logs", []):
        db.add(
            AgentRun(
                organization_id=organization_id,
                investigation_id=inv.id,
                agent_name=run["agent_name"],
                step_order=run["step_order"],
                attempt_number=run["attempt_number"],
                status=run["status"],
                input_payload=run["input_payload"],
                output_payload=run["output_payload"],
                latency_ms=run["latency_ms"],
                token_usage=run["token_usage"],
            )
        )

    for v in val.get("claim_verdicts", []):
        db.add(
            EvidenceItem(
                organization_id=organization_id,
                investigation_id=inv.id,
                evidence_type=v["evidence_type"],
                reference_id=v["reference_id"],
                claim_text=v["claim_text"],
                validation_verdict=v["validation_verdict"],
                validator_notes=v["validator_notes"],
            )
        )

    for rec in final_state.get("recommendations", []):
        db.add(
            Recommendation(
                organization_id=organization_id,
                investigation_id=inv.id,
                title=rec["title"],
                category=rec["category"],
                priority=rec["priority"],
                description=rec["description"],
                risk_impact=rec["risk_impact"],
                supporting_evidence_ids=rec.get("supporting_evidence_ids", []),
                approval_status="pending_approval",
            )
        )

    incident.status = "investigating"
    record_audit(
        db,
        action="investigation.completed",
        resource_type="investigation",
        organization_id=organization_id,
        actor_user_id=triggered_by,
        actor_type="agent",
        resource_id=inv.id,
        metadata={
            "incident_id": incident_id,
            "validation_status": inv.validation_status,
            "revision_count": inv.revision_count,
        },
    )
    db.commit()
    db.refresh(inv)
    return inv
