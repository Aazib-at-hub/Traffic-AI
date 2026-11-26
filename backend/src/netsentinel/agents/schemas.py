"""Typed Pydantic v2 schemas for all 5 agents and shared LangGraph InvestigationState."""

from __future__ import annotations

from typing import Any, Literal, TypedDict

from pydantic import BaseModel, Field


class DetectionAnalystOutput(BaseModel):
    observations: list[str]
    key_indicators: list[str]
    epistemic_tier: Literal["anomalous", "suspicious"]
    search_queries: list[str]


class ThreatIntelOutput(BaseModel):
    matched_techniques: list[str]
    matched_cves: list[str]
    cited_chunk_ids: list[str]


class ClaimCitation(BaseModel):
    claim_text: str
    evidence_type: Literal["network_flow", "detection_result", "document_chunk", "historical_incident"]
    reference_id: str
    excerpt: str = ""


class CoordinatorOutput(BaseModel):
    executive_summary: str
    hypothesis: str
    timeline: list[str]
    claims_with_citations: list[ClaimCitation]
    confidence: Literal["low", "medium", "high"]


class RecommendationProposal(BaseModel):
    title: str
    category: Literal["containment", "eradication", "hardening", "monitoring"]
    priority: Literal["low", "medium", "high", "critical"]
    description: str
    risk_impact: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)


class ResponseAdvisorOutput(BaseModel):
    recommendations: list[RecommendationProposal]


class ClaimValidationVerdict(BaseModel):
    claim_text: str
    reference_id: str
    evidence_type: str
    validation_verdict: Literal["supported", "partially_supported", "unsupported"]
    validator_notes: str


class ValidatorOutput(BaseModel):
    overall_status: Literal["verified", "needs_revision", "flagged"]
    claim_verdicts: list[ClaimValidationVerdict]
    unsupported_claims: list[str]
    revision_feedback: str = ""


class InvestigationState(TypedDict):
    investigation_id: str
    organization_id: str
    incident_id: str
    alert_ids: list[str]
    flow_summaries: list[dict[str, Any]]
    detection_summaries: list[dict[str, Any]]
    detection_analysis: dict[str, Any] | None
    threat_intel_chunks: list[dict[str, Any]]
    threat_intel_summary: dict[str, Any] | None
    correlation_report: dict[str, Any] | None
    recommendations: list[dict[str, Any]]
    validation_result: dict[str, Any] | None
    revision_count: int
    agent_run_logs: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    status: Literal["running", "completed", "completed_flagged", "failed"]
