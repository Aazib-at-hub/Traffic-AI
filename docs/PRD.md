# NetSentinel AI — Product Requirements Document (PRD)

---

## 1. Document Control

| Field | Value |
| :--- | :--- |
| **Project Name** | NetSentinel AI |
| **Document Title** | Product Requirements Document (PRD) |
| **Version** | 1.0.0-draft |
| **Status** | Draft — Baseline Specification (Greenfield Repository) |
| **Document Owner** | Product Management & Principal Architecture |
| **Last Updated** | 2026-11-27 |
| **Intended Audience** | Engineering, ML/AI Research, Security Engineering, Product Design, QA, Stakeholders |
| **Related Documents** | [SRS.md](SRS.md), [README.md](../README.md) |

> **Repository Baseline Note:** At the time of authoring, the project repository is empty (greenfield). All capabilities described in this document represent **planned requirements** unless explicitly marked otherwise. No application code, models, or infrastructure are currently implemented.

---

## 2. Executive Summary

**NetSentinel AI** is an AI-powered cybersecurity platform for **Intelligent Network Threat Detection and Autonomous Security Investigation**. It bridges the operational gap between raw network telemetry analysis and contextual incident investigation.

Security Operations Center (SOC) teams routinely struggle with high alert volumes, fragmented threat intelligence, and opaque anomaly alerts that lack actionable context. NetSentinel AI addresses this by combining four tightly integrated layers:

1. **Deterministic Network Processing:** Validates and parses PCAP captures into structured bidirectional network flows and protocol metadata.
2. **Explainable Machine Learning Detection:** Runs modular unsupervised (Isolation Forest, optional Autoencoder) and supervised (XGBoost / Random Forest) models with SHAP-based feature attribution. Crucially, the platform distinguishes between **anomalous**, **suspicious**, and **confirmed malicious** activity rather than equating statistical anomalies with confirmed compromises.
3. **Evidence-Grounded Security Intelligence RAG:** Retrieves relevant MITRE ATT&CK techniques, CVEs, security advisories, and historical incident reports using hybrid retrieval (dense vector + keyword search), Reciprocal Rank Fusion (RRF), and cross-encoder reranking.
4. **Controlled Multi-Agent Investigation:** Orchestrates five specialized LangGraph agents—Detection Analyst, Threat Intelligence, Investigation Coordinator, Response Advisor, and Evidence Validator—under strict state schemas, deterministic verification, bounded retries, and mandatory human-in-the-loop approval for all response actions.

---

## 3. Product Vision and Mission

- **Vision:** Empower every security team to investigate complex network threats with the rigor of a senior incident responder, combining deterministic ML detection with verifiable, evidence-backed AI reasoning.
- **Mission:** Reduce alert triage fatigue and Mean Time to Investigate (MTTI) by uniting network flow analytics, explainable anomaly/attack detection, curated threat intelligence retrieval, and auditable agentic investigation workflows inside a single security operations platform.

---

## 4. Problem Statement

Modern network monitoring tools generate thousands of alerts daily, yet SOC analysts face four compounding challenges:

1. **Context-Free Anomaly Alerts:** Traditional anomaly detectors flag unusual statistical patterns without explaining *why* a flow is unusual or what attack technique it might represent.
2. **Manual Investigation Bottlenecks:** Correlating packet/flow metadata with MITRE ATT&CK tactics, CVE databases, and prior incident reports requires switching across disparate tools, driving up MTTI.
3. **Opaque AI & Hallucination Risk:** Unconstrained LLM wrappers applied to security logs risk fabricating indicators, misattributing benign anomalies as attacks, or suggesting unsafe remediation actions.
4. **Lack of Reproducibility and Auditability:** Ad-hoc analyst investigations rarely leave a structured, evidence-linked audit trail connecting raw network flows to final incident conclusions.

---

## 5. Market and User Context

Security teams across mid-market enterprises, managed security service providers (MSSPs), and academic/research labs need practical threat investigation platforms that:
- Operate on standard packet capture artifacts (`.pcap`, `.pcapng`) for forensic and retrospective analysis before expanding to live network taps.
- Provide transparent ML predictions rather than black-box scores so analysts can validate findings and tune false-positive rates.
- Support self-hosted and cloud-native deployments with strict tenant isolation, since network traffic captures frequently contain sensitive internal topology and payload metadata.
- Keep human analysts firmly in control of containment and remediation decisions.

---

## 6. Target Audience and User Personas

| Persona ID | Role | Primary Responsibilities | Technical Proficiency | Key Needs from NetSentinel AI |
| :--- | :--- | :--- | :--- | :--- |
| **PER-01** | **Tier-1 SOC Analyst** | Alert triage, initial validation, escalation to Tier-2 | Intermediate networking & SIEM | Fast triage, clear plain-language explanations of ML scores, noise reduction |
| **PER-02** | **Tier-2/3 Incident Responder** | Deep packet/flow forensics, threat hunting, containment planning | Advanced networking, MITRE ATT&CK, DFIR | Evidence-linked investigation timelines, ATT&CK/CVE mapping, verifiable mitigation steps |
| **PER-03** | **Detection / ML Engineer** | Dataset curation, model training, threshold tuning, drift monitoring | Advanced Python, ML, network security | Model versioning, evaluation metrics, SHAP explainability, reproducible pipelines |
| **PER-04** | **SOC Manager / CISO** | Team KPIs, compliance, executive reporting, risk oversight | Strategic / governance-focused | Executive incident reports, audit logs, MTTI tracking, strict action guardrails |
| **PER-05** | **Platform Administrator** | Tenant onboarding, RBAC, knowledge base maintenance, system health | DevOps, Linux, Docker, IAM | Multi-tenant isolation, health telemetry, secure secret/key management |

---

## 7. User Pain Points

| Pain Point ID | Affected Personas | Description |
| :--- | :--- | :--- |
| **PP-01** | PER-01, PER-02 | High false-positive rates in unsupervised anomaly detectors cause alert fatigue and missed true positives. |
| **PP-02** | PER-01, PER-02 | Manual cross-referencing of flow anomalies against MITRE ATT&CK and CVE feeds consumes 30–60+ minutes per incident. |
| **PP-03** | PER-02, PER-04 | AI-generated summaries frequently lack citations or conflate statistical anomalies with confirmed breaches. |
| **PP-04** | PER-03 | Lack of visibility into feature contributions and model drift prevents safe deployment of ML models in SOC workflows. |
| **PP-05** | PER-04, PER-05 | Absence of immutable audit trails and approval gates blocks adoption of AI-assisted tools in regulated environments. |

---

## 8. Product Goals

| Goal ID | Goal Statement | Target Phase |
| :--- | :--- | :--- |
| **PG-01** | Deliver reliable asynchronous PCAP ingestion and deterministic bidirectional flow feature extraction. | MVP (v1.0) |
| **PG-02** | Provide modular, explainable ML detection combining unsupervised anomaly scoring and supervised attack classification. | MVP (v1.0) |
| **PG-03** | Ground all threat intelligence reasoning in a hybrid RAG pipeline with verifiable document citations. | MVP (v1.0) |
| **PG-04** | Orchestrate structured, bounded, evidence-validated multi-agent investigations with mandatory human approval for response actions. | MVP (v1.0) |
| **PG-05** | Provide a unified Security Operations Dashboard with RBAC, multi-tenant isolation, and comprehensive audit logging. | MVP (v1.0) |
| **PG-06** | Extend platform capabilities to live traffic streaming, drift monitoring, and automated SOAR integrations. | Post-MVP (v1.1–v2.0) |

---

## 9. Measurable Success Criteria

> **Note:** All numerical targets below are **proposed targets** to be validated during implementation and evaluation. No benchmark results exist yet.

| Criterion ID | Metric | Proposed Target | Measurement Method |
| :--- | :--- | :--- | :--- |
| **SC-01** | PCAP Ingestion Reliability | ≥ 99% valid PCAPs parsed without worker crash (up to 500 MB per file in MVP) | Automated integration test suite with diverse PCAP corpus |
| **SC-02** | Supervised Detection Macro F1 | ≥ 0.88 Macro F1 on held-out test split (CIC-IDS2017 / UNSW-NB15) | Offline ML evaluation harness |
| **SC-03** | False Positive Rate (FPR) | ≤ 3% at calibrated operating threshold on benign validation traffic | Evaluation suite confusion matrix |
| **SC-04** | RAG Retrieval Quality | Recall@5 ≥ 0.85 and MRR@10 ≥ 0.75 on curated security QA benchmark | Retrieval evaluation pipeline |
| **SC-05** | Evidence Grounding Rate | ≥ 95% of claims in final investigation reports pass Evidence Validator verification | Automated Evidence Validator audit metrics |
| **SC-06** | Investigation Turnaround Time | ≤ 90 seconds end-to-end (p95) for a standard single-incident agent investigation | OpenTelemetry + Langfuse trace telemetry |
| **SC-07** | Zero Unauthorized Actions | 0 autonomous execution of containment/blocking actions without explicit human approval | Security test suite & audit log verification |
| **SC-08** | Analyst Triage Time Reduction | ≥ 40% reduction in simulated triage time compared to raw flow inspection | Usability testing with structured SOC scenarios |

---

## 10. Product Scope

### 10.1 In Scope (MVP — v1.0)
- Multi-tenant authentication, RBAC, and organization-scoped data isolation.
- Asynchronous PCAP/PCAPNG upload (object storage backed), validation, and flow feature extraction.
- Modular ML detection engine: Isolation Forest (unsupervised), XGBoost / Random Forest (supervised), model versioning, and SHAP explainability.
- Security Intelligence RAG pipeline ingesting MITRE ATT&CK, CVE records, advisories, and internal security docs with hybrid retrieval (pgvector + PostgreSQL FTS), RRF, and cross-encoder reranking.
- LangGraph 5-agent investigation workflow with typed state, bounded retries, timeouts, evidence validation, and human-in-the-loop approval for recommendations.
- Security Operations Dashboard (overview, traffic analytics, datasets, alerts, incidents, investigation workspace, threat intel viewer, agent history, reports, model analytics, audit logs).
- Docker Compose deployment, CI pipeline, OpenTelemetry + Langfuse observability.

### 10.2 Out of Scope (Explicitly Excluded from v1.0)
- Autonomous firewall rule modification, host isolation, or automated active network defense.
- Deep Packet Inspection (DPI) decryption of TLS-encrypted application payloads without customer-supplied keys.
- Claiming that an LLM independently detects network attacks from raw packets.
- Full SIEM log aggregation across endpoints (EDR/Sysmon/Windows Event Logs).
- Microservices decomposition (explicitly using a modular monolith with background workers).

### 10.3 Future Scope (Post-MVP — v1.1 to v2.0+)
- Live network traffic ingestion via packet capture sensors / NetFlow / IPFIX / Zeek streams.
- Optional Autoencoder-based unsupervised anomaly detection model.
- Automated feature drift and concept drift alerting with scheduled retraining pipelines.
- External ticketing and SOAR webhook integrations (e.g., Jira, ServiceNow, Slack, TheHive) with human approval gates.
- Federated/custom threat intelligence feeds (STIX/TAXII ingestion).

---

## 11. Functional Product Modules

| Module ID | Module Name | Core Responsibility | Phase |
| :--- | :--- | :--- | :--- |
| **MOD-01** | Identity, Tenancy & Access Control | User auth, JWT sessions, organization isolation, RBAC enforcement | MVP |
| **MOD-02** | Traffic Ingestion & Flow Engine | PCAP upload, magic-byte validation, async parsing, bidirectional flow extraction | MVP |
| **MOD-03** | ML Detection & Explainability Engine | Feature preprocessing, Isolation Forest + XGBoost/RF inference, SHAP attributions, model registry | MVP |
| **MOD-04** | Alert & Incident Management | Alert generation, deduplication, status lifecycle (`anomalous` vs `suspicious` vs `confirmed_malicious`), incident correlation | MVP |
| **MOD-05** | Security Intelligence RAG | Document ingestion, chunking, BGE embeddings, pgvector + keyword hybrid search, RRF, BGE reranking | MVP |
| **MOD-06** | Multi-Agent Investigation Engine | LangGraph orchestration of 5 specialized agents, evidence validation, approval workflow | MVP |
| **MOD-07** | Security Operations Dashboard | React + TypeScript web interface for monitoring, investigation, reporting, and administration | MVP |
| **MOD-08** | Observability & Audit Subsystem | Immutable audit logs, OpenTelemetry traces, Langfuse LLM/agent telemetry | MVP |
| **MOD-09** | Live Traffic & Drift Monitoring | Real-time flow streaming, PSI/KS drift checks, Autoencoder anomaly model | Post-MVP |

---

## 12. User Journeys

### Journey 1: Forensic PCAP Upload to Verified Incident Report (PER-01 / PER-02)
1. Analyst logs into NetSentinel AI and selects their organization workspace.
2. Analyst uploads a suspicious `.pcap` file in **Dataset Management** with metadata tags.
3. System validates the file, stores it in object storage, and enqueues an asynchronous extraction job.
4. Dashboard displays processing progress; upon completion, Traffic Analytics shows flow distributions, top talkers, and protocol breakdowns.
5. Analyst triggers ML Detection (or auto-trigger runs); system scores flows using Isolation Forest and XGBoost, computes SHAP explanations, and creates prioritized alerts marked `anomalous` or `suspicious`.
6. Analyst promotes a cluster of related alerts into an **Incident** and launches an **Autonomous Investigation**.
7. LangGraph executes the 5-agent workflow; analyst monitors live node progress in the Investigation Workspace.
8. Evidence Validator verifies all claims against flow records and retrieved MITRE ATT&CK / CVE chunks.
9. Analyst reviews the investigation timeline, inspects SHAP plots and cited sources, approves or rejects recommended mitigation steps, updates incident verdict (e.g., `confirmed_malicious` or `false_positive`), and exports a structured Incident Report.

### Journey 2: Model Evaluation & Promotion (PER-03)
1. Detection Engineer trains a new XGBoost model version on curated CIC-IDS2017 / UNSW-NB15 features via the training pipeline.
2. Engineer reviews Precision, Recall, Macro F1, PR-AUC, ROC-AUC, FPR, and confusion matrix in **Model Performance Analytics**.
3. Engineer promotes the validated model artifact to `active` status; subsequent inference jobs reference the new `model_version_id`.

### Journey 3: Threat Intelligence Knowledge Base Update (PER-02 / PER-05)
1. Administrator uploads updated MITRE ATT&CK STIX/Markdown docs, CVE advisories, or internal runbooks.
2. RAG ingestion pipeline parses, chunks, extracts metadata, generates BGE embeddings, and indexes chunks into PostgreSQL (`pgvector` + FTS).
3. Analysts test retrieval relevance in the **Threat Intelligence Viewer** and verify citation links.

---

## 13. User Stories

| Story ID | Persona | User Story | Acceptance Criteria | Priority | Phase |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **US-001** | PER-01 | As a SOC Analyst, I want to authenticate securely and access only my organization's data so that tenant traffic remains isolated. | Login returns short-lived JWT + refresh token; cross-tenant API queries return HTTP 403/404. | Must | MVP |
| **US-002** | PER-01 | As a SOC Analyst, I want to upload PCAP/PCAPNG files and see validation feedback so that malformed or oversized files fail gracefully. | Files validated by magic bytes & size limit; stored in S3-compatible storage; job ID returned within 2s. | Must | MVP |
| **US-003** | PER-01 | As a SOC Analyst, I want large PCAP files processed in the background with real-time status updates so the UI never blocks. | Background worker updates status (`queued` → `processing` → `completed`/`failed`) with error details on failure. | Must | MVP |
| **US-004** | PER-01 | As a SOC Analyst, I want to explore extracted network flows by IP, port, protocol, and timestamp so I can inspect raw context. | Paginated flow table supports filtering and sorting; returns < 500ms for 100k indexed flows. | Must | MVP |
| **US-005** | PER-02 | As an Incident Responder, I want ML anomaly and attack classification scores on every flow so I can prioritize suspicious traffic. | Detection results store anomaly score, predicted class, confidence, and `classification_tier` (`benign`, `anomalous`, `suspicious`). | Must | MVP |
| **US-006** | PER-02 | As an Incident Responder, I want SHAP feature explanations for flagged flows so I understand *why* the model flagged them. | Top-K positive/negative contributing features persisted and rendered per flagged detection. | Must | MVP |
| **US-007** | PER-01 | As a SOC Analyst, I want to triage, filter, assign, and update alert statuses so I can manage my queue. | Alerts support status transitions (`open`, `triaging`, `escalated`, `resolved`, `false_positive`) logged to `audit_logs`. | Must | MVP |
| **US-008** | PER-02 | As an Incident Responder, I want to group related alerts into an Incident so I can investigate an attack campaign holistically. | Incidents link multiple alerts via `incident_alerts` with severity, verdict, and timeline. | Must | MVP |
| **US-009** | PER-05 | As a Platform Admin, I want to ingest MITRE ATT&CK, CVE, and internal security documents into the RAG knowledge base so agents have current context. | Ingestion pipeline chunks, embeds, and indexes documents with source metadata and version tracking. | Must | MVP |
| **US-010** | PER-02 | As an Incident Responder, I want to search the security knowledge base using hybrid semantic + keyword search so exact CVE IDs and conceptual queries both succeed. | Search combines dense vector + FTS via RRF and cross-encoder reranking, returning ranked chunks with citations. | Must | MVP |
| **US-011** | PER-02 | As an Incident Responder, I want to trigger a multi-agent investigation on an incident so I receive a structured, evidence-backed analysis. | LangGraph runs all 5 agents with typed state, saving `agent_runs`, `evidence_items`, and `recommendations`. | Must | MVP |
| **US-012** | PER-02 | As an Incident Responder, I want every claim in an investigation report to be verified against retrieved evidence so hallucinations are flagged or blocked. | Evidence Validator marks each claim `supported`, `partially_supported`, or `unsupported`; unsupported claims are flagged/redacted. | Must | MVP |
| **US-013** | PER-02 | As an Incident Responder, I want recommended containment actions to require explicit human approval so the platform never executes destructive changes autonomously. | Recommendations default to `pending_approval`; only authorized roles can approve/reject; no auto-execution occurs. | Must | MVP |
| **US-014** | PER-02 | As an Incident Responder, I want to inspect the step-by-step agent execution graph and history so I can audit how conclusions were reached. | Agent Execution History displays node transitions, inputs/outputs, latencies, token usage, and retry counts. | Must | MVP |
| **US-015** | PER-04 | As a SOC Manager, I want to export structured incident reports (Markdown/JSON/PDF) so I can share findings with leadership. | Report includes executive summary, flow evidence, SHAP highlights, ATT&CK/CVE citations, and approved mitigations. | Should | MVP |
| **US-016** | PER-03 | As an ML Engineer, I want to view model versions and evaluation metrics in the dashboard so I can monitor detection quality. | Model Performance Analytics displays version metadata, Precision, Recall, Macro F1, PR-AUC, ROC-AUC, FPR, and confusion matrix. | Should | MVP |
| **US-017** | PER-04 | As a SOC Manager, I want immutable audit logs of all user and agent actions so we satisfy security compliance requirements. | All auth, upload, verdict change, investigation trigger, and recommendation approval events are recorded in `audit_logs`. | Must | MVP |
| **US-018** | PER-03 | As an ML Engineer, I want an optional Autoencoder anomaly detector alongside Isolation Forest so I can compare non-linear reconstruction anomalies. | Modular model interface supports plugging in Autoencoder artifacts with standardized anomaly score output. | Could | Post-MVP |
| **US-019** | PER-02 | As an Incident Responder, I want live network traffic monitoring so threats are detected in near real-time without manual PCAP uploads. | Streaming collector ingests flows continuously into detection pipeline with sliding-window alerting. | Could | Post-MVP |
| **US-020** | PER-03 | As an ML Engineer, I want automated feature drift detection alerts so I know when network baselines shift. | Periodic PSI/KS drift checks flag significant distribution shifts per feature. | Could | Post-MVP |

---

## 14. Feature Prioritization (MoSCoW)

| Priority | Features |
| :--- | :--- |
| **Must Have (MVP)** | Auth & RBAC; multi-tenant isolation; PCAP upload & validation; async flow extraction; Isolation Forest + XGBoost/RF detection; SHAP explainability; `anomalous`/`suspicious`/`confirmed_malicious` taxonomy; Alert & Incident CRUD; Hybrid RAG (pgvector + FTS + RRF + BGE reranker); 5-agent LangGraph investigation workflow; Evidence Validator; Human-in-the-loop recommendation approval; Core SOC Dashboard; Audit logging; Docker Compose setup. |
| **Should Have (MVP+)** | Incident report export (Markdown/JSON/PDF); Model Performance Analytics UI; React Flow interactive agent workflow visualizer; RAG retrieval evaluation harness; OpenTelemetry + Langfuse tracing integration. |
| **Could Have (Post-MVP)** | Optional Autoencoder anomaly detector; Live traffic monitoring (Zeek/NetFlow/pcap stream); Automated feature/concept drift monitoring; STIX/TAXII threat feed sync; External SOAR/ticketing webhooks (approval-gated). |
| **Won't Have (v1.0)** | Autonomous firewall/EDR blocking without human approval; Decryption of third-party TLS payloads; Full endpoint SIEM replacement; Microservices architecture split. |

---

## 15. Product Workflows

### 15.1 Detection & Investigation Lifecycle
1. **Ingest:** Upload PCAP → Object Storage → Async Flow Extraction → `network_flows`.
2. **Detect:** Feature Preprocessing → Unsupervised (Isolation Forest) + Supervised (XGBoost/RF) → SHAP Attribution → `detection_results` → `alerts`.
3. **Correlate:** Analyst groups alerts → `incidents`.
4. **Investigate:** LangGraph workflow (`Detection Analyst` → `Threat Intelligence` → `Investigation Coordinator` → `Response Advisor` → `Evidence Validator`) → `investigations`, `agent_runs`, `evidence_items`, `recommendations`.
5. **Decide & Report:** Analyst reviews verified evidence → Approves/rejects recommendations → Sets final verdict (`confirmed_malicious`, `suspicious`, `benign`, `false_positive`) → Generates report.

---

## 16. AI/ML Capabilities

- **Dual-Paradigm Detection:** Combines unsupervised anomaly detection (Isolation Forest; optional Autoencoder later) to catch novel/zero-day deviations with supervised classification (XGBoost / Random Forest) to categorize known attack families (e.g., DoS/DDoS, PortScan, Brute Force, Botnet, Web Attacks, Infiltration).
- **Epistemic Discipline:** Unsupervised anomaly scores alone can only classify a flow as `anomalous`. Escalation to `suspicious` requires supervised attack classification, correlated multi-flow evidence, or corroborated threat intelligence. `confirmed_malicious` is strictly reserved for human-confirmed verdicts.
- **Explainability:** SHAP TreeExplainer (for XGBoost/RF) and feature-attribution summaries (for Isolation Forest) surface the top contributing flow features (e.g., `flow_duration`, `syn_flag_count`, `fwd_packet_length_mean`, `dst_port`) so analysts can validate model reasoning.
- **Lifecycle Management:** Versioned model artifacts with immutable metadata (training dataset, feature schema hash, hyperparameters, evaluation metrics) managed via Joblib/MLflow.

---

## 17. RAG Requirements

| Req ID | Requirement | Measurable Acceptance Criteria |
| :--- | :--- | :--- |
| **PRD-RAG-01** | Support ingesting MITRE ATT&CK, CVE records, security advisories, network security docs, historical incident reports, and internal runbooks. | Parsers handle JSON, Markdown, PDF, and plain text; provenance metadata (`source_type`, `source_id`, `published_at`) stored on 100% of documents. |
| **PRD-RAG-02** | Perform structure-aware chunking with configurable chunk size and overlap. | Chunks preserve section headers/identifiers (e.g., `T1046`, `CVE-2024-XXXX`); zero orphaned chunks without parent document FK. |
| **PRD-RAG-03** | Implement hybrid retrieval combining dense vector similarity (`pgvector`, BGE embeddings) and lexical keyword search (PostgreSQL FTS). | Exact CVE/ATT&CK ID queries achieve ≥ 95% top-3 hit rate; semantic queries return contextually relevant chunks. |
| **PRD-RAG-04** | Fuse dense and lexical candidates using Reciprocal Rank Fusion (RRF) followed by cross-encoder reranking (BGE Reranker). | Reranker improves NDCG@5 over raw vector-only retrieval on evaluation benchmark. |
| **PRD-RAG-05** | Enforce evidence-linked generation and untrusted-document handling. | Every generated claim references explicit `chunk_id`s; prompt-injection patterns embedded in retrieved documents are treated strictly as data, never instructions. |
| **PRD-RAG-06** | Provide an automated retrieval evaluation harness. | Evaluates Recall@K, MRR, NDCG@K, and citation faithfulness on a curated test set. |

---

## 18. Agentic AI Capabilities

NetSentinel AI uses **LangGraph** to run a deterministic, inspectable state machine across five specialized agents:

1. **Detection Analyst Agent:** Interprets ML anomaly scores, predicted attack classes, SHAP attributions, and flow statistics; translates quantitative features into structured technical observations.
2. **Threat Intelligence Agent:** Formulates targeted queries to the RAG engine to retrieve matching MITRE ATT&CK techniques, CVEs, and advisories with citations.
3. **Investigation Coordinator Agent:** Correlates alerts, network flow evidence, historical incident records, and retrieved threat intelligence into a unified hypothesis and timeline.
4. **Response Advisor Agent:** Proposes prioritized containment, eradication, and hardening recommendations mapped to the observed evidence. **Strictly prohibited from executing network/system changes.**
5. **Evidence Validator Agent:** Independently verifies whether claims in the coordinator's hypothesis and advisor's recommendations are supported by actual `network_flows`, `detection_results`, and retrieved `document_chunks`. Triggers bounded revision or flags unsupported claims.

All agents operate with:
- Strongly typed Pydantic input/output schemas.
- Explicit LangGraph state transitions, bounded retry limits, and per-node timeouts.
- Provider-agnostic LLM abstraction (Gemini / OpenAI-compatible).
- Complete execution logging (`agent_runs`) and Langfuse tracing.

---

## 19. Security and Privacy Requirements

- **Tenant Isolation:** Organization-scoped access enforced at API, query, and object-storage key levels.
- **Untrusted Input Handling:** Uploaded PCAPs are parsed in isolated worker processes with strict size, packet-count, and time limits. Retrieved RAG documents and packet metadata (e.g., DNS names, HTTP headers) are treated as untrusted data to mitigate indirect prompt injection.
- **Human-in-the-Loop Safety:** Response Advisor outputs are advisory only; dangerous operations cannot be executed autonomously.
- **Data Privacy:** Support optional IP anonymization/pseudonymization for exported reports and configurable retention policies for PCAPs and flow records (GDPR/SOC2-aligned principles).
- **Secrets & Transport Security:** TLS in transit, encrypted storage at rest, Argon2id/bcrypt password hashing, and environment/secret-manager injection for API keys.

---

## 20. UX/UI Requirements

The Security Operations Dashboard (React + TypeScript + Tailwind CSS) must provide:
1. **Authentication & Workspace Switcher:** Secure login and organization context indicator.
2. **Dashboard Overview:** KPI cards (active alerts, open incidents, datasets processed, avg investigation time), alert severity distribution, recent activity feed.
3. **Traffic Analytics:** Protocol breakdown, top source/destination IPs and ports, flow volume over time (Recharts).
4. **Dataset Management:** Drag-and-drop PCAP upload, validation feedback, async processing status tracker, dataset metadata.
5. **Alert Management:** Filterable, sortable alert queue with clear visual distinction between `anomalous`, `suspicious`, and `confirmed_malicious` badges, plus inline SHAP feature-contribution charts.
6. **Incident Management:** Incident list, alert grouping, severity/verdict controls, timeline view.
7. **Investigation Workspace:** Interactive LangGraph execution view (React Flow), live/completed agent run details, cited evidence drawer, and recommendation approval panel.
8. **Threat Intelligence Viewer:** Hybrid search interface over ingested MITRE ATT&CK, CVE, and advisory documents with highlighted matched chunks.
9. **Agent Execution History:** Auditable log of past runs, latencies, retry counts, validation pass rates.
10. **Incident Reports:** Structured report preview and export (Markdown/JSON; PDF in MVP+).
11. **Model Performance Analytics:** Model version selector, evaluation metrics, ROC/PR curves, confusion matrix.
12. **Audit Logs:** Searchable, read-only compliance trail of system and analyst actions.

---

## 21. Performance Expectations

> **Note:** Proposed targets for MVP single-node / modest multi-worker deployment.

- **API Latency:** p95 ≤ 300 ms for standard CRUD and paginated flow/alert queries (excluding LLM/ML compute endpoints).
- **PCAP Ingestion:** Process a 100 MB PCAP (~100k–150k packets) within ≤ 60 seconds on a standard 4-vCPU worker.
- **ML Inference:** Batch inference + SHAP top-K attribution on 10,000 flows within ≤ 15 seconds.
- **Hybrid RAG Retrieval:** Hybrid vector + FTS + RRF + BGE reranking p95 ≤ 1.5 seconds over 100k chunks.
- **Multi-Agent Investigation:** Complete 5-agent workflow p95 ≤ 90 seconds (dependent on external LLM provider latency).

---

## 22. Risks and Mitigation

| Risk ID | Risk Description | Impact | Likelihood | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **RSK-01** | **Alert Fatigue from High False Positives** | High | Medium | Pair unsupervised Isolation Forest with supervised XGBoost; calibrate thresholds via PR-AUC; clearly separate `anomalous` from `suspicious`. |
| **RSK-02** | **LLM Hallucination in Security Reports** | High | Medium | Enforce Evidence Validator agent; require explicit `evidence_id`/`chunk_id` citations; keep deterministic ML and evidence verification independent of the LLM provider. |
| **RSK-03** | **Indirect Prompt Injection via Packet Metadata or RAG Docs** | High | Medium | Treat all PCAP fields and retrieved chunks as untrusted data; use structured schemas, input sanitization, strict system/data delimiters, and zero autonomous tool execution. |
| **RSK-04** | **Malicious or Malformed PCAP Causing Worker DoS** | High | Medium | Enforce file size limits, magic-byte checks, isolated worker memory/CPU cgroups, and hard processing timeouts. |
| **RSK-05** | **Dataset Bias / Domain Shift in Public Benchmarks** | Medium | High | Validate across multiple datasets (CIC-IDS2017, UNSW-NB15, CSE-CIC-IDS2018); prevent leakage via time/host-aware splits; plan drift monitoring for v1.1. |
| **RSK-06** | **LLM Provider Outage or Rate Limiting** | Medium | Medium | Provider-agnostic LLM adapter (Gemini/OpenAI-compatible), bounded retries with exponential backoff, and graceful degradation (deterministic ML + RAG remain operational). |

---

## 23. Dependencies

- **Technical Dependencies:** Python 3.12+, FastAPI, PostgreSQL 16 + `pgvector`, Redis, S3-compatible object storage (MinIO/S3), Scikit-learn, XGBoost, SHAP, LangGraph, Sentence Transformers (BGE models), React + Vite + Tailwind CSS.
- **External Data Dependencies:** Public ML training datasets (CIC-IDS2017, UNSW-NB15, CSE-CIC-IDS2018); MITRE ATT&CK knowledge base; NVD/CVE feeds.
- **External Service Dependencies:** Configured LLM API provider (Gemini or OpenAI-compatible endpoint) for agent reasoning; Langfuse instance (self-hosted or cloud) for LLM tracing.

---

## 24. Release Strategy

1. **Phase 0 — Architecture & Foundation (Weeks 1–2):** Repository scaffold, Docker Compose (Postgres+pgvector, Redis, MinIO), Alembic schema migrations, Auth/RBAC, CI pipeline.
2. **Phase 1 — Ingestion & ML Core (Weeks 3–5):** PCAP upload & async flow extraction, ML training/evaluation pipeline (Isolation Forest + XGBoost + SHAP), alert generation.
3. **Phase 2 — Security Intelligence RAG (Weeks 6–7):** Document ingestion, chunking, BGE embeddings, pgvector + FTS hybrid search, RRF, BGE reranker, retrieval eval harness.
4. **Phase 3 — Multi-Agent Investigation (Weeks 8–10):** LangGraph 5-agent workflow, Evidence Validator, human approval gates, OpenTelemetry + Langfuse integration.
5. **Phase 4 — SOC Dashboard & MVP Hardening (Weeks 11–13):** Complete React/TS dashboard, Playwright E2E tests, security review, documentation & MVP v1.0 release.
6. **Phase 5 — Production Extensions (Post-MVP):** Live traffic streaming, Autoencoder model, drift monitoring, SOAR integrations.

---

## 25. Product Roadmap

| Milestone | Target Release | Key Deliverables |
| :--- | :--- | :--- |
| **M1: Core Platform** | v0.2 | Auth, multi-tenancy, PCAP upload, async flow extraction, PostgreSQL schema |
| **M2: Explainable ML** | v0.4 | Isolation Forest + XGBoost pipeline, SHAP explainability, model versioning, alerts |
| **M3: Threat Intel RAG** | v0.6 | MITRE ATT&CK + CVE ingestion, hybrid search + RRF + BGE reranker, eval harness |
| **M4: Agentic SOC** | v0.8 | 5-agent LangGraph investigation workflow, Evidence Validator, approval gates |
| **M5: MVP Launch** | v1.0 | Full SOC Dashboard, reporting, audit logs, E2E tests, Docker deployment |
| **M6: Continuous Defense** | v1.5 | Live traffic ingestion, Autoencoder anomaly model, feature drift monitoring |
| **M7: Enterprise Scale** | v2.0 | STIX/TAXII feeds, approval-gated SOAR connectors, SSO/OIDC |

---

## 26. Acceptance Criteria (MVP Sign-Off)

The MVP (v1.0) is accepted when all of the following conditions are verified:
1. **End-to-End Flow:** An authenticated analyst can upload a valid PCAP, extract flows asynchronously, run ML detection with SHAP explanations, escalate alerts to an incident, execute a 5-agent LangGraph investigation, approve/reject recommendations, and export an evidence-cited report.
2. **Epistemic & Safety Guarantees:** Unsupervised anomalies alone never auto-label as `confirmed_malicious`; zero containment actions execute without human approval; Evidence Validator flags unsupported claims in automated adversarial tests.
3. **Security & Isolation:** Cross-tenant access tests pass with 100% isolation; malformed PCAP and prompt-injection test fixtures are safely handled.
4. **Quality Gates:** Pytest unit/integration suites and Playwright E2E tests pass in GitHub Actions CI; ML and RAG evaluation harnesses execute reproducibly and produce metric reports.

---

## 27. Future Enhancements & Open Questions

### Future Enhancements
- Automated packet-to-graph entity relationship visualization (host communication graphs).
- Natural-language-to-SQL/Filter assistant for flow hunting (read-only, strictly parameterized).
- Multi-modal support for ingesting firewall/IDS alerts (Suricata, Zeek) alongside PCAPs.
- Federated learning or privacy-preserving model fine-tuning across enterprise environments.

### OPEN QUESTIONS
- **OQ-PRD-01:** What maximum PCAP file size should be enforced in MVP (proposed: 500 MB) vs. enterprise tier (e.g., 5 GB)?
- **OQ-PRD-02:** Which LLM provider will be the default primary provider for MVP deployment (Gemini vs. OpenAI-compatible local/cloud endpoint)?
- **OQ-PRD-03:** Should PDF report generation be included in v1.0 MVP or deferred to v1.1 (with Markdown and JSON in v1.0)?
- **OQ-PRD-04:** What default data retention window (e.g., 30/90/365 days) should apply to raw PCAP binaries in object storage vs. extracted flow metadata?
