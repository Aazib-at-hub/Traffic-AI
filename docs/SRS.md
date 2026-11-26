# NetSentinel AI — Software Requirements Specification (SRS)

---

## 1. Introduction

This Software Requirements Specification (SRS) defines the technical architecture, functional and non-functional requirements, API contracts, database schema, machine learning pipeline, Retrieval-Augmented Generation (RAG) subsystem, multi-agent LangGraph design, security controls, and verification strategy for **NetSentinel AI**.

This document follows an IEEE 830 / ISO/IEC/IEEE 29148-inspired structure and serves as the engineering blueprint complementing [PRD.md](PRD.md) and [README.md](../README.md).

> **Repository Baseline Note:** The repository is currently empty (greenfield). All specifications herein describe the **target implementation architecture**. Explicitly noted assumptions and `OPEN QUESTIONS` must be resolved before production deployment.

---

## 2. Purpose

The purpose of this SRS is to establish an unambiguous, testable, and traceable engineering specification for building NetSentinel AI as a **modular monolith with dedicated background workers**. It is intended for backend engineers, ML engineers, AI research engineers, frontend engineers, security reviewers, and QA engineers.

---

## 3. Scope

NetSentinel AI ingests network traffic captures (`.pcap`/`.pcapng`), extracts structured bidirectional flow features, executes explainable ML anomaly detection and attack classification, retrieves grounded cybersecurity intelligence via hybrid RAG, orchestrates a controlled 5-agent LangGraph investigation workflow with deterministic evidence verification, and presents operational workflows through a multi-tenant React/TypeScript Security Operations Dashboard.

- **Current Implementation State:** None (greenfield documentation baseline).
- **MVP Scope (v1.0):** Offline PCAP ingestion, Isolation Forest + XGBoost/Random Forest detection with SHAP, hybrid RAG (pgvector + PostgreSQL FTS + RRF + BGE reranker), 5-agent LangGraph workflow, human-in-the-loop approval gates, SOC dashboard, audit logging, Docker Compose deployment.
- **Post-MVP Scope (v1.1+):** Live traffic streaming, optional Autoencoder anomaly model, automated feature/concept drift monitoring, STIX/TAXII sync, approval-gated SOAR integrations.

---

## 4. Definitions and Acronyms

| Term / Acronym | Definition |
| :--- | :--- |
| **Anomalous** | Statistically unusual traffic identified by unsupervised ML relative to baseline. Does **not** prove maliciousness. |
| **Suspicious** | Traffic corroborated by supervised attack classification, multi-flow correlation, or threat intelligence context. |
| **Confirmed Malicious** | Threat verdict explicitly confirmed by an authorized human analyst based on verified evidence. |
| **BGE** | BAAI General Embedding / Reranker model family (`BAAI/bge-base-en-v1.5`, `BAAI/bge-reranker-base`). |
| **CVE** | Common Vulnerabilities and Exposures identifier. |
| **FTS** | Full-Text Search (PostgreSQL `tsvector` + `GIN` index). |
| **HITL** | Human-in-the-Loop approval requirement. |
| **HNSW** | Hierarchical Navigable Small World graph index in `pgvector`. |
| **MITRE ATT&CK** | Knowledge base of adversary tactics, techniques, and procedures (TTPs). |
| **PCAP / PCAPNG** | Packet Capture binary file formats. |
| **PR-AUC / ROC-AUC** | Area Under the Precision-Recall Curve / Receiver Operating Characteristic Curve. |
| **RAG** | Retrieval-Augmented Generation. |
| **RBAC** | Role-Based Access Control. |
| **RRF** | Reciprocal Rank Fusion rank-aggregation algorithm. |
| **SHAP** | SHapley Additive exPlanations for feature contribution attribution. |
| **SOC** | Security Operations Center. |

---

## 5. References

1. [NetSentinel AI Product Requirements Document (PRD.md)](PRD.md)
2. [NetSentinel AI Repository Guide (README.md)](../README.md)
3. ISO/IEC/IEEE 29148:2018 — Systems and software engineering — Requirements engineering.
4. MITRE ATT&CK Framework — https://attack.mitre.org/
5. CIC-IDS2017 & CSE-CIC-IDS2018 Datasets — Canadian Institute for Cybersecurity (University of New Brunswick).
6. UNSW-NB15 Dataset — UNSW Canberra Cyber Range Lab.
7. OWASP API Security Top 10 & OWASP Top 10 for LLM Applications.

---

## 6. Overall System Description

NetSentinel AI is architected as a **modular monolith** (`FastAPI` + `Python 3.12+`) paired with **asynchronous background workers** (assumption: `Celery` with `Redis` broker/result backend) and a single-page web application (`React` + `TypeScript` + `Vite`).

**Architectural Justification (Modular Monolith vs. Microservices):**
A modular monolith enforces strict Python package boundaries (`auth`, `ingestion`, `ml`, `rag`, `agents`, `incidents`, `reporting`, `audit`) while avoiding distributed-transaction complexity, network serialization overhead, and operational sprawl during v1.0. Heavy CPU/I/O workloads (PCAP parsing, ML inference/SHAP, RAG embedding, LangGraph execution) are offloaded to horizontally scalable worker pools via Redis queues.

---

## 7. System Context

### 7.1 System Context Diagram

```mermaid
flowchart LR
    Analyst["SOC Analyst / Responder"] -->|HTTPS| WebUI["NetSentinel AI Platform"]
    MLEng["ML / Detection Engineer"] -->|HTTPS / CLI| WebUI
    Admin["Platform Administrator"] -->|HTTPS| WebUI

    WebUI -->|S3 API| ObjStore["S3-Compatible Object Storage (MinIO / S3)"]
    WebUI -->|HTTPS API| LLM["LLM Provider (Gemini / OpenAI-Compatible)"]
    WebUI -->|OTLP| OTel["OpenTelemetry Collector"]
    WebUI -->|HTTPS| Langfuse["Langfuse Tracing"]
    ThreatFeeds["External Security Knowledge (MITRE ATT&CK, NVD/CVE, Advisories)"] -->|Batch Ingestion| WebUI
```

---

## 8. User Classes and Permissions

| Role | Tenant Scope | Capabilities & Permissions |
| :--- | :--- | :--- |
| **`viewer`** | Single Org | Read-only access to dashboard, traffic analytics, alerts, incidents, threat intel, and reports. |
| **`soc_analyst`** | Single Org | All `viewer` permissions + upload PCAPs, trigger flow extraction & ML detection, triage alerts, create incidents, run agent investigations, export reports. |
| **`incident_responder`** | Single Org | All `soc_analyst` permissions + approve/reject Response Advisor recommendations, set `confirmed_malicious` verdicts, manage incident lifecycle. |
| **`ml_engineer`** | Single Org | Read traffic/detections + register/evaluate/promote ML model versions, inspect SHAP & drift metrics. |
| **`org_admin`** | Single Org | Full organization administration: manage `organization_members`, ingest org-scoped RAG documents, configure retention, view all `audit_logs`. |
| **`super_admin`** | Platform-Wide | Manage organizations, global MITRE ATT&CK / CVE knowledge base ingestion, system health. |

---

## 9. Operating Environment

- **Runtime:** Linux containers (`python:3.12-slim` for API/workers, `node:20-alpine` for frontend build, `nginx:alpine` for reverse proxy & static serving).
- **Database:** PostgreSQL 16 with `pgvector` (≥ 0.7) and `pg_trgm` extensions.
- **Cache & Queue Broker:** Redis 7.
- **Object Storage:** MinIO (local/self-hosted) or AWS S3-compatible endpoint.
- **Browser Support:** Latest two versions of Chrome, Firefox, Edge, Safari.
- **Hardware Baseline (Dev/MVP):** 4 vCPU, 16 GB RAM (CPU-only BGE embeddings/reranking supported; optional CUDA GPU accelerates embedding/reranking and future Autoencoder training).

---

## 10. Technical Constraints

1. **No Raw PCAP Storage in PostgreSQL:** Binary `.pcap`/`.pcapng` files MUST be stored in S3-compatible object storage; PostgreSQL stores only metadata, hashes, and object keys.
2. **Deterministic Detection Independence:** ML detection, flow extraction, and deterministic evidence checks MUST function independently of any LLM provider.
3. **No Autonomous Dangerous Actions:** Agents have zero write/exec access to firewalls, routers, or host OS commands.
4. **Strict Multi-Tenant Isolation:** Every tenant-owned table MUST carry `organization_id` and be filtered at the repository/service layer.
5. **Untrusted Data Boundary:** Uploaded PCAP payloads/headers and retrieved RAG documents MUST be treated as untrusted data.

---

## 11. Architectural Overview

### 11.1 High-Level Architecture Diagram

```mermaid
flowchart TB
    subgraph Client["Client Tier"]
        Browser["React + TypeScript + Vite SPA (Tailwind, Recharts, React Flow)"]
    end

    subgraph Edge["Edge / Proxy"]
        Nginx["Nginx Reverse Proxy (TLS, Rate Limiting, Static Assets)"]
    end

    subgraph App["Application Tier (Modular Monolith)"]
        API["FastAPI Application (REST API, Pydantic v2, RBAC, Auth)"]
        subgraph Modules["Internal Domain Modules"]
            MAuth["Auth & Tenancy"]
            MIngest["Ingestion Service"]
            MML["ML & SHAP Service"]
            MRAG["RAG Service"]
            MAgent["LangGraph Orchestrator"]
            MInc["Alerts, Incidents & Reports"]
            MAudit["Audit & Telemetry"]
        end
    end

    subgraph Workers["Background Worker Pools (Celery)"]
        WIngest["PCAP / Flow Worker (Scapy / PyShark)"]
        WML["ML Inference & SHAP Worker (Scikit-learn, XGBoost)"]
        WRAG["RAG Indexing Worker (BGE Embeddings)"]
        WAgent["Agent Investigation Worker (LangGraph + LLM Adapter)"]
    end

    subgraph Data["Data & Storage Tier"]
        PG["PostgreSQL 16 + pgvector + FTS"]
        Redis["Redis 7 (Broker, Cache, Job Status)"]
        S3["S3-Compatible Object Storage (PCAPs, Artifacts, Reports)"]
    end

    subgraph External["External & Observability"]
        LLM["LLM Provider (Gemini / OpenAI-Compatible)"]
        OTel["OpenTelemetry"]
        LF["Langfuse"]
    end

    Browser -->|HTTPS| Nginx
    Nginx -->|/api/v1| API
    API --> Modules
    API -->|SQLAlchemy 2| PG
    API -->|Enqueue Tasks| Redis
    API -->|Presigned / Stream| S3

    Redis --> WIngest & WML & WRAG & WAgent
    WIngest & WML & WRAG & WAgent --> PG
    WIngest & WML --> S3
    WAgent --> LLM
    API & Workers --> OTel
    WAgent --> LF
```

### 11.2 Component Diagram

```mermaid
flowchart LR
    subgraph FastAPI["FastAPI Backend (src/netsentinel)"]
        Routers["API Routers (/api/v1/*)"]
        Deps["Auth & Tenant Context Dependencies"]
        Services["Domain Services"]
        Repos["SQLAlchemy 2 Repositories"]
        Schemas["Pydantic v2 Schemas"]
    end

    subgraph MLCore["ML Engine (src/netsentinel/ml)"]
        Preproc["Feature Preprocessor & Scaler"]
        IsoForest["Isolation Forest Detector"]
        XGB["XGBoost / RF Classifier"]
        SHAPMod["SHAP Explainer"]
        Registry["Model Registry (Joblib / MLflow)"]
    end

    subgraph RAGCore["RAG Engine (src/netsentinel/rag)"]
        Parser["Doc Parsers (STIX/JSON/MD/PDF)"]
        Chunker["Structure-Aware Chunker"]
        Embedder["BGE Embedder"]
        Hybrid["Hybrid Retriever (pgvector + FTS + RRF)"]
        Reranker["BGE Cross-Encoder Reranker"]
    end

    subgraph AgentCore["Agent Engine (src/netsentinel/agents)"]
        Graph["LangGraph StateGraph"]
        LLMClient["Provider-Agnostic LLM Adapter"]
        Tools["Validated Read-Only Tools"]
        Validator["Deterministic + LLM Evidence Validator"]
    end

    Routers --> Deps --> Services --> Repos
    Services --> MLCore & RAGCore & AgentCore
    AgentCore --> RAGCore & Repos
```

### 11.3 Network Traffic Processing Sequence Diagram

```mermaid
sequenceDiagram
    actor Analyst
    participant UI as React Dashboard
    participant API as FastAPI Backend
    participant S3 as Object Storage (MinIO/S3)
    participant PG as PostgreSQL
    participant Redis as Redis Queue
    participant W1 as PCAP Worker
    participant W2 as ML Worker

    Analyst->>UI: Upload PCAP file + metadata
    UI->>API: POST /api/v1/datasets/upload (multipart)
    API->>API: Validate magic bytes, extension, size limit
    API->>S3: Stream raw PCAP to org-scoped key
    API->>PG: INSERT traffic_datasets (status=uploaded) + audit_log
    API-->>UI: 201 Created (dataset_id)

    Analyst->>UI: Trigger Processing
    UI->>API: POST /api/v1/datasets/{id}/process
    API->>PG: UPDATE traffic_datasets (status=queued)
    API->>Redis: Enqueue extract_flows_task(dataset_id)
    API-->>UI: 202 Accepted (job_id)

    Redis->>W1: Consume extract_flows_task
    W1->>PG: UPDATE status=processing
    W1->>S3: Download PCAP to isolated tmpfs
    W1->>W1: Parse packets (Scapy/PyShark), aggregate bidirectional flows, compute features
    W1->>PG: Bulk INSERT network_flows (batched COPY/insert)
    W1->>PG: UPDATE traffic_datasets (status=completed, flow_count, stats)
    W1->>W1: Delete temporary PCAP file

    Analyst->>UI: Trigger ML Detection
    UI->>API: POST /api/v1/datasets/{id}/detect
    API->>Redis: Enqueue run_detection_task(dataset_id, model_ids)
    API-->>UI: 202 Accepted (job_id)

    Redis->>W2: Consume run_detection_task
    W2->>PG: Fetch network_flows & active model_versions
    W2->>S3: Load model artifacts (cached locally)
    W2->>W2: Run Isolation Forest + XGBoost/RF + SHAP Top-K
    W2->>PG: Bulk INSERT detection_results & alerts (anomalous/suspicious)
    W2->>PG: INSERT audit_logs
```

---

## 12. Functional Requirements

### 12.1 Authentication & Multi-Tenancy
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-001** | The system SHALL authenticate users via email and password (hashed with Argon2id) and issue short-lived JWT access tokens (≤ 15 min) and revocable refresh tokens stored in Redis/DB. | US-001, SEC-001 |
| **FR-002** | The system SHALL enforce organization-scoped multi-tenancy such that every API query filters records by the authenticated user's active `organization_id`. | US-001, SEC-003 |
| **FR-003** | The system SHALL enforce Role-Based Access Control (RBAC) across `viewer`, `soc_analyst`, `incident_responder`, `ml_engineer`, `org_admin`, and `super_admin` roles on every endpoint. | US-001, SEC-002 |
| **FR-004** | The system SHALL allow `org_admin` users to invite, assign roles to, and deactivate members within their organization. | US-001 |

### 12.2 Network Traffic Ingestion & Flow Extraction
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-005** | The system SHALL accept `.pcap` and `.pcapng` uploads up to a configurable limit (default 500 MB), validating magic bytes (`0xa1b2c3d4`, `0xd4c3b2a1`, `0x0a0d0d0a`) and computing SHA-256 checksums. | US-002, SEC-004 |
| **FR-006** | The system SHALL store uploaded PCAP files in S3-compatible object storage under tenant-prefixed keys (`orgs/{org_id}/datasets/{dataset_id}/{sha256}.pcap`) and store only metadata in `traffic_datasets`. | US-002 |
| **FR-007** | The system SHALL process PCAP files asynchronously in background workers, extracting bidirectional 5-tuple network flows (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) with packet counts, byte volumes, timing, TCP flag counts, and flow feature vectors. | US-003 |
| **FR-008** | The system SHALL track dataset processing lifecycle states (`uploaded`, `queued`, `processing`, `completed`, `failed`) with progress percentage and structured error messages. | US-003 |
| **FR-009** | The system SHALL provide paginated, filterable, and sortable retrieval of `network_flows` by dataset, IP, port, protocol, timestamp range, and anomaly status. | US-004 |

### 12.3 ML Detection & Explainability
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-010** | The system SHALL support executing unsupervised anomaly detection (Isolation Forest) and supervised attack classification (XGBoost or Random Forest) on extracted flow datasets. | US-005 |
| **FR-011** | The system SHALL apply the exact saved feature preprocessing pipeline (imputation, scaling, encoding) associated with each `model_version` during inference. | US-005 |
| **FR-012** | The system SHALL assign a `classification_tier` to every detection result: `benign`, `anomalous` (unsupervised-only flag), or `suspicious` (supervised attack classification or multi-indicator corroboration). Automated ML pipelines SHALL NEVER assign `confirmed_malicious`. | US-005 |
| **FR-013** | The system SHALL compute and persist SHAP feature-contribution attributions (top-K features with signed values and baseline) for flagged (`anomalous`/`suspicious`) flows. | US-006 |
| **FR-014** | The system SHALL maintain versioned model artifacts in `model_versions` with dataset provenance, feature schema hash, hyperparameters, evaluation metrics, and lifecycle stage (`staging`, `active`, `archived`). | US-016 |
| **FR-015** | The system SHALL provide a pluggable model interface allowing an optional Autoencoder anomaly detector to be registered without modifying API or worker contracts. | US-018 |

### 12.4 Alert & Incident Management
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-016** | The system SHALL generate `alerts` from detection results exceeding calibrated thresholds, including severity (`low`, `medium`, `high`, `critical`), classification tier, summary, and linked `detection_result_id`. | US-007 |
| **FR-017** | The system SHALL support alert triage workflows including status transitions (`open`, `triaging`, `escalated`, `resolved`, `false_positive`), assignee updates, and analyst notes. | US-007 |
| **FR-018** | The system SHALL allow analysts to create `incidents` and correlate multiple `alerts` via `incident_alerts`. | US-008 |
| **FR-019** | The system SHALL restrict transitioning an incident's `verdict` to `confirmed_malicious` to authorized roles (`incident_responder`, `org_admin`) and log every verdict change to `audit_logs`. | US-008, US-017 |

### 12.5 Security Intelligence RAG
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-020** | The system SHALL ingest security documents (MITRE ATT&CK, CVE records, advisories, network docs, historical incidents, internal runbooks) with source metadata and deduplication via content hash. | US-009 |
| **FR-021** | The system SHALL chunk documents with structure-aware splitting, generate dense vector embeddings (BGE model), and index chunks in `document_chunks` with both `pgvector` HNSW and PostgreSQL `tsvector` GIN indexes. | US-009 |
| **FR-022** | The system SHALL execute hybrid retrieval combining dense vector search and lexical FTS, fuse candidate lists via Reciprocal Rank Fusion (RRF), and rerank top candidates using a cross-encoder (BGE Reranker). | US-010 |
| **FR-023** | The system SHALL return source metadata, document title, section identifier, relevance score, and verbatim snippet for every retrieved chunk. | US-010 |
| **FR-024** | The system SHALL provide a repeatable retrieval evaluation script computing Recall@K, MRR@K, and NDCG@K against a labeled security query dataset. | PRD-RAG-06 |

### 12.6 Multi-Agent Investigation Engine
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-025** | The system SHALL orchestrate incident investigations via a LangGraph state machine coordinating five agents: Detection Analyst, Threat Intelligence, Investigation Coordinator, Response Advisor, and Evidence Validator. | US-011 |
| **FR-026** | The system SHALL validate all agent inputs, outputs, and tool invocations using strict Pydantic v2 schemas. | US-011, SEC-006 |
| **FR-027** | The system SHALL enforce per-node execution timeouts, bounded retry limits, and loop ceilings (max 2 revision cycles between Coordinator/Advisor and Evidence Validator). | US-011 |
| **FR-028** | The Evidence Validator Agent SHALL verify that every factual claim references valid `network_flows`, `detection_results`, or retrieved `document_chunks`, labeling each claim `supported`, `partially_supported`, or `unsupported`. | US-012 |
| **FR-029** | The Response Advisor Agent SHALL emit structured, advisory-only `recommendations` initialized with `approval_status = 'pending_approval'`. No recommendation SHALL be executed autonomously. | US-013, SEC-007 |
| **FR-030** | The system SHALL persist every agent node execution in `agent_runs`, linked evidence in `evidence_items`, and proposed mitigations in `recommendations`. | US-014 |

### 12.7 Reporting, Dashboard & Audit
| ID | Requirement | Traceability |
| :--- | :--- | :--- |
| **FR-031** | The system SHALL generate structured incident reports (JSON and Markdown in v1.0; PDF in MVP+) containing executive summary, flow evidence, SHAP top features, ATT&CK/CVE citations, validation status, and approved recommendations. | US-015 |
| **FR-032** | The system SHALL expose dashboard analytics endpoints for traffic volume, protocol distribution, alert trends, model metrics, and investigation statistics. | US-016 |
| **FR-033** | The system SHALL display an interactive visual graph of LangGraph execution states and transitions in the Investigation Workspace (React Flow). | US-014 |
| **FR-034** | The system SHALL record immutable entries in `audit_logs` for authentication, uploads, detection runs, alert/incident updates, investigations, recommendation approvals, and admin changes. | US-017 |
| **FR-035** | The system SHALL support LLM provider switching via configuration (Gemini or OpenAI-compatible API) without code modifications. | RSK-06 |

---

## 13. Non-Functional Requirements

| ID | Category | Requirement | Proposed Target |
| :--- | :--- | :--- | :--- |
| **NFR-001** | Performance | Standard API read/write endpoints (CRUD, paginated queries) latency. | p95 ≤ 300 ms |
| **NFR-002** | Performance | Async PCAP ingestion & flow extraction throughput (4-vCPU worker). | 100 MB PCAP in ≤ 60 s |
| **NFR-003** | Performance | Batch ML inference + SHAP top-K attribution on 10,000 flows. | ≤ 15 s |
| **NFR-004** | Performance | Hybrid RAG search (pgvector + FTS + RRF + BGE reranker) over 100k chunks. | p95 ≤ 1.5 s |
| **NFR-005** | Performance | Full 5-agent LangGraph investigation turnaround time. | p95 ≤ 90 s |
| **NFR-006** | Scalability | Background worker pools SHALL scale horizontally by adding stateless worker replicas connected to Redis. | Linear throughput scaling up to DB write saturation |
| **NFR-007** | Availability | API service SHALL expose `/health/live` and `/health/ready` endpoints checking DB, Redis, and Object Storage. | ≥ 99.5% uptime target (self-hosted/cloud MVP) |
| **NFR-008** | Reliability | Failed background tasks SHALL retry with exponential backoff (max 3 retries for transient I/O errors) and transition to `failed` with structured diagnostics if exhausted. | Zero silent task drops |
| **NFR-009** | Observability | All API requests and worker tasks SHALL emit OpenTelemetry traces and structured JSON logs with `correlation_id` and `organization_id`. | 100% request traceability |
| **NFR-010** | AI Observability | All LLM calls and LangGraph node transitions SHALL be instrumented with Langfuse (latency, token usage, model name, validation outcome). | 100% agent run coverage |
| **NFR-011** | Maintainability | Codebase SHALL enforce type checking (`mypy`/`pyright`, TypeScript `strict`), linting (`ruff`, `eslint`), and modular package boundaries. | Zero CI lint/type errors |
| **NFR-012** | Data Integrity | All multi-table mutations SHALL execute inside ACID PostgreSQL transactions with foreign-key constraints enforced. | Zero orphaned relational rows |
| **NFR-013** | Portability | Entire stack SHALL run reproducibly via Docker Compose locally and in CI without vendor lock-in. | Single-command local boot |
| **NFR-014** | Extensibility | ML models, RAG embedders/rerankers, and LLM providers SHALL sit behind abstract Python protocols/interfaces. | Swap provider via config/plugin |
| **NFR-015** | Usability | Dashboard SHALL provide responsive layouts, keyboard-accessible tables, and clear visual distinction between `anomalous`, `suspicious`, and `confirmed_malicious`. | WCAG 2.1 AA baseline for core views |

---

## 14. API Requirements & Example Contracts

All API endpoints are prefixed with `/api/v1`, use JSON (`application/json`) unless multipart upload is specified, and return a standardized error envelope:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable summary",
    "details": [{"field": "file", "issue": "Invalid PCAP magic bytes"}],
    "request_id": "req_01J9X..."
  }
}
```

### 14.1 Authentication
- **Endpoint:** `POST /api/v1/auth/login`
- **Authentication:** Public (rate-limited: 10 req/min/IP)
- **Request Schema:**
```json
{
  "email": "analyst@acme-soc.io",
  "password": "StrongPassword!2026"
}
```
- **Response Schema (`200 OK`):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 900,
  "user": {
    "id": "usr_7f9a2c10-...",
    "email": "analyst@acme-soc.io",
    "active_organization_id": "org_1a2b3c4d-...",
    "role": "soc_analyst"
  }
}
```
- **Validation & Errors:** Email format, non-empty password; `401 UNAUTHORIZED` on invalid credentials, `429 TOO_MANY_REQUESTS` on rate limit. Companion endpoints: `POST /api/v1/auth/refresh`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`.

### 14.2 PCAP Upload
- **Endpoint:** `POST /api/v1/datasets/upload`
- **Authentication:** Bearer JWT (`soc_analyst`, `incident_responder`, `org_admin`)
- **Request:** `multipart/form-data` with fields: `file` (binary `.pcap`/`.pcapng`), `name` (string, 3–120 chars), `description` (optional string), `tags` (optional JSON string array).
- **Response Schema (`201 Created`):**
```json
{
  "dataset_id": "ds_9c8b7a6d-...",
  "organization_id": "org_1a2b3c4d-...",
  "name": "branch-firewall-2026-11-26.pcap",
  "file_size_bytes": 48234496,
  "sha256": "e3b0c44298fc1c149afbf4c8996fb924...",
  "status": "uploaded",
  "created_at": "2026-11-27T00:10:00Z"
}
```
- **Validation & Errors:** Magic-byte check, max file size (500 MB default); `400 INVALID_PCAP`, `413 PAYLOAD_TOO_LARGE`, `403 FORBIDDEN`.

### 14.3 Dataset Processing
- **Endpoint:** `POST /api/v1/datasets/{dataset_id}/process`
- **Authentication:** Bearer JWT (`soc_analyst`, `incident_responder`, `org_admin`)
- **Request Schema:**
```json
{
  "flow_timeout_seconds": 120,
  "auto_run_detection": true,
  "extraction_engine": "scapy"
}
```
- **Response Schema (`202 Accepted`):**
```json
{
  "dataset_id": "ds_9c8b7a6d-...",
  "job_id": "celery_4412f9...",
  "status": "queued",
  "submitted_at": "2026-11-27T00:10:05Z"
}
```
- **Status Endpoint:** `GET /api/v1/datasets/{dataset_id}/status` returns `status`, `progress_pct`, `packet_count`, `flow_count`, `error_message`, `started_at`, `completed_at`.
- **Errors:** `404 NOT_FOUND`, `409 CONFLICT` (if already processing).

### 14.4 Flow Retrieval
- **Endpoint:** `GET /api/v1/datasets/{dataset_id}/flows`
- **Authentication:** Bearer JWT (any org role)
- **Query Params:** `page` (default 1), `page_size` (1–200, default 50), `src_ip`, `dst_ip`, `dst_port`, `protocol`, `classification_tier` (`benign|anomalous|suspicious`), `sort_by` (`start_time|bytes_total|anomaly_score`), `sort_order` (`asc|desc`).
- **Response Schema (`200 OK`):**
```json
{
  "items": [
    {
      "flow_id": "flw_3321ab...",
      "src_ip": "10.0.14.22",
      "dst_ip": "198.51.100.44",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "start_time": "2026-11-26T22:14:01.102Z",
      "duration_ms": 14520,
      "fwd_packets": 142,
      "bwd_packets": 18,
      "bytes_total": 98420,
      "latest_classification_tier": "suspicious",
      "latest_anomaly_score": 0.87
    }
  ],
  "total": 12450,
  "page": 1,
  "page_size": 50
}
```
- **Errors:** `400 INVALID_FILTER`, `404 NOT_FOUND`.

### 14.5 Anomaly Detection & Explainability
- **Endpoint:** `POST /api/v1/datasets/{dataset_id}/detect`
- **Authentication:** Bearer JWT (`soc_analyst`, `incident_responder`, `ml_engineer`, `org_admin`)
- **Request Schema:**
```json
{
  "unsupervised_model_version_id": "mv_iso_v1",
  "supervised_model_version_id": "mv_xgb_v2",
  "compute_shap": true,
  "shap_top_k": 8
}
```
- **Response Schema (`202 Accepted`):**
```json
{
  "job_id": "celery_89a1c...",
  "dataset_id": "ds_9c8b7a6d-...",
  "status": "queued"
}
```
- **Explainability Endpoint:** `GET /api/v1/detections/{detection_id}/explain` returns `classification_tier`, `anomaly_score`, `predicted_class`, `confidence`, `base_value`, and `shap_features: [{"feature": "syn_flag_count", "value": 48, "shap_value": 0.41}]`.
- **Errors:** `404 NOT_FOUND`, `422 MODEL_NOT_ACTIVE`.

### 14.6 Alert Management
- **Endpoints:** `GET /api/v1/alerts` and `PATCH /api/v1/alerts/{alert_id}`
- **Authentication:** Bearer JWT (`GET`: any org role; `PATCH`: `soc_analyst`, `incident_responder`, `org_admin`)
- **PATCH Request Schema:**
```json
{
  "status": "escalated",
  "severity": "high",
  "assigned_to": "usr_7f9a2c10-...",
  "analyst_note": "Repeated SYN bursts targeting internal SSH ports."
}
```
- **Response Schema (`200 OK`):** Returns updated alert object including `alert_id`, `classification_tier`, `status`, `severity`, `detection_result_id`, `updated_at`.
- **Errors:** `400 INVALID_STATUS_TRANSITION`, `403 FORBIDDEN`, `404 NOT_FOUND`.

### 14.7 Incident Investigation & Human Approval
- **Trigger Endpoint:** `POST /api/v1/incidents/{incident_id}/investigations`
- **Authentication:** Bearer JWT (`soc_analyst`, `incident_responder`, `org_admin`)
- **Request Schema:**
```json
{
  "priority": "high",
  "include_historical_incidents": true,
  "max_rag_chunks": 10
}
```
- **Response Schema (`202 Accepted`):**
```json
{
  "investigation_id": "inv_5512ef...",
  "incident_id": "inc_1092cd...",
  "status": "queued",
  "created_at": "2026-11-27T00:20:00Z"
}
```
- **Status/Results Endpoint:** `GET /api/v1/investigations/{investigation_id}` returns `status`, `summary`, `confidence_level`, `validation_status`, `agent_runs[]`, `evidence_items[]`, and `recommendations[]`.
- **Approval Endpoint:** `POST /api/v1/investigations/{investigation_id}/recommendations/{recommendation_id}/approve`
  - **Auth:** `incident_responder` or `org_admin` only.
  - **Request:** `{"decision": "approved", "rationale": "Confirmed C2 beaconing pattern; ready for firewall team ticket."}`
  - **Errors:** `403 FORBIDDEN`, `404 NOT_FOUND`, `409 ALREADY_DECIDED`.

### 14.8 Threat Intelligence Search
- **Endpoint:** `POST /api/v1/threat-intel/search`
- **Authentication:** Bearer JWT (any org role)
- **Request Schema:**
```json
{
  "query": "SSH brute force T1110 repeated SYN authentication failure",
  "source_types": ["mitre_attack", "cve", "advisory"],
  "top_k": 5,
  "use_reranker": true
}
```
- **Response Schema (`200 OK`):**
```json
{
  "query": "SSH brute force T1110 repeated SYN authentication failure",
  "results": [
    {
      "chunk_id": "chk_00192a...",
      "document_id": "doc_8812bc...",
      "title": "MITRE ATT&CK T1110 - Brute Force",
      "source_type": "mitre_attack",
      "external_id": "T1110",
      "content": "Adversaries may use brute force techniques to gain access to accounts...",
      "rrf_score": 0.0321,
      "rerank_score": 0.9412
    }
  ],
  "latency_ms": 214
}
```
- **Errors:** `400 EMPTY_QUERY`, `422 INVALID_TOP_K`.

### 14.9 Report Generation
- **Endpoint:** `POST /api/v1/incidents/{incident_id}/reports`
- **Authentication:** Bearer JWT (`soc_analyst`, `incident_responder`, `org_admin`)
- **Request Schema:**
```json
{
  "format": "markdown",
  "anonymize_ips": false,
  "include_shap_details": true
}
```
- **Response Schema (`201 Created`):**
```json
{
  "report_id": "rpt_7721aa...",
  "incident_id": "inc_1092cd...",
  "format": "markdown",
  "storage_key": "orgs/org_1a2b/reports/rpt_7721aa.md",
  "download_url": "/api/v1/reports/rpt_7721aa/download",
  "created_at": "2026-11-27T00:35:00Z"
}
```
- **Errors:** `404 NOT_FOUND`, `422 UNSUPPORTED_FORMAT`.

---

## 15. Database Requirements & Schema Design

NetSentinel AI uses **PostgreSQL 16** with `pgvector` (vector similarity search) and `tsvector` (full-text search). All primary keys use UUIDv7/UUIDv4 (`UUID`). Timestamps use `TIMESTAMPTZ` in UTC.

### 15.1 Entity-Relationship Diagram

```mermaid
erDiagram
    organizations ||--o{ organization_members : "has"
    users ||--o{ organization_members : "belongs_to"
    organizations ||--o{ traffic_datasets : "owns"
    traffic_datasets ||--o{ network_flows : "contains"
    organizations ||--o{ model_versions : "scoping_optional"
    network_flows ||--o{ detection_results : "evaluated_by"
    model_versions ||--o{ detection_results : "produced_by"
    detection_results ||--o{ alerts : "triggers"
    organizations ||--o{ alerts : "owns"
    organizations ||--o{ incidents : "owns"
    incidents ||--o{ incident_alerts : "links"
    alerts ||--o{ incident_alerts : "grouped_in"
    incidents ||--o{ investigations : "analyzed_by"
    investigations ||--o{ agent_runs : "executes"
    investigations ||--o{ evidence_items : "cites"
    investigations ||--o{ recommendations : "proposes"
    security_documents ||--o{ document_chunks : "split_into"
    document_chunks ||--o{ evidence_items : "referenced_by"
    organizations ||--o{ audit_logs : "records"
    users ||--o{ audit_logs : "actor"
```

### 15.2 Normalized Table Specifications

| Table | Key Columns & Data Types | Constraints & Indexes |
| :--- | :--- | :--- |
| **`organizations`** | `id` (UUID PK), `name` (VARCHAR 120), `slug` (VARCHAR 80), `retention_days` (INT DEFAULT 90), `is_active` (BOOL), `created_at` (TIMESTAMPTZ) | `UNIQUE(slug)` |
| **`users`** | `id` (UUID PK), `email` (CITEXT), `password_hash` (TEXT), `full_name` (VARCHAR 120), `is_super_admin` (BOOL), `is_active` (BOOL), `last_login_at` (TIMESTAMPTZ), `created_at` (TIMESTAMPTZ) | `UNIQUE(email)` |
| **`organization_members`** | `id` (UUID PK), `organization_id` (UUID FK → `organizations`), `user_id` (UUID FK → `users`), `role` (VARCHAR 32), `created_at` (TIMESTAMPTZ) | `UNIQUE(organization_id, user_id)`, `IDX(user_id)` |
| **`traffic_datasets`** | `id` (UUID PK), `organization_id` (UUID FK), `uploaded_by` (UUID FK → `users`), `name` (VARCHAR 120), `storage_bucket` (VARCHAR 64), `storage_key` (TEXT), `file_size_bytes` (BIGINT), `sha256` (CHAR 64), `status` (VARCHAR 24), `progress_pct` (SMALLINT), `packet_count` (BIGINT), `flow_count` (BIGINT), `error_message` (TEXT), `tags` (JSONB), `created_at`, `completed_at` | `UNIQUE(organization_id, sha256)` (or non-unique if re-uploads allowed; indexed), `IDX(organization_id, created_at DESC)`, `IDX(status)` |
| **`network_flows`** | `id` (UUID PK), `organization_id` (UUID FK), `dataset_id` (UUID FK → `traffic_datasets`), `src_ip` (INET), `dst_ip` (INET), `src_port` (INT), `dst_port` (INT), `protocol` (VARCHAR 16), `start_time` (TIMESTAMPTZ), `end_time` (TIMESTAMPTZ), `duration_ms` (DOUBLE PRECISION), `fwd_packets` (INT), `bwd_packets` (INT), `bytes_total` (BIGINT), `tcp_flags` (JSONB), `feature_vector` (JSONB) | `IDX(organization_id, dataset_id, start_time)`, `IDX(organization_id, src_ip)`, `IDX(organization_id, dst_ip)`, `IDX(dst_port, protocol)` |
| **`model_versions`** | `id` (UUID PK), `organization_id` (UUID NULLABLE FK; NULL = global), `name` (VARCHAR 80), `model_type` (VARCHAR 32: `isolation_forest`, `xgboost`, `random_forest`, `autoencoder`), `version` (VARCHAR 32), `stage` (VARCHAR 20: `staging`, `active`, `archived`), `artifact_storage_key` (TEXT), `feature_schema_hash` (CHAR 64), `training_dataset_ref` (VARCHAR 120), `hyperparameters` (JSONB), `metrics` (JSONB), `threshold_config` (JSONB), `created_by` (UUID FK), `created_at` | `UNIQUE(name, version)`, `IDX(model_type, stage)` |
| **`detection_results`** | `id` (UUID PK), `organization_id` (UUID FK), `flow_id` (UUID FK → `network_flows`), `model_version_id` (UUID FK → `model_versions`), `anomaly_score` (DOUBLE PRECISION), `predicted_class` (VARCHAR 64), `confidence` (DOUBLE PRECISION), `classification_tier` (VARCHAR 24: `benign`, `anomalous`, `suspicious`), `shap_values` (JSONB), `created_at` | `IDX(organization_id, flow_id)`, `IDX(organization_id, classification_tier, created_at DESC)`, `IDX(model_version_id)` |
| **`alerts`** | `id` (UUID PK), `organization_id` (UUID FK), `dataset_id` (UUID FK), `detection_result_id` (UUID FK → `detection_results`), `title` (VARCHAR 200), `summary` (TEXT), `severity` (VARCHAR 16), `classification_tier` (VARCHAR 24), `status` (VARCHAR 24), `assigned_to` (UUID NULLABLE FK → `users`), `created_at`, `updated_at` | `IDX(organization_id, status, severity)`, `IDX(organization_id, created_at DESC)` |
| **`incidents`** | `id` (UUID PK), `organization_id` (UUID FK), `title` (VARCHAR 200), `description` (TEXT), `severity` (VARCHAR 16), `status` (VARCHAR 24: `open`, `investigating`, `contained`, `closed`), `verdict` (VARCHAR 32: `pending`, `benign`, `anomalous`, `suspicious`, `confirmed_malicious`, `false_positive`), `created_by` (UUID FK), `assigned_to` (UUID NULLABLE FK), `created_at`, `updated_at` | `IDX(organization_id, status, severity)`, `IDX(organization_id, verdict)` |
| **`incident_alerts`** | `incident_id` (UUID FK → `incidents`), `alert_id` (UUID FK → `alerts`), `linked_at` (TIMESTAMPTZ), `linked_by` (UUID FK) | `PRIMARY KEY(incident_id, alert_id)`, `IDX(alert_id)` |
| **`security_documents`** | `id` (UUID PK), `organization_id` (UUID NULLABLE FK; NULL = global intel), `source_type` (VARCHAR 32: `mitre_attack`, `cve`, `advisory`, `network_doc`, `incident_report`, `internal_kb`), `external_id` (VARCHAR 100), `title` (VARCHAR 255), `source_url` (TEXT), `content_sha256` (CHAR 64), `metadata` (JSONB), `published_at` (TIMESTAMPTZ), `ingested_at` (TIMESTAMPTZ) | `UNIQUE(organization_id, source_type, external_id)` (with partial unique index for NULL `organization_id`), `IDX(source_type)` |
| **`document_chunks`** | `id` (UUID PK), `document_id` (UUID FK → `security_documents` ON DELETE CASCADE), `organization_id` (UUID NULLABLE FK), `chunk_index` (INT), `section_header` (VARCHAR 255), `content` (TEXT), `token_count` (INT), `embedding` (`vector(768)`), `tsv` (`tsvector` GENERATED ALWAYS AS `to_tsvector('english', coalesce(section_header,'') || ' ' || content)` STORED), `metadata` (JSONB) | `HNSW` index on `embedding` (`vector_cosine_ops`, `m=16`, `ef_construction=64`), `GIN` index on `tsv`, `IDX(document_id, chunk_index)` |
| **`investigations`** | `id` (UUID PK), `organization_id` (UUID FK), `incident_id` (UUID FK → `incidents`), `triggered_by` (UUID FK → `users`), `status` (VARCHAR 24: `queued`, `running`, `completed`, `failed`, `partial`), `executive_summary` (TEXT), `hypothesis` (TEXT), `validation_status` (VARCHAR 24: `verified`, `partially_verified`, `flagged`), `revision_count` (SMALLINT DEFAULT 0), `state_snapshot` (JSONB), `langfuse_trace_id` (VARCHAR 128), `started_at`, `completed_at` | `IDX(organization_id, incident_id)`, `IDX(status)` |
| **`agent_runs`** | `id` (UUID PK), `organization_id` (UUID FK), `investigation_id` (UUID FK → `investigations`), `agent_name` (VARCHAR 64), `step_order` (INT), `attempt_number` (SMALLINT), `status` (VARCHAR 24), `input_payload` (JSONB), `output_payload` (JSONB), `error_message` (TEXT), `latency_ms` (INT), `token_usage` (JSONB), `created_at` | `IDX(investigation_id, step_order)` |
| **`evidence_items`** | `id` (UUID PK), `organization_id` (UUID FK), `investigation_id` (UUID FK → `investigations`), `evidence_type` (VARCHAR 32: `network_flow`, `detection_result`, `document_chunk`, `historical_incident`), `reference_id` (UUID), `claim_text` (TEXT), `excerpt` (TEXT), `validation_verdict` (VARCHAR 24: `supported`, `partially_supported`, `unsupported`), `validator_notes` (TEXT), `created_at` | `IDX(investigation_id, validation_verdict)` |
| **`recommendations`** | `id` (UUID PK), `organization_id` (UUID FK), `investigation_id` (UUID FK → `investigations`), `title` (VARCHAR 200), `category` (VARCHAR 32: `containment`, `eradication`, `hardening`, `monitoring`), `priority` (VARCHAR 16), `description` (TEXT), `risk_impact` (TEXT), `supporting_evidence_ids` (UUID[]), `approval_status` (VARCHAR 24 DEFAULT `'pending_approval'`), `decided_by` (UUID NULLABLE FK → `users`), `decision_rationale` (TEXT), `decided_at` (TIMESTAMPTZ), `created_at` | `IDX(organization_id, approval_status)`, `IDX(investigation_id)` |
| **`audit_logs`** | `id` (UUID PK), `organization_id` (UUID NULLABLE FK), `actor_user_id` (UUID NULLABLE FK), `actor_type` (VARCHAR 24: `user`, `system`, `agent`), `action` (VARCHAR 80), `resource_type` (VARCHAR 64), `resource_id` (UUID NULLABLE), `ip_address` (INET NULLABLE), `metadata` (JSONB), `created_at` (TIMESTAMPTZ) | Append-only policy (no UPDATE/DELETE by app role), `IDX(organization_id, created_at DESC)`, `IDX(resource_type, resource_id)` |

### 15.3 Tenant Isolation, pgvector & Retention Policies
- **Tenant Isolation:** Application repositories enforce `WHERE organization_id = :active_org_id` on every tenant-scoped query; optional PostgreSQL Row-Level Security (RLS) policies can be enabled as defense-in-depth (`SET LOCAL app.current_org_id = ...`). Global threat intel (`organization_id IS NULL`) is readable by all tenants; org-private internal knowledge bases (`organization_id = :org_id`) are strictly isolated.
- **pgvector Schema:** `document_chunks.embedding` uses `vector(768)` matching `BAAI/bge-base-en-v1.5` (configurable to `vector(1024)` if upgraded to `bge-large-en-v1.5` via migration).
- **Retention & Archival:** Raw PCAPs in object storage follow S3 lifecycle rules (default 90 days per `organizations.retention_days`). `network_flows` and `audit_logs` are partitioned by month (`created_at` / `start_time`) in production deployments to allow fast archival/dropping without vacuum overhead.

---

## 16. Data Models (Pydantic v2 Core Contracts)

Core domain schemas mirror the database entities while enforcing strict validation boundaries:
- `FlowFeatureSchema`: Validated numeric feature dictionary with NaN/Inf rejection before ML inference.
- `DetectionOutputSchema`: `flow_id`, `anomaly_score: float`, `predicted_class: str | None`, `confidence: float | None`, `classification_tier: Literal["benign", "anomalous", "suspicious"]`, `shap_top_features: list[ShapFeatureContribution]`.
- `RetrievedChunkSchema`: `chunk_id`, `document_id`, `external_id`, `source_type`, `section_header`, `content`, `rrf_score`, `rerank_score`.
- `InvestigationState` (defined in Section 19.2).

---

## 17. Machine Learning Requirements & Pipeline Specification

### 17.1 ML Inference Pipeline Diagram

```mermaid
flowchart LR
    Flows["Extracted Network Flows (PostgreSQL)"] --> SchemaCheck["Schema & NaN/Inf Validation"]
    SchemaCheck --> Preproc["Versioned Preprocessor (Imputer + RobustScaler + Encoder)"]
    Preproc --> Iso["Isolation Forest (Unsupervised Anomaly Score)"]
    Preproc --> Sup["XGBoost / Random Forest (Supervised Attack Classifier)"]
    Preproc -.->|Optional Post-MVP| AE["Autoencoder (Reconstruction Error)"]

    Iso --> Tier["Deterministic Tier Resolver (benign / anomalous / suspicious)"]
    Sup --> Tier
    AE -.-> Tier

    Tier -->|"If anomalous or suspicious"| SHAP["SHAP Explainer (Top-K Feature Contributions)"]
    Tier --> Persist["Persist detection_results & Generate alerts"]
    SHAP --> Persist
```

### 17.2 Dataset Acquisition & Provenance
Training and offline evaluation use established public intrusion detection benchmarks, each tracked with immutable dataset manifests (source URL, download date, SHA-256, license, split seed):
- **CIC-IDS2017:** Labeled bidirectional network flows covering Benign, DoS/DDoS, PortScan, Brute Force, Web Attacks, Botnet, and Infiltration.
- **UNSW-NB15:** Hybrid modern normal and contemporary synthetic attack behaviors (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).
- **CSE-CIC-IDS2018:** Large-scale enterprise-like topology dataset for generalization and temporal validation.

### 17.3 Data Cleaning, Feature Engineering & Label Encoding
1. **Cleaning:** Strip leading/trailing whitespace in column headers, replace `±Infinity` with `NaN`, drop corrupted rows missing 5-tuple or timestamp, remove duplicate flow records, and drop identifier leakage columns (`Flow ID`, raw `Src IP`, `Dst IP`, raw timestamps) from model feature vectors.
2. **Feature Engineering:** Compute bidirectional flow features: `duration_ms`, forward/backward packet counts and byte totals, packet length stats (min/max/mean/std), Inter-Arrival Time (IAT) stats, flow bytes/sec, flow packets/sec, TCP flag ratios (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), forward-to-backward packet ratio, and normalized destination port buckets (well-known/registered/ephemeral).
3. **Label Encoding:** Map dataset-specific attack strings to a canonical NetSentinel attack taxonomy (`benign`, `dos_ddos`, `port_scan`, `brute_force`, `web_attack`, `botnet`, `infiltration`, `reconnaissance`, `other_attack`) using deterministic, versioned JSON mappings.

### 17.4 Splitting, Leakage Prevention & Imbalance Handling
- **Train/Validation/Test Splitting:** Use **time-ordered or capture-day/host-grouped splits** (70% train / 15% validation / 15% test) rather than naive random shuffling across correlated flow windows.
- **Leakage Prevention:** Fit all imputers, scalers (`RobustScaler`/`StandardScaler`), encoders, and resampling transformations **strictly on the training split** inside a `scikit-learn` `Pipeline`. Persist the fitted pipeline together with the model artifact.
- **Class Imbalance Handling:** Use stratified sampling, class-weighted loss (`scale_pos_weight` / `class_weight="balanced"`), and optional training-only SMOTE/undersampling evaluated strictly on unmodified validation/test distributions.

### 17.5 Model Training, Comparison & Threshold Selection
- **Unsupervised (Isolation Forest):** Trained on benign-dominant flows; outputs continuous normalized anomaly score in `[0.0, 1.0]`. Threshold selected via validation-set FPR cap (proposed target: FPR ≤ 3% on benign validation traffic).
- **Supervised (XGBoost & Random Forest):** Trained on canonical multi-class labels; models compared on Macro F1, PR-AUC, per-class recall, and inference latency. Operating confidence thresholds tuned on the validation set to balance Recall vs. FPR.
- **Optional Autoencoder (Post-MVP):** PyTorch MLP/symmetric autoencoder trained on benign flows; anomaly score derived from standardized MSE reconstruction error.

### 17.6 Evaluation Metrics & Proposed Targets
> **Disclaimer:** No models have been trained yet. Values below are **proposed engineering targets**, not measured benchmark results.

| Metric | Scope | Proposed Target |
| :--- | :--- | :--- |
| **Macro F1** | Supervised multi-class | ≥ 0.88 |
| **Precision (Weighted / Attack)** | Supervised | ≥ 0.90 |
| **Recall (Attack Classes)** | Supervised | ≥ 0.85 |
| **PR-AUC** | Imbalanced attack detection | ≥ 0.90 |
| **ROC-AUC** | Binary anomaly / attack | ≥ 0.94 |
| **False Positive Rate (FPR)** | Benign validation set | ≤ 3.0% |
| **Confusion Matrix** | Per-class breakdown | Logged per `model_version` |
| **Inference Latency** | 10,000 flows + SHAP Top-K | ≤ 15 s (4-vCPU worker) |

### 17.7 Explainability, Versioning & Drift Monitoring
- **Explainability:** `shap.TreeExplainer` for XGBoost/Random Forest and `TreeExplainer`/feature-perturbation attribution for Isolation Forest. Top-K (default `K=8`) features with signed SHAP contributions are stored in `detection_results.shap_values`.
- **Versioning:** Serialized with `joblib` (and optionally tracked in `MLflow`), uploaded to object storage, and registered in `model_versions` with `feature_schema_hash`.
- **Drift Monitoring (Post-MVP v1.1):** Scheduled jobs compute Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) statistics comparing incoming production flow features against training baseline histograms, flagging drift when `PSI > 0.2`.

---

## 18. RAG Requirements & Architecture

### 18.1 RAG Retrieval Pipeline Diagram

```mermaid
flowchart LR
    subgraph Ingestion["Offline / Batch Knowledge Ingestion"]
        Docs["MITRE ATT&CK, CVEs, Advisories, Incident Reports, Internal KB"] --> Parse["Format Parsers (STIX/JSON/MD/PDF)"]
        Parse --> Chunk["Structure-Aware Chunker (512 tokens, 64 overlap)"]
        Chunk --> Embed["BGE Embedder (BAAI/bge-base-en-v1.5)"]
        Embed --> Store["PostgreSQL (document_chunks: pgvector HNSW + tsvector GIN)"]
    end

    subgraph Retrieval["Online Hybrid Retrieval"]
        Query["Sanitized Query + Org Scope"] --> QEmbed["Query Embedding (BGE)"]
        Query --> FTS["Lexical Search (PostgreSQL FTS ts_rank_cd, Top-30)"]
        QEmbed --> Vec["Vector Search (pgvector Cosine HNSW, Top-30)"]
        FTS --> RRF["Reciprocal Rank Fusion (k=60, Top-20)"]
        Vec --> RRF
        RRF --> Rerank["Cross-Encoder Reranker (BAAI/bge-reranker-base, Top-K)"]
        Rerank --> Cited["Evidence-Linked Chunks (chunk_id + metadata)"]
    end
```

### 18.2 Ingestion, Chunking & Metadata Extraction
- **Supported Sources:** MITRE ATT&CK Enterprise STIX/JSON, NVD CVE JSON 2.0 feeds, CISA/vendor advisories, network protocol/security documentation, anonymized historical incident reports, and org-scoped internal runbooks.
- **Chunking:** Structure-aware splitting by heading/section (target 400–512 tokens, 64-token overlap), preserving identifiers (`external_id`, `section_header`, `tactics`, `cvss_score`, `affected_ports`) in `document_chunks.metadata`.
- **Hybrid Retrieval & Fusion:**
  - Dense retrieval: Cosine distance over `pgvector` HNSW index (`top_k = 30`).
  - Keyword retrieval: PostgreSQL `websearch_to_tsquery` + `ts_rank_cd` over `tsv` GIN index (`top_k = 30`), crucial for exact identifiers like `CVE-2024-3094` or `T1046`.
  - Fusion: Reciprocal Rank Fusion: $\text{RRF}(d) = \sum_{r \in \{\text{vec}, \text{fts}\}} \frac{1}{60 + \text{rank}_r(d)}$.
  - Reranking: Top-20 fused candidates scored by `BAAI/bge-reranker-base`, returning final `top_k` (default 5–10) chunks.
- **Retrieval Evaluation:** Automated script measures Recall@5, Recall@10, MRR@10, and NDCG@5 against a curated gold query-document benchmark (proposed target: Recall@5 ≥ 0.85, MRR@10 ≥ 0.75).

---

## 19. Agentic AI Requirements & Design Specification

### 19.1 Multi-Agent Investigation Workflow Diagram

```mermaid
stateDiagram-v2
    [*] --> DetectionAnalyst
    DetectionAnalyst --> ThreatIntelligence: "structured_findings"
    ThreatIntelligence --> InvestigationCoordinator: "retrieved_intel_chunks"
    InvestigationCoordinator --> ResponseAdvisor: "correlated_hypothesis"
    ResponseAdvisor --> EvidenceValidator: "draft_recommendations"

    EvidenceValidator --> Completed: "validation == verified"
    EvidenceValidator --> InvestigationCoordinator: "validation == needs_revision AND revision_count < 2"
    EvidenceValidator --> CompletedFlagged: "validation == flagged OR revision_count >= 2"

    DetectionAnalyst --> Failed: "timeout / unrecoverable error"
    ThreatIntelligence --> Failed: "timeout / unrecoverable error"
    InvestigationCoordinator --> Failed: "timeout / unrecoverable error"
    ResponseAdvisor --> Failed: "timeout / unrecoverable error"

    Completed --> [*]
    CompletedFlagged --> [*]
    Failed --> [*]
```

### 19.2 Shared LangGraph State Schema (`InvestigationState`)

```python
class InvestigationState(TypedDict):
    investigation_id: str
    organization_id: str
    incident_id: str
    alert_ids: list[str]
    flow_summaries: list[dict]           # Untrusted network metadata (sanitized)
    detection_summaries: list[dict]      # ML scores, classes, SHAP top-K
    detection_analysis: dict | None      # Output of Detection Analyst
    threat_intel_chunks: list[dict]      # Output of Threat Intelligence (cited chunk_ids)
    correlation_report: dict | None      # Output of Investigation Coordinator
    recommendations: list[dict]          # Output of Response Advisor (advisory only)
    validation_result: dict | None       # Output of Evidence Validator
    revision_count: int                  # Bounded: max 2
    errors: list[dict]
    status: Literal["running", "completed", "completed_flagged", "failed"]
```

### 19.3 Detailed Agent Specifications

| Dimension | 1. Detection Analyst Agent | 2. Threat Intelligence Agent | 3. Investigation Coordinator Agent | 4. Response Advisor Agent | 5. Evidence Validator Agent |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Purpose** | Interpret ML scores, SHAP attributions, and flow metadata into structured technical observations. | Query hybrid RAG for relevant MITRE ATT&CK techniques, CVEs, and advisories. | Correlate detection observations, flow records, historical incidents, and threat intel into a cohesive hypothesis and timeline. | Propose prioritized, advisory-only containment, eradication, and hardening recommendations. | Independently verify that every claim and recommendation is backed by retrieved evidence and DB records. |
| **Input Schema** | `DetectionAnalystInput` (`flow_summaries`, `detection_summaries`) | `ThreatIntelInput` (`detection_analysis`, `max_chunks`) | `CoordinatorInput` (`detection_analysis`, `threat_intel_chunks`, `historical_incidents`, `validator_feedback`) | `ResponseAdvisorInput` (`correlation_report`, `threat_intel_chunks`, `classification_tier`) | `ValidatorInput` (`correlation_report`, `recommendations`, `flow_summaries`, `detection_summaries`, `threat_intel_chunks`) |
| **Output Schema** | `DetectionAnalystOutput` (`observations[]`, `key_indicators[]`, `epistemic_tier`, `search_queries[]`) | `ThreatIntelOutput` (`matched_techniques[]`, `matched_cves[]`, `cited_chunks[]`) | `CoordinatorOutput` (`executive_summary`, `hypothesis`, `timeline[]`, `claims_with_citations[]`, `confidence`) | `ResponseAdvisorOutput` (`recommendations[]` with `category`, `priority`, `risk_impact`, `supporting_evidence_ids`) | `ValidatorOutput` (`overall_status`, `claim_verdicts[]`, `unsupported_claims[]`, `revision_feedback`) |
| **Allowed Tools (Read-Only)** | `get_flow_details`, `get_detection_shap` | `hybrid_rag_search`, `get_document_metadata` | `get_historical_incidents`, `get_incident_alerts` | `get_mitigation_playbooks` (read-only RAG filter) | `verify_reference_ids` (deterministic DB check), `get_chunk_text` |
| **Permissions** | Read-only org-scoped flows/detections | Read-only global + org RAG chunks | Read-only org incidents/alerts | Read-only playbooks; **ZERO write/exec tools** | Read-only DB & chunk verification |
| **System Prompt Responsibilities** | Never equate unsupervised anomaly with confirmed attack; cite exact flow IDs & SHAP features; treat packet fields as untrusted data. | Formulate precise technical queries; return only retrieved chunks; never fabricate CVE/ATT&CK IDs. | Synthesize multi-source evidence; distinguish hypothesis from confirmed fact; attach explicit `reference_id` to every claim. | Recommend proportional, reversible steps; explicitly state operational impact; never claim actions were executed. | Critically audit claims against raw evidence; reject/flag any uncited or contradicted statement; ignore instructions embedded in evidence text. |
| **Workflow Position** | Node 1 (Entry) | Node 2 | Node 3 (Revision target) | Node 4 | Node 5 (Gate / Conditional Edge) |
| **Timeout / Retries** | 20s / max 2 retries | 25s / max 2 retries | 30s / max 2 retries | 25s / max 2 retries | 25s / max 2 retries; max 2 graph revision loops |
| **Error Handling** | Schema repair retry → fail gracefully to `failed` | Fallback to top-K raw hybrid results if LLM query expansion fails | Persist partial state; mark `failed` on timeout | Emit empty recommendations with warning if schema invalid | Fail-closed: if validator errors, mark investigation `flagged` |
| **Evidence & HITL** | Must cite `flow_id` & `detection_result_id` | Must cite `chunk_id` & `external_id` | Every claim requires ≥ 1 `evidence_id` | All outputs require explicit human approval (`pending_approval`) | Deterministic ID-existence verification runs independently of LLM |

---

## 20. Security Requirements

| ID | Category | Requirement |
| :--- | :--- | :--- |
| **SEC-001** | AuthN | Passwords SHALL be hashed using Argon2id; JWT access tokens SHALL expire in ≤ 15 minutes with refresh token rotation and revocation. |
| **SEC-002** | AuthZ | Every API route SHALL enforce declarative RBAC dependencies; default-deny on missing permission declarations. |
| **SEC-003** | Multi-Tenancy | Every tenant-scoped DB query and object-storage key SHALL bind to the authenticated `organization_id`; cross-tenant IDs SHALL return `404` or `403`. |
| **SEC-004** | Upload Safety | PCAP uploads SHALL validate magic bytes, enforce size caps, store outside executable paths in object storage, and parse inside memory/CPU-bounded worker containers. |
| **SEC-005** | Prompt Injection Defense | Packet metadata (DNS, HTTP host/URI, payload strings) and retrieved RAG chunks SHALL be wrapped in explicit data delimiters and treated strictly as untrusted data, never system instructions. |
| **SEC-006** | Tool Safety | All agent tools SHALL use strict Pydantic schemas, parameterized SQL queries, and read-only DB/RAG access. No shell, filesystem-write, or outbound arbitrary HTTP tools SHALL be exposed to agents. |
| **SEC-007** | Action Guardrails | Response Advisor recommendations SHALL remain advisory (`pending_approval`) until an `incident_responder` or `org_admin` records explicit approval; no autonomous network blocking is permitted. |
| **SEC-008** | Verification Independence | Existence checks for cited `flow_id`, `detection_result_id`, and `chunk_id` SHALL be verified deterministically in Python/SQL independent of the LLM provider. |
| **SEC-009** | Transport & Storage Encryption | TLS 1.2+ SHALL encrypt all external traffic (Nginx); S3 server-side encryption and PostgreSQL TLS SHALL be supported in production. |
| **SEC-010** | Secrets Management | API keys, DB credentials, and JWT signing keys SHALL never be committed to Git; loaded solely via environment variables / secret manager. |
| **SEC-011** | Rate Limiting | Auth, upload, RAG search, and investigation trigger endpoints SHALL enforce per-IP and per-org rate limits (Nginx / Redis). |
| **SEC-012** | Auditability | Security-relevant events (login, RBAC changes, uploads, verdict changes, approvals) SHALL be written to append-only `audit_logs`. |
| **SEC-013** | Privacy & PII | Optional IP anonymization SHALL be supported on report exports; configurable tenant retention policies SHALL purge expired PCAPs and flows. |
| **SEC-014** | Dependency Hygiene | CI SHALL run dependency vulnerability scanning (`pip-audit`, `npm audit`) and static security analysis (`bandit`). |
| **SEC-015** | Ethical Use | Documentation and UI SHALL explicitly state that NetSentinel AI is designed for authorized defensive network monitoring and forensic analysis only. |

---

## 21. Error Handling

- **API Layer:** Global FastAPI exception handlers map domain errors (`NotFoundError`, `TenantAccessError`, `InvalidPcapError`, `ModelNotActiveError`, `RateLimitError`) to deterministic HTTP status codes and the standard JSON error envelope without leaking stack traces in production.
- **Worker Layer:** Transient infrastructure errors (Redis/DB connection blips, LLM 429/5xx) retry with jittered exponential backoff (max 3 attempts). Permanent errors (corrupt PCAP, schema violation after retry) mark the job/entity `failed`, store sanitized diagnostics, and emit an OpenTelemetry error span.
- **Graceful Degradation:** If the external LLM provider is unavailable, PCAP ingestion, ML detection, SHAP explainability, alert triage, and hybrid RAG search continue operating unaffected.

---

## 22. Logging and Monitoring

- **Structured Logging:** JSON logs (`structlog`) emitted to stdout across FastAPI and Celery workers with `timestamp`, `level`, `service`, `correlation_id`, `organization_id`, and `task_id`. Sensitive fields (passwords, tokens, API keys) are redacted.
- **Distributed Tracing:** OpenTelemetry SDK instruments FastAPI, SQLAlchemy, Redis, Celery, and HTTPX, exporting OTLP traces and metrics (request latency, worker queue depth, task failure rates).
- **LLM & Agent Observability:** Langfuse captures trace trees for every investigation (prompt version, latency per agent node, token counts, validation pass/flag rates, revision counts).

---

## 23. Performance and Scalability

- **Bulk Persistence:** Flow extraction and ML inference workers use PostgreSQL batch inserts (`COPY` / `insert().values()` in chunks of 1,000–5,000 rows) to avoid N+1 write bottlenecks.
- **Dedicated Queues:** Separate Celery queues (`q_ingestion`, `q_ml`, `q_rag`, `q_agents`) prevent long-running PCAP parses or LLM calls from starving fast ML or indexing jobs.
- **Model & Embedding Caching:** ML models (Joblib) and BGE embedding/reranker weights are loaded once per worker process and cached in memory.
- **Indexing:** Composite B-tree indexes on `(organization_id, created_at DESC)`, HNSW index on `document_chunks.embedding`, and GIN index on `document_chunks.tsv`.

---

## 24. Deployment Requirements

### 24.1 Deployment Architecture Diagram

```mermaid
flowchart TB
    Users["Users / SOC Analysts"] -->|HTTPS 443| Nginx["Nginx Container (Reverse Proxy + Static React Build)"]
    Nginx -->|/api/v1| FastAPI["FastAPI Container(s) (Uvicorn / Gunicorn)"]

    subgraph WorkerContainers["Worker Containers (Docker Compose / Orchestrator)"]
        W1["Celery Ingestion Worker (q_ingestion)"]
        W2["Celery ML Worker (q_ml)"]
        W3["Celery RAG Worker (q_rag)"]
        W4["Celery Agent Worker (q_agents)"]
    end

    FastAPI --> PG["PostgreSQL 16 + pgvector Container"]
    FastAPI --> Redis["Redis 7 Container"]
    FastAPI --> MinIO["MinIO / S3 Object Storage"]

    W1 & W2 & W3 & W4 --> PG
    W1 & W2 & W3 & W4 --> Redis
    W1 & W2 --> MinIO
    W4 -->|HTTPS| LLM["External / Self-Hosted LLM API"]

    FastAPI & WorkerContainers -->|OTLP| OTel["OpenTelemetry Collector"]
    W4 -->|HTTPS| Langfuse["Langfuse Server"]
```

- **Containerization:** Multi-stage Dockerfiles for backend (`python:3.12-slim`) and frontend (`node:20-alpine` → `nginx:alpine`), orchestrated via `docker-compose.yml` for local/staging and portable to Kubernetes/ECS for production.
- **Migrations:** Alembic migrations run as an explicit pre-deploy step (`alembic upgrade head`) before starting API/worker containers.
- **CI/CD:** GitHub Actions runs linting, type checking, unit/integration tests (with ephemeral Postgres+pgvector and Redis services), Playwright E2E tests, and container image builds on every PR.

---

## 25. Testing Requirements

| Test Layer | Tools | Scope & Requirements |
| :--- | :--- | :--- |
| **Unit Tests** | `pytest` | Feature extraction math, tier resolver (`anomalous` vs `suspicious`), RRF scoring, Pydantic schemas, prompt sanitization, deterministic validator checks. |
| **Integration Tests** | `pytest`, `httpx`, Testcontainers / CI services | FastAPI endpoints, Alembic migrations, tenant isolation (cross-org negative tests), pgvector + FTS hybrid search, Celery task execution with mocked LLM. |
| **ML Evaluation Tests** | `pytest` / eval CLI | Reproducible pipeline smoke test, leakage guardrails, metric calculation (Precision, Recall, Macro F1, PR-AUC, ROC-AUC, FPR). |
| **RAG Evaluation Tests** | Eval harness | Recall@5, MRR@10, NDCG@5 on curated security QA benchmark; prompt-injection resilience fixtures. |
| **Agent Tests** | `pytest` + mocked LLM adapter | State transitions, bounded retry/revision limits, Evidence Validator flagging of fabricated IDs, HITL approval enforcement. |
| **End-to-End UI Tests** | `Playwright` | Login, PCAP upload, flow viewing, alert triage, incident investigation workspace, recommendation approval flow. |

---

## 26. Traceability Matrix

| PRD User Story | SRS Functional Req(s) | Security / NFR | Primary DB Tables | Primary API Endpoints |
| :--- | :--- | :--- | :--- | :--- |
| **US-001** (Auth & Tenancy) | FR-001..FR-004 | SEC-001..003, NFR-001 | `users`, `organizations`, `organization_members` | `POST /api/v1/auth/login`, `GET /api/v1/auth/me` |
| **US-002 / US-003** (PCAP Upload & Async) | FR-005..FR-008 | SEC-004, NFR-002, NFR-008 | `traffic_datasets`, `network_flows` | `POST /api/v1/datasets/upload`, `POST /api/v1/datasets/{id}/process` |
| **US-004** (Flow Exploration) | FR-009 | NFR-001 | `network_flows` | `GET /api/v1/datasets/{id}/flows` |
| **US-005 / US-006** (ML + SHAP) | FR-010..FR-015 | NFR-003, NFR-014 | `model_versions`, `detection_results` | `POST /api/v1/datasets/{id}/detect`, `GET /api/v1/detections/{id}/explain` |
| **US-007 / US-008** (Alerts & Incidents) | FR-016..FR-019 | SEC-002, SEC-012 | `alerts`, `incidents`, `incident_alerts` | `GET/PATCH /api/v1/alerts`, `POST /api/v1/incidents` |
| **US-009 / US-010** (Hybrid RAG) | FR-020..FR-024 | SEC-005, NFR-004 | `security_documents`, `document_chunks` | `POST /api/v1/threat-intel/search` |
| **US-011..US-014** (Multi-Agent & HITL) | FR-025..FR-030, FR-033 | SEC-005..008, NFR-005, NFR-010 | `investigations`, `agent_runs`, `evidence_items`, `recommendations` | `POST /api/v1/incidents/{id}/investigations`, `POST .../approve` |
| **US-015..US-017** (Reports, Analytics, Audit) | FR-031, FR-032, FR-034 | SEC-012, SEC-013, NFR-009 | `audit_logs`, `model_versions`, `incidents` | `POST /api/v1/incidents/{id}/reports` |

---

## 27. Acceptance Criteria & Open Questions

### 27.1 Technical Acceptance Criteria
1. All 17 normalized PostgreSQL tables deploy cleanly via Alembic with `pgvector` HNSW and `tsvector` GIN indexes verified.
2. All 9 core API contract domains pass automated schema, auth, RBAC, and tenant-isolation integration tests.
3. ML pipeline produces reproducible artifacts with zero train/test leakage and persists SHAP attributions for flagged flows.
4. Hybrid RAG (pgvector + FTS + RRF + BGE reranker) executes end-to-end and passes retrieval evaluation harness checks.
5. LangGraph 5-agent workflow enforces typed state, timeouts, bounded retries, deterministic reference verification, and HITL approval gates.
6. Full stack boots via Docker Compose with healthy `/health/ready` checks and CI green across Pytest and Playwright suites.

### 27.2 OPEN QUESTIONS
- **OQ-SRS-01:** Worker task framework selection: `Celery` (assumed in this specification) vs. `Dramatiq` or `ARQ` for async Python workers.
- **OQ-SRS-02:** Packet parsing engine for large PCAPs (> 250 MB): `Scapy`/`PyShark` (specified for MVP) vs. adding `NFStream`/`dpkt` as a high-throughput extraction backend.
- **OQ-SRS-03:** Default embedding dimensionality: `BAAI/bge-base-en-v1.5` (`vector(768)`, assumed for MVP CPU efficiency) vs. `BAAI/bge-large-en-v1.5` (`vector(1024)`).
- **OQ-SRS-04:** PostgreSQL Row-Level Security (RLS) enforcement: enable in MVP v1.0 or rely on repository-layer `organization_id` scoping in v1.0 and add RLS in v1.1.
- **OQ-SRS-05:** Model registry backend: lightweight `Joblib` + PostgreSQL `model_versions` + S3 in MVP vs. running a dedicated `MLflow` tracking server container from day one.
