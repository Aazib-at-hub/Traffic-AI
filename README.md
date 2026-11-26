# NetSentinel AI

**Intelligent Network Threat Detection and Autonomous Security Investigation Platform**

> **Project Status:** MVP v0.1 Codebase Implemented (Modular Monolith + Background Workers + React/TS SOC Dashboard). Live traffic streaming, PyTorch Autoencoder, and drift monitoring remain planned for post-MVP milestones.

---

## 1. Overview

**NetSentinel AI** is a production-oriented cybersecurity platform that bridges the gap between statistical network anomaly detection and evidence-backed incident investigation.

Rather than relying on black-box anomaly alerts or unconstrained LLM wrappers, NetSentinel AI combines four deterministic and AI-assisted layers inside a **modular monolith with dedicated background workers**:

1. **Deterministic Network Processing:** Validates and parses `.pcap`/`.pcapng` captures into bidirectional network flows and protocol metadata.
2. **Explainable Machine Learning Detection:** Pairs unsupervised anomaly detection (Isolation Forest; optional Autoencoder post-MVP) with supervised attack classification (XGBoost / Random Forest) and SHAP feature attribution. Explicitly separates **anomalous**, **suspicious**, and **confirmed malicious** traffic.
3. **Evidence-Grounded Security Intelligence RAG:** Retrieves MITRE ATT&CK techniques, CVE records, advisories, and internal runbooks via hybrid search (`pgvector` + PostgreSQL Full-Text Search), Reciprocal Rank Fusion (RRF), and BGE cross-encoder reranking.
4. **Controlled Multi-Agent Investigation:** Orchestrates five specialized **LangGraph** agents under typed schemas, bounded retries, deterministic evidence verification, and mandatory human-in-the-loop approval for all response recommendations.

For full product and engineering specifications, see:
- **Product Requirements Document:** [docs/PRD.md](docs/PRD.md)
- **Software Requirements Specification:** [docs/SRS.md](docs/SRS.md)

---

## 2. Key Capabilities

- **Asynchronous PCAP Ingestion:** Magic-byte validation, S3-compatible object storage for raw captures, and background bidirectional flow feature extraction (`Scapy` / `PyShark`).
- **Dual-Paradigm Explainable ML:** Isolation Forest + XGBoost/Random Forest with versioned preprocessing pipelines, model versioning, and persisted SHAP top-K feature contributions.
- **Hybrid Security RAG:** Structure-aware chunking, BGE embeddings (`BAAI/bge-base-en-v1.5`), `pgvector` HNSW + PostgreSQL `tsvector` FTS, RRF fusion, and `BAAI/bge-reranker-base` reranking.
- **5-Agent LangGraph Investigation Engine:**
  - **Detection Analyst Agent:** Interprets ML scores, SHAP values, and flow statistics.
  - **Threat Intelligence Agent:** Retrieves cited MITRE ATT&CK techniques, CVEs, and advisories.
  - **Investigation Coordinator Agent:** Correlates flows, alerts, history, and threat intel into a hypothesis and timeline.
  - **Response Advisor Agent:** Proposes advisory-only containment and hardening actions (zero autonomous execution).
  - **Evidence Validator Agent:** Verifies claims against raw DB records and retrieved chunks; flags unsupported statements.
- **Security Operations Dashboard:** Multi-tenant React + TypeScript UI covering Traffic Analytics, Dataset Management, Alert/Incident Triage, Investigation Workspace (React Flow), Threat Intel Viewer, Agent History, Model Analytics, Reports, and Audit Logs.

---

## 3. Feature Highlights

| Area | Implemented (v0.1) | Planned (Post-MVP) |
| :--- | :--- | :--- |
| **Documentation & Architecture** | PRD, SRS, DB Schema, API Contracts, 9 Mermaid Diagrams | — |
| **Traffic Ingestion** | PCAP/PCAPNG magic-byte validation, S3/local storage, bidirectional flow extraction | Live traffic streaming (Zeek / NetFlow / IPFIX) |
| **ML Detection** | Isolation Forest, XGBoost/RF, SHAP top-K attribution, model versioning, training/eval CLI | Optional PyTorch Autoencoder, Automated Drift Monitoring |
| **Security RAG** | MITRE ATT&CK + CVE Hybrid Search (`pgvector` + FTS + RRF + BGE reranker), ingest/eval CLI | STIX/TAXII automated threat feed sync |
| **Agentic SOC** | 5-Agent LangGraph Workflow, Deterministic Evidence Validator, HITL Approval | Approval-gated SOAR / ticketing webhooks |
| **Dashboard & Observability** | Multi-tenant RBAC, React/TS SOC Dashboard, Audit Logs, OTel & Langfuse hooks | Enterprise SSO / OIDC, PostgreSQL RLS |

---

## 4. Architecture Overview

```mermaid
flowchart TB
    UI["React + TypeScript SPA (Vite, Tailwind, Recharts, React Flow)"] -->|HTTPS| Nginx["Nginx Reverse Proxy"]
    Nginx -->|/api/v1| API["FastAPI Modular Monolith (Python 3.12+)"]

    API --> PG["PostgreSQL 16 + pgvector + FTS"]
    API --> Redis["Redis 7 (Broker & Cache)"]
    API --> S3["S3-Compatible Storage (MinIO / S3)"]

    Redis --> Workers["Background Workers (PCAP, ML/SHAP, RAG, LangGraph Agents)"]
    Workers --> PG
    Workers --> S3
    Workers -->|Provider Adapter| LLM["LLM Provider (Gemini / OpenAI-Compatible)"]
    API & Workers --> Obs["OpenTelemetry + Langfuse"]
```

Detailed diagrams (System Context, Component, Sequence, ML Pipeline, RAG Pipeline, Multi-Agent Workflow, Database ER, and Deployment) are documented in [docs/SRS.md](docs/SRS.md).

---

## 5. Technology Stack

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, Celery (assumed worker framework; see `OQ-SRS-01`)
- **Packet Processing:** Scapy, PyShark
- **Machine Learning:** Scikit-learn, XGBoost, Pandas, NumPy, SHAP, Joblib / MLflow
- **AI / RAG / Agents:** LangGraph, Provider-Agnostic LLM Adapter (Gemini / OpenAI-compatible), Sentence Transformers (`BAAI/bge-base-en-v1.5`), Cross-Encoder (`BAAI/bge-reranker-base`)
- **Data & Storage:** PostgreSQL 16 (`pgvector` + Full-Text Search), Redis 7, S3-compatible Object Storage (MinIO / AWS S3)
- **Frontend:** React, TypeScript, Vite, Tailwind CSS, Recharts, React Flow
- **Infrastructure & Quality:** Docker, Docker Compose, Nginx, GitHub Actions, Pytest, Playwright, OpenTelemetry, Langfuse

---

## 6. Planned Repository Structure

> **Note:** Only `README.md`, `docs/PRD.md`, and `docs/SRS.md` currently exist. The tree below represents the target modular monolith layout.

```text
netsentinel-ai/
├── README.md
├── docs/
│   ├── PRD.md                       # Product Requirements Document (exists)
│   └── SRS.md                       # Software Requirements Specification (exists)
├── backend/                         # [TODO] FastAPI modular monolith + workers
│   ├── pyproject.toml
│   ├── alembic.ini
│   ├── migrations/                  # Alembic DB migrations
│   ├── src/netsentinel/
│   │   ├── main.py                  # FastAPI entrypoint
│   │   ├── core/                    # Config, security, logging, telemetry
│   │   ├── db/                      # SQLAlchemy 2 models & repositories
│   │   ├── auth/                    # JWT auth, RBAC, multi-tenancy
│   │   ├── ingestion/               # PCAP validation & flow extraction
│   │   ├── ml/                      # Preprocessing, models, SHAP, training/eval
│   │   ├── rag/                     # Parsers, chunking, BGE embed/rerank, hybrid search
│   │   ├── agents/                  # LangGraph state, 5 agents, tools, validator
│   │   ├── incidents/               # Alerts, incidents, recommendations, reports
│   │   └── workers/                 # Celery task definitions
│   └── tests/                       # Pytest unit, integration, ML/RAG/agent tests
├── frontend/                        # [TODO] React + TypeScript + Vite SPA
│   ├── package.json
│   ├── src/
│   └── e2e/                         # Playwright E2E tests
├── infra/                           # [TODO] Dockerfiles, Nginx config, OTel config
├── docker-compose.yml               # [TODO] Local/staging full-stack composition
├── .env.example                     # [TODO] Environment variable template
└── .github/workflows/ci.yml         # [TODO] Lint, test, and build pipeline
```

---

## 7. Screenshots (Placeholders)

> Screenshots will be added once the Security Operations Dashboard (MVP v1.0) is implemented.

- `[PLACEHOLDER: Security Operations Dashboard Overview]`
- `[PLACEHOLDER: Traffic Analytics & Flow Explorer]`
- `[PLACEHOLDER: Alert Triage & SHAP Feature Attribution View]`
- `[PLACEHOLDER: Multi-Agent Investigation Workspace (React Flow) & Evidence Validator]`
- `[PLACEHOLDER: Threat Intelligence Hybrid RAG Viewer]`

---

## 8. Prerequisites

To build and run NetSentinel AI once implemented:
- **Docker** (24+) & **Docker Compose** (v2+)
- **Python 3.12+** (for local backend/ML development)
- **Node.js 20+** & **npm/pnpm** (for local frontend development)
- **LLM API Key** (Gemini or OpenAI-compatible provider) for agent investigations
- **Recommended Hardware:** 4+ vCPU, 16 GB RAM (optional CUDA GPU for faster BGE embedding/reranking)

---

## 9. Installation & Environment Configuration

1. Clone the repository (replace with actual repository URL once hosted):
   ```bash
   git clone <REPOSITORY_URL>
   cd netsentinel-ai
   ```

2. Create environment configuration from the template (`[TODO]` — `.env.example` not yet created):
   ```bash
   cp .env.example .env
   ```

3. Required environment variables (planned):

| Variable | Description | Example / Default |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL 16 async/sync connection string | `postgresql+asyncpg://postgres:postgres@localhost:5432/netsentinel` |
| `REDIS_URL` | Redis broker & cache URL | `redis://localhost:6379/0` |
| `S3_ENDPOINT_URL` | MinIO / S3-compatible endpoint | `http://localhost:9000` |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | Object storage credentials | *(set in `.env`)* |
| `S3_BUCKET_NAME` | Bucket for PCAPs, model artifacts, reports | `netsentinel-data` |
| `JWT_SECRET_KEY` | Signing secret for JWT access/refresh tokens | *(generate 32+ byte random string)* |
| `LLM_PROVIDER` | Active LLM adapter (`gemini` or `openai_compatible`) | `gemini` |
| `LLM_API_KEY` | Provider API key | *(set in `.env`)* |
| `LLM_MODEL_NAME` | Model identifier for agent reasoning | *(provider-specific)* |
| `EMBEDDING_MODEL` | Sentence Transformers embedding model | `BAAI/bge-base-en-v1.5` |
| `RERANKER_MODEL` | Cross-encoder reranker model | `BAAI/bge-reranker-base` |
| `LANGFUSE_HOST` / `LANGFUSE_PUBLIC_KEY` / `LANGFUSE_SECRET_KEY` | Langfuse observability credentials | *(optional for local dev)* |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint | `http://localhost:4317` |

---

## 10. Docker Setup

`[TODO]` — `docker-compose.yml` and Dockerfiles are not yet implemented. Target workflow:

```bash
# [TODO] Build and start PostgreSQL (pgvector), Redis, MinIO, FastAPI, Celery workers, and Nginx/Frontend
docker compose up --build -d

# [TODO] Verify service health
docker compose ps
```

---

## 11. Local Development Setup

`[TODO]` — Backend and frontend scaffolds are not yet implemented. Target workflow:

```bash
# [TODO] Start infrastructure dependencies only
docker compose up -d postgres redis minio

# [TODO] Backend API (from backend/)
pip install -e ".[dev]"
uvicorn netsentinel.main:app --reload --port 8000

# [TODO] Background workers (from backend/)
celery -A netsentinel.workers.app worker --loglevel=info -Q q_ingestion,q_ml,q_rag,q_agents

# [TODO] Frontend dev server (from frontend/)
npm install
npm run dev
```

---

## 12. Database Migrations

`[TODO]` — Alembic configuration and initial migrations for the 17-table schema defined in [docs/SRS.md](docs/SRS.md#15-database-requirements--schema-design) are not yet implemented. Target commands:

```bash
# [TODO] Apply all migrations (including pgvector extension setup)
alembic upgrade head

# [TODO] Generate a new migration after SQLAlchemy model updates
alembic revision --autogenerate -m "describe_change"
```

---

## 13. ML Model Training & Inference

### Training (`[TODO]`)
Target CLI workflow for training Isolation Forest and XGBoost/Random Forest models on CIC-IDS2017 / UNSW-NB15 / CSE-CIC-IDS2018 with leak-free time/group splits:

```bash
# [TODO] Train and evaluate supervised + unsupervised models and register artifacts
python -m netsentinel.ml.train --dataset cic_ids2017 --data-dir ./data/cic_ids2017 --output-dir ./artifacts
```

### Running Inference (`[TODO]`)
Once the API and workers are running, inference is triggered via API or the Dashboard:
- Upload PCAP: `POST /api/v1/datasets/upload`
- Extract flows: `POST /api/v1/datasets/{dataset_id}/process`
- Run ML detection + SHAP: `POST /api/v1/datasets/{dataset_id}/detect`

---

## 14. RAG Knowledge Base Ingestion

`[TODO]` — RAG ingestion CLI is not yet implemented. Target command to parse, chunk, embed (`BAAI/bge-base-en-v1.5`), and index MITRE ATT&CK, CVE feeds, and advisories into `security_documents` and `document_chunks`:

```bash
# [TODO] Ingest MITRE ATT&CK STIX/JSON and NVD CVE records
python -m netsentinel.rag.ingest --source-type mitre_attack --input ./data/intel/enterprise-attack.json
python -m netsentinel.rag.ingest --source-type cve --input ./data/intel/nvdcve-2.0.json
```

---

## 15. Running Agent Investigations

`[TODO]` — Triggered asynchronously via the SOC Dashboard or REST API once an incident is created from correlated alerts:
- Create incident: `POST /api/v1/incidents`
- Launch 5-agent LangGraph investigation: `POST /api/v1/incidents/{incident_id}/investigations`
- Inspect verified evidence & agent runs: `GET /api/v1/investigations/{investigation_id}`
- Approve or reject recommendations (human-in-the-loop): `POST /api/v1/investigations/{investigation_id}/recommendations/{recommendation_id}/approve`

---

## 16. API Documentation

Once the FastAPI backend is implemented, interactive OpenAPI / Swagger documentation will be served at:
- Swagger UI: `http://localhost:8000/docs` *(local dev)*
- ReDoc: `http://localhost:8000/redoc` *(local dev)*

Complete endpoint contracts (Authentication, PCAP Upload, Dataset Processing, Flow Retrieval, Anomaly Detection, Alert Management, Incident Investigation, Threat Intelligence Search, and Report Generation) are specified in [docs/SRS.md](docs/SRS.md#14-api-requirements--example-contracts).

---

## 17. Testing & Evaluation

### Automated Tests (`[TODO]`)
```bash
# [TODO] Backend unit & integration tests
pytest backend/tests -v

# [TODO] Frontend end-to-end tests
npx playwright test
```

### ML & RAG Evaluation (`[TODO]`)
```bash
# [TODO] Evaluate ML models (Precision, Recall, Macro F1, PR-AUC, ROC-AUC, FPR, confusion matrix)
python -m netsentinel.ml.evaluate --model-version <version_id> --test-split ./data/test.parquet

# [TODO] Evaluate Hybrid RAG retrieval (Recall@K, MRR@K, NDCG@K)
python -m netsentinel.rag.evaluate --benchmark ./data/eval/rag_security_qa.jsonl
```

---

## 18. Security Considerations

- **Defensive Use Only:** NetSentinel AI is designed exclusively for authorized network defense, SOC triage, and forensic investigation.
- **Epistemic Discipline:** Unsupervised anomaly detection flags `anomalous` traffic only; it never proves maliciousness on its own. `confirmed_malicious` requires authorized human review.
- **No Autonomous Dangerous Actions:** The Response Advisor Agent is strictly advisory. Every mitigation recommendation defaults to `pending_approval` and cannot execute firewall or host changes.
- **Untrusted Input Boundary:** Uploaded PCAP files are validated by magic bytes, capped in size, and parsed in isolated workers. Packet metadata and retrieved RAG chunks are treated strictly as untrusted data to defend against indirect prompt injection.
- **Deterministic Verification:** Cited flow IDs, detection IDs, and RAG chunk IDs are verified deterministically in SQL/Python independent of the LLM provider.
- **Multi-Tenant Isolation:** Organization scoping is enforced across database queries, API routes, and object-storage keys.

---

## 19. Dataset Acknowledgments & Licenses

NetSentinel AI's planned ML training and evaluation pipelines reference public academic cybersecurity datasets. Users must download these datasets directly from their original providers and comply with each dataset's respective license terms:

- **CIC-IDS2017** & **CSE-CIC-IDS2018:** Canadian Institute for Cybersecurity (University of New Brunswick).
- **UNSW-NB15:** Cyber Range Lab, Australian Centre for Cyber Security (ACCS), UNSW Canberra.
- **MITRE ATT&CK:** © The MITRE Corporation (Apache 2.0 License for ATT&CK data).
- **NVD / CVE Data:** National Vulnerability Database (NIST) / CVE Program.

---

## 20. Known Limitations

- **Greenfield Status:** No application code, trained models, or benchmark measurements exist yet; all numerical metrics in `PRD.md` and `SRS.md` are proposed targets.
- **Offline PCAP First:** MVP v1.0 focuses on uploaded PCAP/PCAPNG files; live streaming traffic ingestion is planned for post-MVP.
- **Encrypted Payloads:** Flow features rely on packet headers, timing, sizes, and TCP flags; TLS-encrypted payloads are not decrypted.
- **LLM Dependency for Synthesis:** While ML detection and RAG retrieval run deterministically without an LLM, multi-agent narrative correlation requires a configured Gemini or OpenAI-compatible LLM provider.

---

## 21. Roadmap

- **M1 (v0.2):** Core platform scaffold, Auth/RBAC, multi-tenancy, Alembic schema, async PCAP ingestion.
- **M2 (v0.4):** Isolation Forest + XGBoost/RF pipeline, SHAP explainability, model versioning, alert management.
- **M3 (v0.6):** Hybrid Security RAG (`pgvector` + FTS + RRF + BGE reranker) and retrieval evaluation harness.
- **M4 (v0.8):** 5-agent LangGraph investigation workflow, Evidence Validator, human-in-the-loop approval gates.
- **M5 (v1.0 — MVP):** Full React/TypeScript SOC Dashboard, incident reports, audit logs, E2E tests, Docker Compose release.
- **M6 (v1.5):** Live traffic ingestion, optional PyTorch Autoencoder, automated feature drift monitoring.
- **M7 (v2.0):** STIX/TAXII feed synchronization, approval-gated SOAR integrations, enterprise SSO/OIDC.

---

## 22. Contributing

Contributions will be welcomed once the initial scaffold is in place:
1. Review [docs/PRD.md](docs/PRD.md) and [docs/SRS.md](docs/SRS.md) before proposing architectural changes.
2. Follow Python typing/linting (`ruff`, `mypy`) and TypeScript strict mode (`eslint`).
3. Include unit/integration tests and ensure security invariants (tenant isolation, HITL guardrails, untrusted-input handling) remain intact.

---

## 23. License

`[LICENSE PLACEHOLDER — e.g., Apache-2.0 or MIT. Add LICENSE file before public release.]`

---

## 24. Contact

`[CONTACT PLACEHOLDER — Maintainer Name / Security Contact Email / Project Repository URL]`
