"""Hybrid Security RAG ingestion, RRF fusion, reranking, seeding, and evaluation."""

from __future__ import annotations

import hashlib
import math
import time
from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from netsentinel.db.models import DocumentChunk, SecurityDocument
from netsentinel.rag.chunker import chunk_document
from netsentinel.rag.embeddings import cosine_similarity, embed_texts, rerank_pairs, tokenize

SEED_SECURITY_DOCS: list[dict[str, Any]] = [
    {
        "source_type": "mitre_attack",
        "external_id": "T1046",
        "title": "MITRE ATT&CK T1046 - Network Service Discovery",
        "source_url": "https://attack.mitre.org/techniques/T1046/",
        "content": (
            "## Description\n"
            "Adversaries may attempt to get a listing of services running on remote hosts and local "
            "network infrastructure devices, including those that may be vulnerable to remote software "
            "exploitation. Common indicators include high-rate TCP SYN port scans across sequential or "
            "ephemeral destination ports with minimal backward packets and frequent RST responses.\n"
            "## Mitigation\n"
            "Segment internal networks, restrict unnecessary exposed ports with host firewalls, and "
            "monitor for anomalous SYN/RST ratios from internal hosts."
        ),
        "metadata": {"tactic": "Discovery", "attack_classes": ["port_scan", "reconnaissance"]},
    },
    {
        "source_type": "mitre_attack",
        "external_id": "T1110",
        "title": "MITRE ATT&CK T1110 - Brute Force",
        "source_url": "https://attack.mitre.org/techniques/T1110/",
        "content": (
            "## Description\n"
            "Adversaries may use brute force techniques to gain access to accounts when passwords are "
            "unknown or password hashes are obtained. Network telemetry typically shows repeated short "
            "connections targeting SSH (port 22), FTP (port 21), or RDP (port 3389) with elevated SYN "
            "and RST flag counts.\n"
            "## Mitigation\n"
            "Enforce multi-factor authentication (MFA), disable password-based SSH login in favor of "
            "public keys, implement account lockout policies, and apply connection rate-limiting."
        ),
        "metadata": {"tactic": "Credential Access", "attack_classes": ["brute_force"]},
    },
    {
        "source_type": "mitre_attack",
        "external_id": "T1498",
        "title": "MITRE ATT&CK T1498 - Network Denial of Service",
        "source_url": "https://attack.mitre.org/techniques/T1498/",
        "content": (
            "## Description\n"
            "Adversaries may perform Network Denial of Service (DoS/DDoS) attacks to degrade or block "
            "the availability of targeted resources to users. Volumetric floods exhibit extreme "
            "flow_bytes_per_sec, flow_pkts_per_sec, high SYN counts, and heavily skewed forward-to-backward "
            "packet ratios.\n"
            "## Mitigation\n"
            "Enable SYN cookies, deploy upstream DDoS scrubbing/rate-limiting policies, and configure "
            "egress/ingress traffic shaping."
        ),
        "metadata": {"tactic": "Impact", "attack_classes": ["dos_ddos"]},
    },
    {
        "source_type": "cve",
        "external_id": "CVE-2024-6387",
        "title": "CVE-2024-6387 - OpenSSH Server regreSSHion Signal Handler Race Condition",
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "content": (
            "## Summary\n"
            "A signal handler race condition was found in OpenSSH's server (sshd) on glibc-based Linux "
            "systems affecting TCP port 22. Repeated rapid connection attempts and authentication timeouts "
            "targeting SSH services can be associated with exploitation or brute-force scanning.\n"
            "## Remediation\n"
            "Upgrade OpenSSH to patched versions (9.8p1+), restrict SSH port 22 access via VPN or "
            "bastion allowlists, and set LoginGraceTime=0 as a temporary mitigation if patching is delayed."
        ),
        "metadata": {"cvss": 8.1, "ports": [22]},
    },
    {
        "source_type": "advisory",
        "external_id": "ADV-NS-001",
        "title": "Network Incident Response Playbook - Suspicious Flow Containment",
        "source_url": "internal://playbooks/suspicious-flow-containment",
        "content": (
            "## Advisory Procedure\n"
            "1. Validate ML anomaly and SHAP feature indicators against raw PCAP/flow telemetry before "
            "escalating to containment.\n"
            "2. Correlate source IP with asset inventory and historical incident records.\n"
            "3. Obtain explicit Incident Responder approval before applying firewall ACL blocks, "
            "rate-limits, or VLAN quarantine.\n"
            "4. Preserve raw PCAP and flow hashes for forensic chain-of-custody."
        ),
        "metadata": {"category": "playbook"},
    },
]


def ingest_security_document(
    db: Session,
    *,
    source_type: str,
    external_id: str,
    title: str,
    content: str,
    source_url: str = "",
    organization_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityDocument:
    content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
    existing = (
        db.query(SecurityDocument)
        .filter(
            SecurityDocument.organization_id == organization_id,
            SecurityDocument.source_type == source_type,
            SecurityDocument.external_id == external_id,
        )
        .first()
    )
    if existing is not None and existing.content_sha256 == content_hash:
        return existing

    if existing is not None:
        db.query(DocumentChunk).filter(DocumentChunk.document_id == existing.id).delete()
        doc = existing
        doc.title = title
        doc.source_url = source_url
        doc.content_sha256 = content_hash
        doc.doc_metadata = metadata or {}
    else:
        doc = SecurityDocument(
            organization_id=organization_id,
            source_type=source_type,
            external_id=external_id,
            title=title,
            source_url=source_url,
            content_sha256=content_hash,
            doc_metadata=metadata or {},
        )
        db.add(doc)
    db.flush()

    chunks = chunk_document(content, default_header=title)
    embeddings = embed_texts([f"{c.section_header}\n{c.content}" for c in chunks])
    for spec, emb in zip(chunks, embeddings):
        db.add(
            DocumentChunk(
                document_id=doc.id,
                organization_id=organization_id,
                chunk_index=spec.chunk_index,
                section_header=spec.section_header,
                content=spec.content,
                token_count=spec.token_count,
                embedding=emb,
                chunk_metadata={
                    "external_id": external_id,
                    "source_type": source_type,
                    "title": title,
                    **(metadata or {}),
                },
            )
        )
    db.commit()
    db.refresh(doc)
    return doc


def seed_default_security_knowledge(db: Session) -> int:
    count = 0
    for item in SEED_SECURITY_DOCS:
        ingest_security_document(
            db,
            source_type=item["source_type"],
            external_id=item["external_id"],
            title=item["title"],
            content=item["content"],
            source_url=item["source_url"],
            organization_id=None,
            metadata=item["metadata"],
        )
        count += 1
    return count


def reciprocal_rank_fusion(
    dense_ranks: dict[str, int],
    lexical_ranks: dict[str, int],
    k: int = 60,
) -> dict[str, float]:
    all_ids = set(dense_ranks.keys()) | set(lexical_ranks.keys())
    fused: dict[str, float] = {}
    for cid in all_ids:
        score = 0.0
        if cid in dense_ranks:
            score += 1.0 / (k + dense_ranks[cid])
        if cid in lexical_ranks:
            score += 1.0 / (k + lexical_ranks[cid])
        fused[cid] = round(score, 6)
    return fused


def hybrid_search(
    db: Session,
    *,
    query: str,
    organization_id: str | None = None,
    source_types: list[str] | None = None,
    top_k: int = 5,
    use_reranker: bool = True,
) -> dict[str, Any]:
    start = time.perf_counter()
    q_db = (
        db.query(DocumentChunk, SecurityDocument)
        .join(SecurityDocument, DocumentChunk.document_id == SecurityDocument.id)
        .filter(
            or_(
                DocumentChunk.organization_id.is_(None),
                DocumentChunk.organization_id == organization_id,
            )
        )
    )
    if source_types:
        q_db = q_db.filter(SecurityDocument.source_type.in_(source_types))

    rows = q_db.all()
    if not rows:
        return {"query": query, "results": [], "latency_ms": 0}

    q_emb = embed_texts([query])[0]
    q_tokens = set(tokenize(query))

    dense_scored: list[tuple[str, float]] = []
    lex_scored: list[tuple[str, float]] = []
    lookup: dict[str, tuple[DocumentChunk, SecurityDocument]] = {}

    for chunk, doc in rows:
        lookup[chunk.id] = (chunk, doc)
        d_sim = cosine_similarity(q_emb, chunk.embedding or [])
        dense_scored.append((chunk.id, d_sim))

        text_tokens = tokenize(f"{doc.external_id} {doc.title} {chunk.section_header} {chunk.content}")
        if text_tokens and q_tokens:
            tf = sum(1 for t in text_tokens if t in q_tokens)
            lex = tf / math.sqrt(len(text_tokens))
            if doc.external_id.lower() in q_tokens:
                lex += 2.0
        else:
            lex = 0.0
        lex_scored.append((chunk.id, lex))

    dense_scored.sort(key=lambda x: x[1], reverse=True)
    lex_scored.sort(key=lambda x: x[1], reverse=True)

    dense_ranks = {cid: rank + 1 for rank, (cid, _) in enumerate(dense_scored[:30])}
    lexical_ranks = {cid: rank + 1 for rank, (cid, sc) in enumerate(lex_scored[:30]) if sc > 0}

    rrf_scores = reciprocal_rank_fusion(dense_ranks, lexical_ranks, k=60)
    candidates = sorted(rrf_scores.items(), key=lambda x: x[1], reverse=True)[:20]

    cand_ids = [cid for cid, _ in candidates]
    passages = [
        f"{lookup[cid][1].title} | {lookup[cid][0].section_header}\n{lookup[cid][0].content}"
        for cid in cand_ids
    ]
    rerank_scores = rerank_pairs(query, passages) if use_reranker else [s for _, s in candidates]

    combined = []
    for cid, rrf_s, rr_s in zip(cand_ids, [s for _, s in candidates], rerank_scores):
        chunk, doc = lookup[cid]
        combined.append(
            {
                "chunk_id": chunk.id,
                "document_id": doc.id,
                "title": doc.title,
                "source_type": doc.source_type,
                "external_id": doc.external_id,
                "section_header": chunk.section_header,
                "content": chunk.content,
                "rrf_score": rrf_s,
                "rerank_score": rr_s,
            }
        )

    combined.sort(key=lambda item: (item["rerank_score"], item["rrf_score"]), reverse=True)
    latency_ms = int((time.perf_counter() - start) * 1000)
    return {"query": query, "results": combined[:top_k], "latency_ms": latency_ms}


def evaluate_retrieval(
    db: Session,
    benchmark: list[dict[str, Any]],
    *,
    top_k: int = 5,
) -> dict[str, float]:
    """Compute Recall@K, MRR@K, and NDCG@K over a labeled security QA benchmark."""
    recalls: list[float] = []
    mrrs: list[float] = []
    ndcgs: list[float] = []

    for item in benchmark:
        expected = set(item["expected_external_ids"])
        res = hybrid_search(db, query=item["query"], top_k=top_k, use_reranker=True)["results"]
        retrieved = [r["external_id"] for r in res]

        hits = [1 if ext in expected else 0 for ext in retrieved]
        recalls.append(len(set(retrieved) & expected) / max(len(expected), 1))

        rr = 0.0
        for idx, h in enumerate(hits):
            if h:
                rr = 1.0 / (idx + 1)
                break
        mrrs.append(rr)

        dcg = sum(h / math.log2(idx + 2) for idx, h in enumerate(hits))
        ideal_hits = [1] * min(len(expected), top_k)
        idcg = sum(h / math.log2(idx + 2) for idx, h in enumerate(ideal_hits)) or 1.0
        ndcgs.append(dcg / idcg)

    n = max(len(benchmark), 1)
    return {
        f"recall@{top_k}": round(sum(recalls) / n, 4),
        f"mrr@{top_k}": round(sum(mrrs) / n, 4),
        f"ndcg@{top_k}": round(sum(ndcgs) / n, 4),
    }
