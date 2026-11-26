"""CLI entrypoint for ingesting security documents and evaluating hybrid RAG retrieval."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netsentinel.db.session import SessionLocal, init_db
from netsentinel.rag.retriever import (
    evaluate_retrieval,
    ingest_security_document,
    seed_default_security_knowledge,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSentinel AI Security RAG Ingestion & Eval CLI")
    parser.add_argument("--seed", action="store_true", help="Seed built-in MITRE ATT&CK / CVE docs")
    parser.add_argument("--source-type", default="internal_kb")
    parser.add_argument("--external-id", default="")
    parser.add_argument("--title", default="")
    parser.add_argument("--input", help="Path to Markdown/Text/JSON file to ingest")
    parser.add_argument("--eval", action="store_true", help="Run retrieval evaluation benchmark")
    args = parser.parse_args()

    init_db()
    with SessionLocal() as db:
        if args.seed:
            n = seed_default_security_knowledge(db)
            print(f"Seeded {n} security documents.")
        if args.input:
            path = Path(args.input)
            content = path.read_text(encoding="utf-8")
            doc = ingest_security_document(
                db,
                source_type=args.source_type,
                external_id=args.external_id or path.stem,
                title=args.title or path.stem,
                content=content,
            )
            print(f"Ingested document {doc.id} ({doc.external_id})")
        if args.eval:
            benchmark = [
                {"query": "T1046 TCP SYN port scan sequential ports", "expected_external_ids": ["T1046"]},
                {"query": "SSH brute force T1110 port 22 authentication", "expected_external_ids": ["T1110", "CVE-2024-6387"]},
                {"query": "DDoS volumetric SYN flood flow_bytes_per_sec", "expected_external_ids": ["T1498"]},
                {"query": "CVE-2024-6387 OpenSSH regreSSHion", "expected_external_ids": ["CVE-2024-6387"]},
            ]
            metrics = evaluate_retrieval(db, benchmark, top_k=5)
            print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
