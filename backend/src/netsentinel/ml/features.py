"""Canonical flow feature schema, NaN/Inf sanitization, and attack label taxonomy."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

import numpy as np

FEATURE_COLUMNS: list[str] = [
    "duration_ms",
    "fwd_packets",
    "bwd_packets",
    "bytes_total",
    "pkt_len_mean",
    "pkt_len_std",
    "flow_bytes_per_sec",
    "flow_pkts_per_sec",
    "iat_mean_ms",
    "iat_std_ms",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "fwd_bwd_pkt_ratio",
    "dst_port",
    "dst_port_bucket",
    "protocol_num",
]

CANONICAL_ATTACK_CLASSES: list[str] = [
    "benign",
    "dos_ddos",
    "port_scan",
    "brute_force",
    "web_attack",
    "botnet",
    "infiltration",
    "reconnaissance",
    "other_attack",
]


def feature_schema_hash() -> str:
    payload = json.dumps(FEATURE_COLUMNS, sort_keys=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def normalize_attack_label(raw_label: str) -> str:
    lower = raw_label.strip().lower()
    if lower in ("benign", "normal", "0"):
        return "benign"
    if any(k in lower for k in ("dos", "ddos", "hulk", "goldeneye", "slowloris")):
        return "dos_ddos"
    if "portscan" in lower or "port_scan" in lower or "scan" in lower:
        return "port_scan"
    if any(k in lower for k in ("patator", "brute", "ssh", "ftp")):
        return "brute_force"
    if any(k in lower for k in ("web", "xss", "sql")):
        return "web_attack"
    if "bot" in lower:
        return "botnet"
    if "infiltration" in lower or "backdoor" in lower:
        return "infiltration"
    if "recon" in lower:
        return "reconnaissance"
    return "other_attack"


def extract_feature_matrix(feature_dicts: list[dict[str, Any]]) -> np.ndarray:
    """Convert flow feature dicts into a clean float64 numpy matrix with NaN/Inf sanitized."""
    rows: list[list[float]] = []
    for vec in feature_dicts:
        row: list[float] = []
        for col in FEATURE_COLUMNS:
            raw = vec.get(col, 0.0)
            try:
                val = float(raw)
            except (TypeError, ValueError):
                val = 0.0
            if math.isnan(val) or math.isinf(val):
                val = 0.0
            row.append(val)
        rows.append(row)
    return np.asarray(rows, dtype=np.float64)
