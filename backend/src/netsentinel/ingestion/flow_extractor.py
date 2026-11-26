"""Bidirectional 5-tuple network flow extractor with Scapy and pure-Python libpcap fallback."""

from __future__ import annotations

import io
import math
import socket
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class _FlowAccumulator:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0
    pkt_lengths: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)
    tcp_flags: dict[str, int] = field(
        default_factory=lambda: {"SYN": 0, "ACK": 0, "FIN": 0, "RST": 0, "PSH": 0, "URG": 0}
    )


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(var)


def _extract_packets_pure_pcap(data: bytes) -> list[tuple[float, str, str, int, int, str, int, int]]:
    """Pure-Python libpcap Ethernet/IPv4 TCP/UDP parser (fallback when Scapy unavailable)."""
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    is_ns = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    pos = 24
    packets: list[tuple[float, str, str, int, int, str, int, int]] = []

    while pos + 16 <= len(data):
        ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[pos : pos + 16])
        pos += 16
        if pos + incl_len > len(data):
            break
        raw = data[pos : pos + incl_len]
        pos += incl_len
        ts = ts_sec + (ts_sub / 1e9 if is_ns else ts_sub / 1e6)

        if len(raw) < 34:
            continue
        eth_type = struct.unpack("!H", raw[12:14])[0]
        if eth_type != 0x0800:
            continue
        ihl = (raw[14] & 0x0F) * 4
        if len(raw) < 14 + ihl:
            continue
        proto_num = raw[23]
        src_ip = socket.inet_ntoa(raw[26:30])
        dst_ip = socket.inet_ntoa(raw[30:34])
        l4 = raw[14 + ihl :]

        src_port, dst_port, flags = 0, 0, 0
        if proto_num == 6 and len(l4) >= 14:
            proto = "TCP"
            src_port, dst_port = struct.unpack("!HH", l4[:4])
            flags = l4[13]
        elif proto_num == 17 and len(l4) >= 8:
            proto = "UDP"
            src_port, dst_port = struct.unpack("!HH", l4[:4])
        elif proto_num == 1:
            proto = "ICMP"
        else:
            proto = str(proto_num)

        packets.append((ts, src_ip, dst_ip, src_port, dst_port, proto, orig_len, flags))
    return packets


def _extract_packets_scapy(data: bytes) -> list[tuple[float, str, str, int, int, str, int, int]]:
    from scapy.all import ICMP, IP, TCP, UDP, rdpcap  # type: ignore[import-untyped]

    pkts = rdpcap(io.BytesIO(data))
    out: list[tuple[float, str, str, int, int, str, int, int]] = []
    for pkt in pkts:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        ts = float(pkt.time)
        src_ip, dst_ip = str(ip.src), str(ip.dst)
        src_port, dst_port, flags = 0, 0, 0
        if TCP in pkt:
            proto = "TCP"
            src_port, dst_port = int(pkt[TCP].sport), int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port, dst_port = int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            proto = str(ip.proto)
        out.append((ts, src_ip, dst_ip, src_port, dst_port, proto, len(pkt), flags))
    return out


def extract_flows_from_pcap(data: bytes, flow_timeout_seconds: int = 120) -> tuple[int, list[dict[str, Any]]]:
    """Parse PCAP bytes and aggregate into bidirectional flow dicts with ML feature vectors."""
    packets: list[tuple[float, str, str, int, int, str, int, int]]
    try:
        packets = _extract_packets_scapy(data)
    except Exception:
        packets = _extract_packets_pure_pcap(data)

    flows: dict[tuple[str, str, int, int, str], _FlowAccumulator] = {}
    for ts, src_ip, dst_ip, src_port, dst_port, proto, pkt_len, tcp_flags in packets:
        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

        if fwd_key in flows and (ts - flows[fwd_key].end_ts) <= flow_timeout_seconds:
            acc = flows[fwd_key]
            is_fwd = True
        elif rev_key in flows and (ts - flows[rev_key].end_ts) <= flow_timeout_seconds:
            acc = flows[rev_key]
            is_fwd = False
        else:
            acc = _FlowAccumulator(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                start_ts=ts,
                end_ts=ts,
            )
            flows[fwd_key] = acc
            is_fwd = True

        acc.end_ts = max(acc.end_ts, ts)
        acc.start_ts = min(acc.start_ts, ts)
        if is_fwd:
            acc.fwd_packets += 1
            acc.fwd_bytes += pkt_len
        else:
            acc.bwd_packets += 1
            acc.bwd_bytes += pkt_len
        acc.pkt_lengths.append(pkt_len)
        acc.timestamps.append(ts)

        if proto == "TCP":
            if tcp_flags & 0x02:
                acc.tcp_flags["SYN"] += 1
            if tcp_flags & 0x10:
                acc.tcp_flags["ACK"] += 1
            if tcp_flags & 0x01:
                acc.tcp_flags["FIN"] += 1
            if tcp_flags & 0x04:
                acc.tcp_flags["RST"] += 1
            if tcp_flags & 0x08:
                acc.tcp_flags["PSH"] += 1
            if tcp_flags & 0x20:
                acc.tcp_flags["URG"] += 1

    records: list[dict[str, Any]] = []
    for acc in flows.values():
        duration_sec = max(acc.end_ts - acc.start_ts, 1e-6)
        duration_ms = round((acc.end_ts - acc.start_ts) * 1000.0, 3)
        total_packets = acc.fwd_packets + acc.bwd_packets
        bytes_total = acc.fwd_bytes + acc.bwd_bytes
        pkt_mean = sum(acc.pkt_lengths) / max(len(acc.pkt_lengths), 1)
        pkt_std = _std([float(x) for x in acc.pkt_lengths])
        sorted_ts = sorted(acc.timestamps)
        iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]
        iat_mean = (sum(iats) / len(iats)) * 1000.0 if iats else 0.0
        iat_std = _std([x * 1000.0 for x in iats]) if iats else 0.0

        port_bucket = 0.0 if acc.dst_port < 1024 else (1.0 if acc.dst_port < 49152 else 2.0)
        proto_num = 6.0 if acc.protocol == "TCP" else (17.0 if acc.protocol == "UDP" else 1.0)

        feature_vector = {
            "duration_ms": float(duration_ms),
            "fwd_packets": float(acc.fwd_packets),
            "bwd_packets": float(acc.bwd_packets),
            "bytes_total": float(bytes_total),
            "pkt_len_mean": round(float(pkt_mean), 4),
            "pkt_len_std": round(float(pkt_std), 4),
            "flow_bytes_per_sec": round(float(bytes_total / duration_sec), 4),
            "flow_pkts_per_sec": round(float(total_packets / duration_sec), 4),
            "iat_mean_ms": round(float(iat_mean), 4),
            "iat_std_ms": round(float(iat_std), 4),
            "syn_flag_count": float(acc.tcp_flags["SYN"]),
            "ack_flag_count": float(acc.tcp_flags["ACK"]),
            "fin_flag_count": float(acc.tcp_flags["FIN"]),
            "rst_flag_count": float(acc.tcp_flags["RST"]),
            "psh_flag_count": float(acc.tcp_flags["PSH"]),
            "fwd_bwd_pkt_ratio": round(float(acc.fwd_packets / max(acc.bwd_packets, 1)), 4),
            "dst_port": float(acc.dst_port),
            "dst_port_bucket": port_bucket,
            "protocol_num": proto_num,
        }

        records.append(
            {
                "src_ip": acc.src_ip,
                "dst_ip": acc.dst_ip,
                "src_port": acc.src_port,
                "dst_port": acc.dst_port,
                "protocol": acc.protocol,
                "start_time": datetime.fromtimestamp(acc.start_ts, tz=timezone.utc),
                "end_time": datetime.fromtimestamp(acc.end_ts, tz=timezone.utc),
                "duration_ms": duration_ms,
                "fwd_packets": acc.fwd_packets,
                "bwd_packets": acc.bwd_packets,
                "bytes_total": bytes_total,
                "tcp_flags": acc.tcp_flags,
                "feature_vector": feature_vector,
            }
        )

    return len(packets), records
