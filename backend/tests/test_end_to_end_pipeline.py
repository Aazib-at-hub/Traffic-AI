"""End-to-end API integration tests: Auth, Tenant Isolation, PCAP, ML/SHAP, LangGraph Agents, HITL, Reports."""

from __future__ import annotations

import socket
import struct


def _build_minimal_pcap_bytes(packet_count: int = 120, dst_port: int = 22) -> bytes:
    """Synthesize a valid libpcap Ethernet/IPv4/TCP capture simulating a high-rate SSH SYN/RST burst."""
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    chunks = [header]
    src_ip = socket.inet_aton("10.10.0.55")
    dst_ip = socket.inet_aton("192.168.1.10")

    for i in range(packet_count):
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        tcp_flags = 0x02 if i % 2 == 0 else 0x04  # SYN / RST burst
        tcp = struct.pack("!HHIIBBHHH", 44000, dst_port, i + 1, 0, 0x50, tcp_flags, 1024, 0, 0)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp),
            i + 1,
            0,
            64,
            6,
            0,
            src_ip,
            dst_ip,
        )
        frame = eth + ip + tcp
        pkt_hdr = struct.pack("<IIII", 1732660000, 2000 * i, len(frame), len(frame))
        chunks.append(pkt_hdr + frame)
    return b"".join(chunks)


def _register_and_login(client, email: str, org: str) -> dict[str, str]:
    reg = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword!2026",
            "full_name": "Test Analyst",
            "organization_name": org,
        },
    )
    assert reg.status_code == 201, reg.text
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword!2026"},
    )
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_full_soc_workflow_and_tenant_isolation(client):
    headers_org1 = _register_and_login(client, "lead@org1.example.com", "Org One SOC")
    headers_org2 = _register_and_login(client, "lead@org2.example.com", "Org Two SOC")

    # 1. Invalid PCAP rejected
    bad = client.post(
        "/api/v1/datasets/upload",
        headers=headers_org1,
        files={"file": ("bad.pcap", b"not-a-pcap-file-at-all-1234567890", "application/octet-stream")},
        data={"name": "Bad Upload"},
    )
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == "INVALID_PCAP"

    # 2. Valid PCAP upload
    pcap_bytes = _build_minimal_pcap_bytes(packet_count=120, dst_port=22)
    up = client.post(
        "/api/v1/datasets/upload",
        headers=headers_org1,
        files={"file": ("ssh_burst.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        data={"name": "SSH Burst Capture"},
    )
    assert up.status_code == 201, up.text
    dataset_id = up.json()["dataset_id"]

    # 3. Tenant isolation check: Org 2 cannot read Org 1's dataset status
    cross = client.get(f"/api/v1/datasets/{dataset_id}/status", headers=headers_org2)
    assert cross.status_code == 404

    # 4. Process PCAP & run ML detection + SHAP
    proc = client.post(
        f"/api/v1/datasets/{dataset_id}/process",
        headers=headers_org1,
        json={"auto_run_detection": True},
    )
    assert proc.status_code == 202, proc.text
    assert proc.json()["flow_count"] >= 1

    flows_resp = client.get(f"/api/v1/datasets/{dataset_id}/flows", headers=headers_org1)
    assert flows_resp.status_code == 200
    assert flows_resp.json()["total"] >= 1

    # 5. Alerts & SHAP explanation
    alerts_resp = client.get("/api/v1/alerts", headers=headers_org1)
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()["items"]
    assert len(alerts) >= 1
    first_alert = alerts[0]
    assert first_alert["classification_tier"] in ("anomalous", "suspicious")

    shap_resp = client.get(
        f"/api/v1/detections/{first_alert['detection_result_id']}/explain",
        headers=headers_org1,
    )
    assert shap_resp.status_code == 200
    assert len(shap_resp.json()["shap_features"]) >= 1

    # 6. Escalate to Incident -> Run 5-Agent LangGraph Investigation
    inc = client.post(
        "/api/v1/incidents",
        headers=headers_org1,
        json={
            "title": "Suspected SSH Brute Force Burst",
            "severity": "high",
            "alert_ids": [first_alert["alert_id"]],
        },
    )
    assert inc.status_code == 201
    incident_id = inc.json()["incident_id"]

    inv_trigger = client.post(
        f"/api/v1/incidents/{incident_id}/investigations",
        headers=headers_org1,
    )
    assert inv_trigger.status_code == 202, inv_trigger.text
    inv_id = inv_trigger.json()["investigation_id"]

    inv_detail = client.get(f"/api/v1/investigations/{inv_id}", headers=headers_org1).json()
    assert inv_detail["validation_status"] == "verified"
    assert len(inv_detail["agent_runs"]) == 5
    assert len(inv_detail["evidence_items"]) >= 1
    assert all(e["validation_verdict"] == "supported" for e in inv_detail["evidence_items"])
    assert len(inv_detail["recommendations"]) >= 1
    assert all(r["approval_status"] == "pending_approval" for r in inv_detail["recommendations"])

    # 7. Human-in-the-Loop Recommendation Approval
    rec_id = inv_detail["recommendations"][0]["id"]
    appr = client.post(
        f"/api/v1/investigations/{inv_id}/recommendations/{rec_id}/approve",
        headers=headers_org1,
        json={"decision": "approved", "rationale": "Verified host logs; approved."},
    )
    assert appr.status_code == 200
    assert appr.json()["approval_status"] == "approved"

    # 8. Hybrid Threat Intel Search
    rag = client.post(
        "/api/v1/threat-intel/search",
        headers=headers_org1,
        json={"query": "T1110 SSH brute force CVE-2024-6387", "top_k": 3},
    )
    assert rag.status_code == 200
    assert len(rag.json()["results"]) >= 1

    # 9. Incident Report Generation & Audit Logs
    rep = client.post(
        f"/api/v1/incidents/{incident_id}/reports",
        headers=headers_org1,
        json={"format": "markdown", "anonymize_ips": True},
    )
    assert rep.status_code == 201
    assert "anon-ip-" in rep.json()["content_preview"]

    logs = client.get("/api/v1/audit-logs", headers=headers_org1)
    assert logs.status_code == 200
    assert len(logs.json()["items"]) >= 5
