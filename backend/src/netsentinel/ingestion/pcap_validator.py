"""PCAP / PCAPNG magic-byte validation, size checks, and SHA-256 hashing."""

from __future__ import annotations

import hashlib

from netsentinel.core.config import get_settings
from netsentinel.core.errors import InvalidPcapError, PayloadTooLargeError

# Standard libpcap (little/big endian, microsecond/nanosecond) and PCAPNG Section Header Block
VALID_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # libpcap little-endian (us)
    b"\xa1\xb2\xc3\xd4",  # libpcap big-endian (us)
    b"\x4d\x3c\xb2\xa1",  # libpcap little-endian (ns)
    b"\xa1\xb2\x3c\x4d",  # libpcap big-endian (ns)
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


def validate_pcap_bytes(data: bytes, filename: str) -> str:
    """Validate extension, size limit, and magic bytes; return SHA-256 hex digest."""
    max_bytes = get_settings().max_pcap_size_mb * 1024 * 1024
    if not data or len(data) < 24:
        raise InvalidPcapError("File is empty or too small to be a valid PCAP/PCAPNG capture")
    if len(data) > max_bytes:
        raise PayloadTooLargeError(
            f"PCAP exceeds maximum allowed size of {get_settings().max_pcap_size_mb} MB"
        )
    lower = filename.lower()
    if not (lower.endswith(".pcap") or lower.endswith(".pcapng")):
        raise InvalidPcapError("File extension must be .pcap or .pcapng")
    if data[:4] not in VALID_PCAP_MAGICS:
        raise InvalidPcapError("Invalid PCAP/PCAPNG magic bytes")
    return hashlib.sha256(data).hexdigest()
