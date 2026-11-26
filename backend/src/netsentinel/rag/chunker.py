"""Structure-aware markdown/text chunker preserving section headers and security identifiers."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEADING_RE = re.compile(r"^(#{1,4})\s+(.+)$")


@dataclass
class ChunkSpec:
    chunk_index: int
    section_header: str
    content: str
    token_count: int


def chunk_document(
    text: str,
    *,
    default_header: str = "Overview",
    max_words: int = 220,
    overlap_words: int = 35,
) -> list[ChunkSpec]:
    """Split text along markdown headings first, then sliding word windows with overlap."""
    sections: list[tuple[str, list[str]]] = []
    current_header = default_header
    current_lines: list[str] = []

    for line in text.splitlines():
        match = _HEADING_RE.match(line.strip())
        if match:
            if current_lines:
                sections.append((current_header, current_lines))
            current_header = match.group(2).strip()[:250]
            current_lines = []
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_header, current_lines))

    chunks: list[ChunkSpec] = []
    idx = 0
    for header, lines in sections:
        body = "\n".join(lines).strip()
        if not body:
            continue
        words = body.split()
        if len(words) <= max_words:
            chunks.append(
                ChunkSpec(
                    chunk_index=idx,
                    section_header=header,
                    content=body,
                    token_count=len(words),
                )
            )
            idx += 1
        else:
            step = max(max_words - overlap_words, 1)
            for start in range(0, len(words), step):
                window = words[start : start + max_words]
                if not window:
                    break
                chunks.append(
                    ChunkSpec(
                        chunk_index=idx,
                        section_header=header,
                        content=" ".join(window),
                        token_count=len(window),
                    )
                )
                idx += 1
                if start + max_words >= len(words):
                    break
    return chunks
