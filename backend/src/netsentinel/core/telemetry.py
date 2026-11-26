"""Structured JSON logging, OpenTelemetry instrumentation, and Langfuse trace helper."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from netsentinel.core.config import get_settings

logger = logging.getLogger("netsentinel")


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
    )


def init_opentelemetry(app: Any) -> None:
    settings = get_settings()
    if not settings.otel_exporter_otlp_endpoint:
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
        logger.info("OpenTelemetry FastAPI instrumentation enabled")
    except ImportError:
        logger.warning("OpenTelemetry packages not installed; skipping OTel setup")


def create_langfuse_trace_id(investigation_id: str) -> str:
    """Return a trace ID (integrates with Langfuse SDK when configured)."""
    settings = get_settings()
    trace_id = f"lf_{investigation_id[:8]}_{uuid.uuid4().hex[:10]}"
    if settings.langfuse_public_key and settings.langfuse_secret_key:
        try:
            from langfuse import Langfuse

            client = Langfuse(
                host=settings.langfuse_host or None,
                public_key=settings.langfuse_public_key,
                secret_key=settings.langfuse_secret_key,
            )
            trace = client.trace(id=trace_id, name="netsentinel_investigation")
            return str(trace.id)
        except Exception as exc:  # pragma: no cover
            logger.warning("Langfuse trace init failed: %s", exc)
    return trace_id
