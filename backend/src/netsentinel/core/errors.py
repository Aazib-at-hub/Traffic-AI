"""Standardized domain exceptions and FastAPI error envelope handlers."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class NetSentinelError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []


class UnauthorizedError(NetSentinelError):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__("UNAUTHORIZED", message, status_code=401)


class ForbiddenError(NetSentinelError):
    def __init__(self, message: str = "Insufficient permissions") -> None:
        super().__init__("FORBIDDEN", message, status_code=403)


class NotFoundError(NetSentinelError):
    def __init__(self, resource: str = "Resource") -> None:
        super().__init__("NOT_FOUND", f"{resource} not found", status_code=404)


class ConflictError(NetSentinelError):
    def __init__(self, message: str) -> None:
        super().__init__("CONFLICT", message, status_code=409)


class InvalidPcapError(NetSentinelError):
    def __init__(self, message: str) -> None:
        super().__init__("INVALID_PCAP", message, status_code=400)


class PayloadTooLargeError(NetSentinelError):
    def __init__(self, message: str) -> None:
        super().__init__("PAYLOAD_TOO_LARGE", message, status_code=413)


def _envelope(
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or [],
            "request_id": request_id or f"req_{uuid.uuid4().hex[:12]}",
        }
    }


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(NetSentinelError)
    async def handle_domain_error(request: Request, exc: NetSentinelError) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None)
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(exc.code, exc.message, exc.details, req_id),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        req_id = getattr(request.state, "request_id", None)
        details = [
            {"field": ".".join(str(x) for x in err["loc"]), "issue": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_envelope("VALIDATION_ERROR", "Request validation failed", details, req_id),
        )
