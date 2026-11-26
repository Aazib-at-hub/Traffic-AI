"""Authentication, Argon2id/PBKDF2 password hashing, JWT tokens, and RBAC definitions."""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any

import jwt

from netsentinel.core.config import get_settings
from netsentinel.core.errors import UnauthorizedError

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError

    _ARGON2 = PasswordHasher()
except ImportError:  # pragma: no cover
    _ARGON2 = None
    VerifyMismatchError = Exception  # type: ignore[misc, assignment]


class Role(StrEnum):
    VIEWER = "viewer"
    SOC_ANALYST = "soc_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    ML_ENGINEER = "ml_engineer"
    ORG_ADMIN = "org_admin"
    SUPER_ADMIN = "super_admin"


ALL_ORG_ROLES = {
    Role.VIEWER,
    Role.SOC_ANALYST,
    Role.INCIDENT_RESPONDER,
    Role.ML_ENGINEER,
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
}

ANALYST_AND_ABOVE = {
    Role.SOC_ANALYST,
    Role.INCIDENT_RESPONDER,
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
}

RESPONDER_AND_ABOVE = {
    Role.INCIDENT_RESPONDER,
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
}

ML_ROLES = {
    Role.ML_ENGINEER,
    Role.SOC_ANALYST,
    Role.INCIDENT_RESPONDER,
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
}

ADMIN_ROLES = {
    Role.ORG_ADMIN,
    Role.SUPER_ADMIN,
}


def hash_password(password: str) -> str:
    if _ARGON2 is not None:
        return _ARGON2.hash(password)
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, password_hash: str) -> bool:
    if password_hash.startswith("$argon2") and _ARGON2 is not None:
        try:
            return _ARGON2.verify(password_hash, password)
        except VerifyMismatchError:
            return False
    if password_hash.startswith("pbkdf2_sha256$"):
        _, salt, expected = password_hash.split("$", 2)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000
        )
        return hmac.compare_digest(dk.hex(), expected)
    return False


def create_access_token(
    user_id: str,
    email: str,
    organization_id: str,
    role: str,
    is_super_admin: bool = False,
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "org_id": organization_id,
        "role": role,
        "is_super_admin": is_super_admin,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_access_token_expire_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(user_id: str, organization_id: str) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": user_id,
        "org_id": organization_id,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=settings.jwt_refresh_token_expire_days)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm]
        )
    except jwt.PyJWTError as exc:
        raise UnauthorizedError("Invalid or expired token") from exc
    if payload.get("type") != expected_type:
        raise UnauthorizedError(f"Expected {expected_type} token")
    return payload
