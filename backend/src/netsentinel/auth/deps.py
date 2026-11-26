"""FastAPI authentication, tenant-scoping, and RBAC dependencies."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from netsentinel.core.errors import ForbiddenError, UnauthorizedError
from netsentinel.core.security import Role, decode_token
from netsentinel.db.models import OrganizationMember, User
from netsentinel.db.session import get_db

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    email: str
    organization_id: str
    role: Role
    is_super_admin: bool


def get_current_auth(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthContext:
    if credentials is None or not credentials.credentials:
        raise UnauthorizedError("Missing Bearer token")
    payload = decode_token(credentials.credentials, expected_type="access")
    user_id = str(payload["sub"])
    org_id = str(payload["org_id"])
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise UnauthorizedError("User account inactive or not found")

    if user.is_super_admin:
        return AuthContext(
            user_id=user.id,
            email=user.email,
            organization_id=org_id,
            role=Role.SUPER_ADMIN,
            is_super_admin=True,
        )

    membership = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.user_id == user.id,
            OrganizationMember.organization_id == org_id,
        )
        .first()
    )
    if membership is None:
        raise ForbiddenError("User does not belong to target organization")

    return AuthContext(
        user_id=user.id,
        email=user.email,
        organization_id=org_id,
        role=Role(membership.role),
        is_super_admin=False,
    )


def require_roles(allowed: set[Role]):
    def _checker(ctx: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if ctx.is_super_admin or ctx.role in allowed:
            return ctx
        raise ForbiddenError(f"Role '{ctx.role}' is not authorized for this action")

    return _checker
