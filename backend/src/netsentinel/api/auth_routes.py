"""Authentication and organization membership endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from netsentinel.auth.deps import AuthContext, get_current_auth
from netsentinel.core.config import get_settings
from netsentinel.core.errors import ConflictError, UnauthorizedError
from netsentinel.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from netsentinel.db.audit import record_audit
from netsentinel.db.models import Organization, OrganizationMember, User
from netsentinel.db.session import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=1, max_length=120)
    organization_name: str = Field(min_length=2, max_length=120)


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email.lower()).first():
        raise ConflictError("Email already registered")

    slug = payload.organization_name.lower().replace(" ", "-")[:70]
    if db.query(Organization).filter(Organization.slug == slug).first():
        slug = f"{slug}-{int(datetime.now(timezone.utc).timestamp())}"

    org = Organization(name=payload.organization_name, slug=slug)
    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add_all([org, user])
    db.flush()

    member = OrganizationMember(organization_id=org.id, user_id=user.id, role="org_admin")
    db.add(member)
    record_audit(
        db,
        action="auth.registered",
        resource_type="user",
        organization_id=org.id,
        actor_user_id=user.id,
        resource_id=user.id,
    )
    db.commit()

    return {
        "user_id": user.id,
        "email": user.email,
        "organization_id": org.id,
        "role": member.role,
    }


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if user is None or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise UnauthorizedError("Invalid email or password")

    membership = (
        db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
    )
    if membership is None:
        raise UnauthorizedError("User has no active organization membership")

    user.last_login_at = datetime.now(timezone.utc)
    record_audit(
        db,
        action="auth.login",
        resource_type="user",
        organization_id=membership.organization_id,
        actor_user_id=user.id,
        resource_id=user.id,
    )
    db.commit()

    settings = get_settings()
    return {
        "access_token": create_access_token(
            user.id, user.email, membership.organization_id, membership.role, user.is_super_admin
        ),
        "refresh_token": create_refresh_token(user.id, membership.organization_id),
        "token_type": "bearer",
        "expires_in": settings.jwt_access_token_expire_minutes * 60,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "active_organization_id": membership.organization_id,
            "role": membership.role,
        },
    }


@router.post("/refresh")
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)):
    data = decode_token(payload.refresh_token, expected_type="refresh")
    user = db.get(User, str(data["sub"]))
    if user is None or not user.is_active:
        raise UnauthorizedError("User not found")
    membership = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.user_id == user.id,
            OrganizationMember.organization_id == str(data["org_id"]),
        )
        .first()
    )
    if membership is None:
        raise UnauthorizedError("Organization membership not found")

    settings = get_settings()
    return {
        "access_token": create_access_token(
            user.id, user.email, membership.organization_id, membership.role, user.is_super_admin
        ),
        "token_type": "bearer",
        "expires_in": settings.jwt_access_token_expire_minutes * 60,
    }


@router.get("/me")
def me(ctx: AuthContext = Depends(get_current_auth), db: Session = Depends(get_db)):
    user = db.get(User, ctx.user_id)
    org = db.get(Organization, ctx.organization_id)
    return {
        "id": ctx.user_id,
        "email": ctx.email,
        "full_name": user.full_name if user else "",
        "active_organization_id": ctx.organization_id,
        "organization_name": org.name if org else "",
        "role": ctx.role.value,
    }
