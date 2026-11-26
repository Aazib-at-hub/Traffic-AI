"""FastAPI application entrypoint for NetSentinel AI."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from netsentinel.api.auth_routes import router as auth_router
from netsentinel.api.dataset_routes import router as dataset_router
from netsentinel.api.soc_routes import router as soc_router
from netsentinel.core.config import get_settings
from netsentinel.core.errors import register_exception_handlers
from netsentinel.core.security import hash_password
from netsentinel.core.telemetry import configure_logging, init_opentelemetry
from netsentinel.db.models import Organization, OrganizationMember, User
from netsentinel.db.session import SessionLocal, init_db
from netsentinel.rag.retriever import seed_default_security_knowledge


def _bootstrap_dev_data() -> None:
    """Create default dev organization, admin user, and seed RAG docs if DB is empty."""
    with SessionLocal() as db:
        if db.query(Organization).count() == 0:
            org = Organization(name="NetSentinel SOC", slug="netsentinel-soc")
            admin = User(
                email="admin@netsentinel.io",
                password_hash=hash_password("NetSentinel!2026"),
                full_name="SOC Administrator",
                is_super_admin=False,
            )
            db.add_all([org, admin])
            db.flush()
            db.add(OrganizationMember(organization_id=org.id, user_id=admin.id, role="org_admin"))
            db.commit()
        seed_default_security_knowledge(db)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    configure_logging()
    init_db()
    if get_settings().app_env == "development":
        _bootstrap_dev_data()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Intelligent Network Threat Detection and Autonomous Security Investigation Platform",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):
        request.state.request_id = request.headers.get("X-Request-ID") or f"req_{uuid.uuid4().hex[:12]}"
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    register_exception_handlers(app)
    init_opentelemetry(app)

    app.include_router(auth_router, prefix=settings.api_prefix)
    app.include_router(dataset_router, prefix=settings.api_prefix)
    app.include_router(soc_router, prefix=settings.api_prefix)

    @app.get("/health/live", tags=["Health"])
    def health_live():
        return {"status": "ok"}

    @app.get("/health/ready", tags=["Health"])
    def health_ready():
        return {"status": "ready", "env": settings.app_env}

    return app


app = create_app()
