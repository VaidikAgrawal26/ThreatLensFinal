from __future__ import annotations

import logging
import re
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import models
from app.core.config import settings
from app.core.security import hash_password
from app.db import SessionLocal, engine
from app.routes import admin, analytics, auth, incidents, model, research, scans, yara

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("threatlens")


def validate_runtime_configuration() -> None:
    if settings.environment != "production":
        return
    if (settings.jwt_secret == "CHANGE_ME_BEFORE_DEPLOYMENT_TO_A_LONG_RANDOM_SECRET"
            or settings.jwt_secret.startswith("development-only-") or len(settings.jwt_secret) < 32):
        raise RuntimeError("Production requires a unique JWT_SECRET of at least 32 characters")
    if settings.jwt_algorithm != "HS256":
        raise RuntimeError("JWT_ALGORITHM must be HS256; the token implementation supports that algorithm only")
    if settings.database_url.startswith("sqlite") or "localdevpass" in settings.database_url:
        raise RuntimeError("Production requires PostgreSQL; SQLite is reserved for development and tests")
    if not settings.origins or "*" in settings.origins:
        raise RuntimeError("Production CORS_ORIGINS must contain explicit trusted origins")
    if not settings.hosts or "*" in settings.hosts:
        raise RuntimeError("Production TRUSTED_HOSTS must contain explicit hostnames")


def bootstrap_admin() -> None:
    if not settings.bootstrap_admin_email and not settings.bootstrap_admin_password:
        return
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        raise RuntimeError("Set both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD, or neither")
    db: Session = SessionLocal()
    try:
        email = settings.bootstrap_admin_email.strip().lower()
        if not db.query(models.User).filter(models.User.email == email).first():
            admin_user = models.User(
                email=email,
                password_hash=hash_password(settings.bootstrap_admin_password),
                full_name="ThreatLens Administrator",
                role="administrator",
                active=True,
            )
            db.add(admin_user)
            db.commit()
            logger.info("Bootstrapped initial administrator account")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_runtime_configuration()
    bootstrap_admin()
    yield


app = FastAPI(
    title=settings.app_name,
    version="2.1.0",
    description="Static malware triage and scan analytics. Uploaded files are never executed.",
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None if settings.environment == "production" else "/redoc",
    openapi_url=None if settings.environment == "production" else "/openapi.json",
    lifespan=lifespan,
)

if settings.environment == "production":
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


@app.middleware("http")
async def security_and_request_id(request: Request, call_next):
    supplied_id = request.headers.get("X-Request-ID", "")[:80]
    request_id = supplied_id if re.fullmatch(r"[A-Za-z0-9._-]{1,80}", supplied_id) else uuid.uuid4().hex
    try:
        response = await call_next(request)
    except Exception:
        logger.exception("Unhandled API error request_id=%s path=%s", request_id, request.url.path)
        response = JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Frame-Options"] = "DENY"
    return response


for router in (auth.router, admin.router, incidents.router, research.router, scans.router, analytics.router, yara.router, model.router):
    app.include_router(router)


@app.get("/")
def root():
    return {"name": settings.app_name, "health": "/health", "readiness": "/ready"}


@app.get("/health", tags=["Operations"])
def health():
    return {"status": "ok", "service": "threatlens-api"}


@app.get("/ready", tags=["Operations"])
def readiness():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok", "model": "optional"}
    except Exception as exc:
        logger.exception("Readiness probe failed")
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "unavailable", "detail": type(exc).__name__})
