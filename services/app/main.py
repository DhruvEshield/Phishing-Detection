"""FastAPI application entry point.

Fat Service, Thin Controller: all business logic lives in app/services/.
Routes parse request → call service → shape response.
"""
from __future__ import annotations

import structlog
import structlog.stdlib
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.database import init_db
from app.scoring.config import ScoringConfig
from app.api import ingest, queue, verdicts, reports

# ── Structured logging setup ──────────────────────────────────────────────────
settings = get_settings()
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.PrintLoggerFactory(),
)
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: validate invariants and initialise DB schema."""
    log.info("startup.begin", version=settings.model_version)

    # Enforce scoring invariant at startup — fail fast if misconfigured
    ScoringConfig.from_settings(settings).validate_invariant()
    log.info("startup.invariant_ok")

    init_db()
    log.info("startup.db_ready")

    yield

    log.info("shutdown.complete")


app = FastAPI(
    title="PhishDetect API",
    description="AI-assisted phishing detection — Phase 1",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(ingest.router, prefix="/api/v1", tags=["ingest"])
app.include_router(queue.router, prefix="/api/v1", tags=["queue"])
app.include_router(verdicts.router, prefix="/api/v1", tags=["verdicts"])
app.include_router(reports.router, prefix="/api/v1", tags=["reports"])


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok", "version": settings.model_version}
