"""Database engine, session factory, and declarative base.

PostgreSQL only. Alembic owns ALL DDL — application code never creates tables.
This is the single source of truth for the schema, in dev, CI, and production alike
(see foundation_plan.md, Phase 1).

Exposes JsonColumn (JSONB) and UuidColumn (UUID) so models read cleanly without
importing dialect-specific types everywhere.
"""
from __future__ import annotations

from typing import Generator

import structlog
from sqlalchemy import create_engine, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

log = structlog.get_logger()

SCHEMA = "phishdetect"

# ── Column types ──────────────────────────────────────────────────────────────
# Models import these instead of dialect-specific names.
JsonColumn = JSONB
UuidColumn = UUID(as_uuid=False)


class Base(DeclarativeBase):
    pass


def _make_engine():
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine = _make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Ensure the schema namespace exists.

    Tables are owned exclusively by Alembic (the one-shot `migrate` service runs
    `alembic upgrade head` before the API starts). This is an idempotent safety
    net so the app fails fast with a clear log if it cannot reach the database.
    """
    with engine.connect() as conn:
        conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}"))
        conn.commit()
    log.info("database.schema_ready", schema=SCHEMA)


def get_db() -> Generator:
    """FastAPI dependency — yields a session and closes it on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
