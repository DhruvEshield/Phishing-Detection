"""Database engine, session factory, and declarative base.

Supports both SQLite (local dev, no install needed) and PostgreSQL (Docker/prod).
Auto-detects from DATABASE_URL:
  sqlite:///./phishdetect.db   →  local dev
  postgresql://...             →  Docker / production

Exposes JsonColumn and UuidColumn shims so models work with both backends.
Alembic owns all DDL for PostgreSQL. SQLite uses create_all() for local dev.
"""
from __future__ import annotations

from typing import Generator

import structlog
from sqlalchemy import JSON, String, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import get_settings

log = structlog.get_logger()

SCHEMA = "phishdetect"

# ── Dialect-agnostic column type shims ───────────────────────────────────────
# Models import these instead of dialect-specific JSONB / UUID.
def _make_json_column():
    """JSONB on Postgres, JSON on SQLite."""
    settings = get_settings()
    if settings.database_url.startswith("postgresql"):
        from sqlalchemy.dialects.postgresql import JSONB
        return JSONB
    return JSON

def _make_uuid_column():
    """UUID on Postgres, String(36) on SQLite."""
    settings = get_settings()
    if settings.database_url.startswith("postgresql"):
        from sqlalchemy.dialects.postgresql import UUID
        return UUID(as_uuid=False)
    return String(36)

JsonColumn = _make_json_column()
UuidColumn = _make_uuid_column()


class Base(DeclarativeBase):
    pass


def _make_engine():
    settings = get_settings()
    url = settings.database_url

    if url.startswith("sqlite"):
        # SQLite: no pool_size, enable WAL for concurrency
        eng = create_engine(url, connect_args={"check_same_thread": False})
        @event.listens_for(eng, "connect")
        def set_sqlite_pragma(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
        return eng

    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine = _make_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
IS_SQLITE = get_settings().database_url.startswith("sqlite")


def init_db() -> None:
    """
    SQLite: create all tables via SQLAlchemy (no Alembic needed).
    PostgreSQL: create schema only — Alembic handles tables.
    """
    if IS_SQLITE:
        # Import all models so Base.metadata knows about them
        import app.models  # noqa: F401
        Base.metadata.create_all(bind=engine)
        log.info("database.sqlite_tables_created")
    else:
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
