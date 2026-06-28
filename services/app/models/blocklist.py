"""BlocklistEntry, FeedbackEvent, AuditLog ORM models."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, SCHEMA, JsonColumn, UuidColumn


class BlocklistEntry(Base):
    __tablename__ = "blocklist_entries"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    indicator: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="internal")
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FeedbackEvent(Base):
    """Feedback loop contract (Layer 1 → future Layer 2). consumed_at=None = pending."""
    __tablename__ = "feedback_events"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    verdict_id: Mapped[str | None] = mapped_column(
        ForeignKey(f"{SCHEMA}.verdicts.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst_verdict")
    payload_json: Mapped[dict] = mapped_column(JsonColumn, nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    actor: Mapped[str] = mapped_column(String(256), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    detail_json: Mapped[dict] = mapped_column(JsonColumn, nullable=False, default=dict)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )
