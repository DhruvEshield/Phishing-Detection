"""Email ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, SCHEMA, IS_SQLITE, JsonColumn, UuidColumn


class Email(Base):
    __tablename__ = "emails"
    __table_args__ = {} if IS_SQLITE else {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(
        UuidColumn, primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    dedup_hash: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    raw_headers_json: Mapped[dict] = mapped_column(JsonColumn, nullable=False)
    body_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    body_html: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attachments_json: Mapped[dict] = mapped_column(JsonColumn, nullable=False, default=list)
    sender: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    subject: Mapped[str] = mapped_column(String(998), nullable=False, default="")
    routing_decision: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    analysis: Mapped["AnalysisResult"] = relationship(back_populates="email", uselist=False)
    queue_entry: Mapped["QueueEntry"] = relationship(back_populates="email", uselist=False)
    verdict: Mapped["Verdict"] = relationship(back_populates="email", uselist=False)
