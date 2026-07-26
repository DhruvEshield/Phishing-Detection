"""Sender history ORM model — tracks first-seen/last-seen/count per sender.

This is groundwork for future first-time-sender / BEC detection (Phase 3).
No detection logic uses this yet — it only records history so the data
exists once that feature is built.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Integer, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, SCHEMA, UuidColumn


class SenderHistory(Base):
    __tablename__ = "sender_history"
    __table_args__ = (
        UniqueConstraint("sender", "tenant_id", name="uq_sender_tenant"),
        {"schema": SCHEMA},
    )

    id: Mapped[str] = mapped_column(
        UuidColumn, primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    sender: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    email_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
