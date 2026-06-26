"""Verdict ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, SCHEMA, UuidColumn


class Verdict(Base):
    __tablename__ = "verdicts"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    email_id: Mapped[str] = mapped_column(
        ForeignKey(f"{SCHEMA}.emails.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    analyst_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )

    email: Mapped["Email"] = relationship(back_populates="verdict")
