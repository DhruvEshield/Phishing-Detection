"""QueueEntry ORM model."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, SCHEMA, IS_SQLITE, UuidColumn

_schema = {} if IS_SQLITE else {"schema": SCHEMA}
_fk_prefix = "" if IS_SQLITE else f"{SCHEMA}."


class QueueEntry(Base):
    __tablename__ = "queue_entries"
    __table_args__ = _schema

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    email_id: Mapped[str] = mapped_column(
        ForeignKey(f"{_fk_prefix}emails.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    email: Mapped["Email"] = relationship(back_populates="queue_entry")
