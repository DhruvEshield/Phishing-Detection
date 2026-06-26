"""AnalysisResult ORM model — stores risk score + full explanation JSON."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base, SCHEMA, JsonColumn, UuidColumn


class AnalysisResult(Base):
    __tablename__ = "analysis_results"
    __table_args__ = {"schema": SCHEMA}

    id: Mapped[str] = mapped_column(UuidColumn, primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    email_id: Mapped[str] = mapped_column(
        ForeignKey(f"{SCHEMA}.emails.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(20), nullable=False)
    verdict: Mapped[str] = mapped_column(String(20), nullable=False)
    explanation_json: Mapped[dict] = mapped_column(JsonColumn, nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), nullable=False)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc),
    )

    email: Mapped["Email"] = relationship(back_populates="analysis")
