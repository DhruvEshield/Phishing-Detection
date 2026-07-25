"""Pydantic schemas for scoring output — the explainability contract.

Every analysis response MUST include a populated `explanation` object.
This is enforced as a non-optional field so the API returns 422
if the scoring engine fails to produce an explanation.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class SignalBreakdown(BaseModel):
    """One detector's contribution — the unit of explainability."""
    signal_name: str
    raw_score: float = Field(ge=0, le=100)
    weight: float = Field(ge=0, le=1)
    weighted_contribution: float = Field(ge=0, le=100)
    flags: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class ScoreExplanation(BaseModel):
    """
    Structured explanation attached to every analysis result.
    Required — never optional. Principle #3: explainability from day one.
    """
    model_config = ConfigDict(protected_namespaces=())

    signals: list[SignalBreakdown]
    # Severity-graded issues list (each entry has detector, flag, severity keys),
    # separate from the raw per-detector signals breakdown.
    issues: list[dict] = Field(default_factory=list)
    model_version: str


class EmailAnalysisResponse(BaseModel):
    """Full response from the ingest endpoint."""
    model_config = ConfigDict(protected_namespaces=())

    email_id: str
    risk_score: float = Field(ge=0, le=100)
    risk_tier: str          # LOW | MEDIUM | HIGH | CRITICAL
    verdict: str            # PHISHING | SUSPICIOUS | LEGITIMATE | UNKNOWN
    routing_decision: str   # quarantine | review | deliver
    explanation: ScoreExplanation   # non-optional — enforced in code, not convention
    analysed_at: datetime
    model_version: str
    tenant_id: Optional[str] = None
