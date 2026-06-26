"""Feedback loop contract — Layer 1 → future Layer 2 interface.

FeedbackEvent is the unit of data that flows from analyst verdicts
back into scoring weights / blocklists. Layer 2 doesn't exist yet,
but the contract + DB table are in place so it can be wired without
a schema change.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel


class VerdictAction(str, Enum):
    APPROVE = "approve"       # analyst confirms email is legitimate
    QUARANTINE = "quarantine"  # analyst confirms email is phishing


class VerdictRequest(BaseModel):
    email_id: str
    action: VerdictAction
    reason: Optional[str] = None
    analyst_id: Optional[str] = None  # nullable for Phase 1 (no auth yet)
    tenant_id: Optional[str] = None


class VerdictResponse(BaseModel):
    verdict_id: str
    email_id: str
    action: VerdictAction
    recorded_at: datetime


class FeedbackEvent(BaseModel):
    """
    Emitted by FeedbackProducer on every analyst verdict.
    Consumed by (future) Layer 2 scoring/blocklist updater.
    Persisted to feedback_events table — consumed_at=None means pending.
    """
    event_id: str
    event_type: str          # "analyst_verdict"
    verdict_id: str
    email_id: str
    action: VerdictAction
    signals_json: dict[str, Any]  # the original signal breakdown
    payload: dict[str, Any]
    occurred_at: datetime
    tenant_id: Optional[str] = None
