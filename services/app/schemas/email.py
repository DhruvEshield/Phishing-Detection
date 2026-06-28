"""Pydantic schemas for email ingest and queue responses."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field
import hashlib


class AttachmentMeta(BaseModel):
    filename: str
    content_type: str
    size_bytes: int


class EmailIngestRequest(BaseModel):
    """
    Inbound email payload. Accepts either raw_mime (full MIME string) or
    parsed fields. Inbound reports (from PhishSkill) carry sender_ip.
    """
    headers: dict[str, str] = Field(..., description="Parsed email headers k/v")
    body_text: str = Field(default="", description="Plain-text body")
    body_html: str = Field(default="", description="HTML body (sanitised server-side)")
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    raw_mime: Optional[str] = Field(default=None, description="Full raw MIME if available")
    # Inbound-report fields (PhishSkill integration — nullable in normal ingest)
    sender_ip: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: Optional[str] = None  # multi-tenant ready

    @property
    def dedup_hash(self) -> str:
        """MD5 of canonical payload for deduplication (per phishskill-integration.md §2)."""
        canonical = (
            self.headers.get("From", "")
            + self.headers.get("Subject", "")
            + self.body_text[:500]
        )
        return hashlib.md5(canonical.encode()).hexdigest()


class EmailSummary(BaseModel):
    """Minimal representation for queue listing."""
    email_id: str
    sender: str
    subject: str
    received_at: datetime
    risk_score: float
    risk_tier: str  # LOW | MEDIUM | HIGH | CRITICAL
    verdict: str    # PHISHING | SUSPICIOUS | LEGITIMATE | UNKNOWN
    status: str     # pending | reviewed
