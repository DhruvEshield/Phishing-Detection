"""Verdict service — persists analyst decisions and emits FeedbackEvents."""
from __future__ import annotations

import structlog
from sqlalchemy.orm import Session

from app.models.verdict import Verdict
from app.models.email import Email
from app.models.blocklist import FeedbackEvent, AuditLog, BlocklistEntry
from app.detectors.domain_intel import extract_domain
from datetime import datetime, timezone, timedelta
from app.models.queue_entry import QueueEntry
from app.models.analysis import AnalysisResult
from app.schemas.feedback import VerdictRequest, VerdictResponse

log = structlog.get_logger()


class VerdictService:
    def __init__(self, db: Session):
        self._db = db

    def record(self, req: VerdictRequest) -> VerdictResponse:
        # Fetch analysis for the feedback payload
        ar = (
            self._db.query(AnalysisResult)
            .filter(AnalysisResult.email_id == req.email_id)
            .first()
        )

        verdict = Verdict(
            email_id=req.email_id,
            action=req.action.value,
            analyst_id=req.analyst_id,
            reason=req.reason,
            tenant_id=req.tenant_id,
        )
        self._db.add(verdict)
        self._db.flush()

        # Mark queue entry as reviewed
        qe = (
            self._db.query(QueueEntry)
            .filter(QueueEntry.email_id == req.email_id)
            .first()
        )
        if qe:
            qe.status = "reviewed"
            qe.reviewed_at = datetime.now(timezone.utc)

        # Emit FeedbackEvent (feedback loop contract — consumed_at=None = pending)
        payload = {
            "email_id": req.email_id,
            "action": req.action.value,
            "analyst_id": req.analyst_id,
            "signals": ar.explanation_json if ar else {},
            "reason": req.reason,
        }
        fb_event = FeedbackEvent(
            verdict_id=verdict.id,
            event_type="analyst_verdict",
            payload_json=payload,
            tenant_id=req.tenant_id,
        )
        self._db.add(fb_event)

        # ── Feedback loop: quarantine verdict → add sender domain to blocklist ──
        if req.action.value == "quarantine":
            email_obj = self._db.query(Email).filter(Email.id == req.email_id).first() if not locals().get('email_obj') else email_obj
            if email_obj and email_obj.sender:
                sender_domain = extract_domain(email_obj.sender)
                if sender_domain:
                    existing = self._db.query(BlocklistEntry).filter(
                        BlocklistEntry.indicator == sender_domain.lower(),
                        BlocklistEntry.indicator_type == "domain",
                        BlocklistEntry.source == "analyst_verdict",
                    ).first()
                    if not existing:
                        self._db.add(BlocklistEntry(
                            indicator=sender_domain.lower(),
                            indicator_type="domain",
                            source="analyst_verdict",
                            tenant_id=req.tenant_id,
                            expires_at=datetime.now(timezone.utc) + timedelta(days=90),
                        ))
                        log.info("blocklist.added", domain=sender_domain, source="analyst_verdict")

        # Audit trail (principle #5 + #7)
        self._db.add(AuditLog(
            actor=req.analyst_id or "anonymous",
            action=f"verdict.{req.action.value}",
            resource_id=req.email_id,
            severity="info",
            detail_json={"verdict_id": verdict.id, "reason": req.reason},
            tenant_id=req.tenant_id,
        ))

        self._db.commit()

        log.info(
            "verdict.recorded",
            verdict_id=verdict.id,
            email_id=req.email_id,
            action=req.action.value,
            analyst=req.analyst_id,
            resource_id=req.email_id,
            tenant_id=req.tenant_id,
        )

        return VerdictResponse(
            verdict_id=verdict.id,
            email_id=req.email_id,
            action=req.action,
            recorded_at=verdict.created_at,
        )
