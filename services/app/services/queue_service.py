"""Queue service — fetches and paginates medium-risk emails."""
from __future__ import annotations

from sqlalchemy.orm import Session
from app.models.queue_entry import QueueEntry
from app.models.email import Email
from app.models.analysis import AnalysisResult


class QueueService:
    def __init__(self, db: Session):
        self._db = db

    def list_pending(self, page: int = 1, page_size: int = 20,
                     tenant_id: str | None = None) -> tuple[list[dict], int]:
        q = (
            self._db.query(QueueEntry, Email, AnalysisResult)
            .join(Email, QueueEntry.email_id == Email.id)
            .join(AnalysisResult, AnalysisResult.email_id == Email.id)
            .filter(QueueEntry.status == "pending")
        )
        if tenant_id:
            q = q.filter(QueueEntry.tenant_id == tenant_id)

        total = q.count()
        rows = q.order_by(AnalysisResult.risk_score.desc()) \
                .offset((page - 1) * page_size).limit(page_size).all()

        items = [
            {
                "email_id": email.id,
                "sender": email.sender,
                "subject": email.subject,
                "received_at": email.received_at.isoformat(),
                "risk_score": ar.risk_score,
                "risk_tier": ar.risk_tier,
                "verdict": ar.verdict,
                "status": qe.status,
                "tenant_id": email.tenant_id,
            }
            for qe, email, ar in rows
        ]
        return items, total

    def get_detail(self, email_id: str) -> dict | None:
        row = (
            self._db.query(Email, AnalysisResult)
            .join(AnalysisResult, AnalysisResult.email_id == Email.id)
            .filter(Email.id == email_id)
            .first()
        )
        if not row:
            return None
        email, ar = row
        return {
            "email_id": email.id,
            "sender": email.sender,
            "subject": email.subject,
            "received_at": email.received_at.isoformat(),
            "body_text": email.body_text,
            "headers": email.raw_headers_json,
            "risk_score": ar.risk_score,
            "risk_tier": ar.risk_tier,
            "verdict": ar.verdict,
            "routing_decision": email.routing_decision,
            "explanation": ar.explanation_json,
            "model_version": ar.model_version,
            "tenant_id": email.tenant_id,
        }
