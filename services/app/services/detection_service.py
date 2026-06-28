"""Detection service — orchestrates the full pipeline.

Fat Service pattern: all pipeline logic lives here; the API route is thin.
Runs all 5 detectors concurrently via threads, then scores and persists.
"""
from __future__ import annotations

import asyncio
import structlog
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.config import get_settings
from app.schemas.email import EmailIngestRequest
from app.schemas.scoring import EmailAnalysisResponse, ScoreExplanation
from app.detectors.header import HeaderAnalyzer
from app.detectors.content import ContentAnalyzer
from app.detectors.url import URLAnalyzer
from app.detectors.qrcode_detector import QRCodeDetector
from app.detectors.threat_intel import ThreatIntelModule, LocalBlocklistAdapter
from app.scoring.config import ScoringConfig
from app.scoring.engine import ScoringEngine
from app.models.email import Email
from app.models.analysis import AnalysisResult
from app.models.queue_entry import QueueEntry

log = structlog.get_logger()


def _load_classifier():
    """Try to load the ML content classifier; return None on cold start."""
    try:
        import sys
        sys.path.insert(0, "/app/ml")
        from inference import ContentClassifier
        settings = get_settings()
        return ContentClassifier.load(settings.model_path, settings.model_version)
    except Exception as exc:
        log.warning("detection.classifier_unavailable", error=str(exc))
        return None


_CLASSIFIER = None  # module-level singleton


def _get_classifier():
    global _CLASSIFIER
    if _CLASSIFIER is None:
        _CLASSIFIER = _load_classifier()
    return _CLASSIFIER


class DetectionService:
    def __init__(self, db: Session):
        self._db = db
        settings = get_settings()
        self._cfg = ScoringConfig.from_settings(settings)
        self._engine = ScoringEngine(self._cfg)

        # Build detector instances
        self._header = HeaderAnalyzer()
        self._content = ContentAnalyzer(classifier=_get_classifier())
        self._url = URLAnalyzer()
        self._qr = QRCodeDetector(url_analyzer=self._url)
        self._threat = ThreatIntelModule(
            provider=LocalBlocklistAdapter(db)
        )

    async def analyse(self, request: EmailIngestRequest) -> EmailAnalysisResponse:
        settings = get_settings()

        # ── Dedup check ───────────────────────────────────────────────────────
        existing = (
            self._db.query(Email)
            .filter(Email.dedup_hash == request.dedup_hash)
            .first()
        )
        if existing and existing.analysis:
            log.info("detection.dedup_hit", email_id=existing.id,
                     action="dedup_skip", resource_id=existing.id)
            ar = existing.analysis
            return self._build_response(existing, ar)

        # ── Run all 5 detectors concurrently ─────────────────────────────────
        def run_header():
            return self._header.analyse(request.headers, weight=self._cfg.weights["header"])

        def run_content():
            return self._content.analyse(request.body_text, weight=self._cfg.weights["content"])

        def run_url():
            return self._url.analyse(request.body_text, request.body_html,
                                     weight=self._cfg.weights["url"])

        def run_qr():
            return self._qr.analyse(request.body_html, weight=self._cfg.weights["qrcode"])

        def run_threat():
            return self._threat.analyse(request.headers, request.body_text,
                                        request.body_html, weight=self._cfg.weights["threat_intel"])

        loop = asyncio.get_event_loop()
        signals = await asyncio.gather(
            loop.run_in_executor(None, run_header),
            loop.run_in_executor(None, run_content),
            loop.run_in_executor(None, run_url),
            loop.run_in_executor(None, run_qr),
            loop.run_in_executor(None, run_threat),
        )

        # ── Score ─────────────────────────────────────────────────────────────
        result = self._engine.compute(list(signals))

        # ── Persist ───────────────────────────────────────────────────────────
        from_header = request.headers.get("From", "")
        email = Email(
            dedup_hash=request.dedup_hash,
            raw_headers_json=request.headers,
            body_text=request.body_text,
            body_html=request.body_html,
            attachments_json=[a.model_dump() for a in request.attachments],
            sender=from_header,
            subject=request.headers.get("Subject", ""),
            routing_decision=result.routing_decision,
            tenant_id=request.tenant_id,
        )
        self._db.add(email)
        self._db.flush()  # get email.id

        ar = AnalysisResult(
            email_id=email.id,
            risk_score=result.total_score,
            risk_tier=result.risk_tier,
            verdict=result.verdict,
            explanation_json={"signals": result.explanation,
                              "model_version": settings.model_version},
            model_version=settings.model_version,
            tenant_id=request.tenant_id,
        )
        self._db.add(ar)

        # Add to review queue if medium risk
        if result.routing_decision == "review":
            self._db.add(QueueEntry(email_id=email.id, tenant_id=request.tenant_id))

        self._db.commit()
        self._db.refresh(email)

        log.info(
            "detection.complete",
            email_id=email.id,
            score=result.total_score,
            tier=result.risk_tier,
            routing=result.routing_decision,
            action="email_analysed",
            resource_id=email.id,
            tenant_id=request.tenant_id,
        )

        return self._build_response(email, ar)

    def _build_response(self, email: Email, ar: AnalysisResult) -> EmailAnalysisResponse:
        settings = get_settings()
        exp_data = ar.explanation_json
        return EmailAnalysisResponse(
            email_id=email.id,
            risk_score=ar.risk_score,
            risk_tier=ar.risk_tier,
            verdict=ar.verdict,
            routing_decision=email.routing_decision,
            explanation=ScoreExplanation(
                signals=exp_data.get("signals", []),
                model_version=exp_data.get("model_version", settings.model_version),
            ),
            analysed_at=ar.created_at,
            model_version=ar.model_version,
            tenant_id=email.tenant_id,
        )
