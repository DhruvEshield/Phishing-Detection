"""Detection service — orchestrates the full pipeline.

Fat Service pattern: all pipeline logic lives here; the API route is thin.
Runs all 5 detectors concurrently via threads, then scores and persists.
"""
from __future__ import annotations

import asyncio
import structlog
from sqlalchemy.orm import Session

from app.config import get_settings
from app.schemas.email import EmailIngestRequest
from app.schemas.scoring import EmailAnalysisResponse, ScoreExplanation
from app.detectors.header import HeaderAnalyzer
from app.detectors.content import ContentAnalyzer
from app.detectors.url import URLAnalyzer
from app.detectors.qrcode_detector import QRCodeDetector
from app.detectors.threat_intel import ThreatIntelModule, ChainedThreatIntelProvider
from app.detectors.attachment_analyzer import AttachmentAnalyzer
from app.scoring.config import ScoringConfig
from app.scoring.engine import ScoringEngine
from app.models.email import Email
from app.models.analysis import AnalysisResult
from app.models.queue_entry import QueueEntry
from app.models.sender_history import SenderHistory
from app.scoring.severity_map import get_flag_severity

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
            provider=ChainedThreatIntelProvider(db)
        )
        self._attachment = AttachmentAnalyzer()

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

        # ── Run header synchronously for context, then rest concurrently ─────
        header_signal = self._header.analyse(request.headers, weight=self._cfg.weights["header"])

        def run_content():
            brand_impersonation_ctx = header_signal.metadata.get("brand_impersonation")
            sender_domain = header_signal.metadata.get("spf", None) and request.headers.get("From", "")
            from app.detectors.domain_intel import extract_domain
            sender_domain = extract_domain(request.headers.get("From", ""))
            content_signal = self._content.analyse(
                body_text=request.body_text,
                body_html=request.body_html,
                weight=self._cfg.weights["content"],
                context={
                    "brand_impersonation": brand_impersonation_ctx,
                    "sender_domain": sender_domain,
                },
            )
            return content_signal

        # Run URL analyzer synchronously to extract redirect URLs for threat intel
        url_signal = self._url.analyse(request.body_text, request.body_html,
                                       weight=self._cfg.weights["url"])
        redirect_final_urls = url_signal.metadata.get("redirect_final_urls", [])

        # ── Brand + URL correlation ───────────────────────────────────────
        # If header detected brand impersonation, check if any URLs go to the real brand domain
        brand_ctx = header_signal.metadata.get("brand_impersonation")
        if brand_ctx:
            from app.detectors.header import BRAND_DOMAINS
            claimed_brand = brand_ctx.get("claimed_brand", "")
            expected_domain = BRAND_DOMAINS.get(claimed_brand, "")
            if expected_domain:
                # Check if any URL in email goes to the real brand domain
                import re
                all_urls = re.findall(r'https?://[^\s<>"\']+', request.body_text + " " + request.body_html)
                goes_to_real_domain = any(expected_domain in url for url in all_urls)
                if not goes_to_real_domain and all_urls:
                    # Links don't go to the real brand domain — suspicious
                    url_signal.flags.append(f"brand_url_mismatch:{claimed_brand}(links_not_going_to:{expected_domain})")
                    url_signal.raw_score = min(url_signal.raw_score + 25.0, 100.0)
                    url_signal.metadata["brand_url_mismatch"] = {
                        "claimed_brand": claimed_brand,
                        "expected_domain": expected_domain,
                        "urls_found": len(all_urls),
                    }

        def run_qr():
            return self._qr.analyse(request.body_html, weight=self._cfg.weights["qrcode"])

        def run_threat():
            # Build extra body text with redirect final URLs for threat intel
            extra_body = request.body_text + " " + " ".join(redirect_final_urls)
            return self._threat.analyse(request.headers, extra_body,
                                        request.body_html, weight=self._cfg.weights["threat_intel"])

        def run_attachment():
            return self._attachment.analyse(
                attachments=request.attachments,
                weight=self._cfg.weights["attachment"],
            )

        loop = asyncio.get_event_loop()
        other_signals = await asyncio.gather(
            loop.run_in_executor(None, run_content),
            loop.run_in_executor(None, run_qr),
            loop.run_in_executor(None, run_threat),
            loop.run_in_executor(None, run_attachment),
        )
        signals = [header_signal, url_signal] + list(other_signals)

        # ── Score ─────────────────────────────────────────────────────────────
        result = self._engine.compute(list(signals))
        issues = self._build_issues_list(signals)

        # ── Persist ───────────────────────────────────────────────────────────
        from_header = request.headers.get("From", "")
        email = Email(
            dedup_hash=request.dedup_hash,
            raw_headers_json=request.headers,
            body_text=request.body_text,
            body_html=request.body_html,
            attachments_json=[a.model_dump(exclude={"content_bytes"}) for a in request.attachments],
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
                              "model_version": settings.model_version,
                              "issues": issues},
            model_version=settings.model_version,
            tenant_id=request.tenant_id,
        )
        self._db.add(ar)

        # Add to review queue if medium risk
        if result.routing_decision == "review":
            self._db.add(QueueEntry(email_id=email.id, tenant_id=request.tenant_id))

        self._record_sender_history(from_header, request.tenant_id)

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

    def _record_sender_history(self, sender: str, tenant_id: str | None) -> None:
        """Upsert a SenderHistory row — tracks first/last seen and count per
        sender. Groundwork for future first-time-sender / BEC detection;
        no detection logic reads this yet."""
        if not sender:
            return
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        try:
            existing = (
                self._db.query(SenderHistory)
                .filter(
                    SenderHistory.sender == sender,
                    SenderHistory.tenant_id == tenant_id,
                )
                .first()
            )
            if existing:
                existing.last_seen_at = now
                existing.email_count += 1
            else:
                self._db.add(SenderHistory(
                    sender=sender,
                    tenant_id=tenant_id,
                    first_seen_at=now,
                    last_seen_at=now,
                    email_count=1,
                ))
        except Exception as exc:
            log.warning("detection.sender_history_error", error=str(exc), sender=sender)

    def _build_issues_list(self, signals: list) -> list[dict]:
        """Build a severity-graded issues list from all detector signals,
        sorted from most to least severe. Each entry: {detector, flag, severity}.
        Flags with no severity (excluded/unmapped) are skipped."""
        _SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        issues = []
        for signal in signals:
            for flag in signal.flags:
                severity = get_flag_severity(flag)
                if severity is None:
                    continue
                issues.append({
                    "detector": signal.name,
                    "flag": flag,
                    "severity": severity,
                })
        issues.sort(key=lambda i: _SEVERITY_ORDER.get(i["severity"], 99))
        return issues

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
                issues=exp_data.get("issues", []),
                model_version=exp_data.get("model_version", settings.model_version),
            ),
            analysed_at=ar.created_at,
            model_version=ar.model_version,
            tenant_id=email.tenant_id,
        )
