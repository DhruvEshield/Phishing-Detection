"""Content analysis detector.

Calls the ContentClassifier interface (implemented in ml/inference.py).
The interface boundary means the backend never imports sklearn directly —
the model is swappable without touching this file.
"""
from __future__ import annotations

import re
import structlog

from app.detectors.base import Signal

log = structlog.get_logger()

# ── Rule-based urgency/phishing patterns (rules before ML) ───────────────────
_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+24\s+hours?\b",
    r"\baccount\s+(suspended|disabled|closed)\b", r"\bverif(y|ication)\b",
    r"\bclick\s+here\b", r"\bact\s+now\b", r"\bexpires?\b",
]
_CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bsign[\s-]in\b", r"\bsign[\s-]on\b",
    r"\bverif(y|ication)\s+(your\s+)?(account|identity|email)\b",
    r"\benter\s+your\s+credentials\b",
]
_AUTHORITY_PATTERNS = [
    r"\bIT\s+(support|security|department|team)\b",
    r"\bhelp\s*desk\b", r"\bsecurity\s+(team|alert|notice)\b",
    r"\bfinancial\s+(department|controller)\b",
]


def _count_pattern_hits(text: str, patterns: list[str]) -> int:
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))


class ContentAnalyzer:
    """
    Combines rule-based pattern matching (fast, always-on) with an ML
    classifier (ContentClassifier interface — swappable).

    Rule layer runs first (rules before ML — principles.md).
    ML score blended in when model is available.
    """

    def __init__(self, classifier=None):
        """
        classifier: object with .predict(text: str) -> ClassificationResult
                    Pass None to run rules-only (useful in tests / cold start).
        """
        self._classifier = classifier

    def analyse(self, body_text: str, body_html: str, weight: float, context: dict | None = None) -> Signal:
        flags: list[str] = []
        meta: dict = {}

        text = body_text or ""

        # ── Rule-based layer ─────────────────────────────────────────────────
        urgency_hits = _count_pattern_hits(text, _URGENCY_PATTERNS)
        credential_hits = _count_pattern_hits(text, _CREDENTIAL_PATTERNS)
        authority_hits = _count_pattern_hits(text, _AUTHORITY_PATTERNS)

        rule_score = min(
            (urgency_hits * 12) + (credential_hits * 15) + (authority_hits * 10),
            60.0,
        )
        meta["urgency_hits"] = urgency_hits
        meta["credential_hits"] = credential_hits
        meta["authority_hits"] = authority_hits

        if urgency_hits:
            flags.append(f"urgency_language({urgency_hits})")
        if credential_hits:
            flags.append(f"credential_request({credential_hits})")
        if authority_hits:
            flags.append(f"authority_impersonation({authority_hits})")

        # ── ML classifier layer ──────────────────────────────────────────────
        ml_score = 0.0
        use_ml = True
        if self._classifier is not None and text.strip():
            try:
                result = self._classifier.predict(text)
                meta["ml_label"] = result.label
                meta["ml_confidence"] = round(result.confidence, 4)
                meta["model_version"] = result.model_version
                if result.label == "phishing":
                    ml_score = result.confidence * 100
                    flags.append(f"ml_phishing(conf={result.confidence:.2f})")
            except Exception as exc:
                log.error(
                    "detector.content.ml_error", error=str(exc),
                    action="content_analysis",
                )
                ml_score = 0.0
                use_ml = False

        # Blend: 40% rules, 60% ML (or 100% rules if no ML)
        if self._classifier is not None and use_ml:
            raw_score = 0.40 * rule_score + 0.60 * ml_score
        else:
            raw_score = rule_score

        raw_score = min(raw_score, 100.0)

        # ── Inter-detector boost: brand impersonation confirmed by header ──────
        if context and context.get("brand_impersonation") and meta.get("ml_label") == "phishing":
            boost = 20.0
            raw_score = min(raw_score + boost, 100.0)
            flags.append("brand_impersonation_confirmed(header+ml)")
            log.info("detector.content.brand_boost", boost=boost, action="content_analysis")

        log.info("detector.content", score=raw_score, flags=flags,
                 action="content_analysis")
        return Signal(name="content", raw_score=raw_score, weight=weight,
                      flags=flags, metadata=meta)
