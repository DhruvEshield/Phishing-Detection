"""Scoring engine — aggregates signals into a risk score + explanation.

Core contract:
  - Accepts a list of Signal objects.
  - Returns ScoreResult (total_score, tier, verdict, routing_decision, breakdowns).
  - explanation is always populated — never None.
  - No single signal can independently produce total >= high_threshold (enforced by ScoringConfig).

Risk tiers (PhishSkill convention): LOW | MEDIUM | HIGH | CRITICAL
Verdicts:                           LEGITIMATE | UNKNOWN | SUSPICIOUS | PHISHING
Routing:                            deliver | review | quarantine
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import structlog

from app.detectors.base import Signal
from app.scoring.config import ScoringConfig

log = structlog.get_logger()


@dataclass
class ScoreResult:
    total_score: float          # 0–100
    risk_tier: str              # LOW | MEDIUM | HIGH | CRITICAL
    verdict: str                # LEGITIMATE | UNKNOWN | SUSPICIOUS | PHISHING
    routing_decision: str       # deliver | review | quarantine
    explanation: list[dict]     # list of SignalBreakdown dicts — always populated
    computed_at: datetime


def _tier(score: float, high: float, medium: float) -> str:
    if score >= high:
        return "CRITICAL" if score >= 90 else "HIGH"
    if score >= medium:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "LOW"


def _verdict(tier: str) -> str:
    return {"CRITICAL": "PHISHING", "HIGH": "PHISHING",
            "MEDIUM": "SUSPICIOUS", "LOW": "LEGITIMATE"}.get(tier, "UNKNOWN")


def _routing(tier: str) -> str:
    return {"CRITICAL": "quarantine", "HIGH": "quarantine",
            "MEDIUM": "review", "LOW": "deliver"}.get(tier, "deliver")


class ScoringEngine:
    def __init__(self, config: ScoringConfig):
        self._cfg = config

    def compute(self, signals: list[Signal]) -> ScoreResult:
        """
        Aggregate weighted signals into a total score.

        Each signal's weight is overridden by config (single source of truth).
        The engine applies the config weight — detectors' own weight field is
        advisory only (used when engine is bypassed in unit tests).
        """
        total = 0.0
        breakdowns: list[dict] = []

        for sig in signals:
            w = self._cfg.weights.get(sig.name, sig.weight)
            contribution = round(sig.raw_score * w, 4)
            total += contribution
            breakdowns.append({
                "signal_name": sig.name,
                "raw_score": round(sig.raw_score, 2),
                "weight": w,
                "weighted_contribution": contribution,
                "flags": sig.flags,
                "metadata": sig.metadata,
            })

        total = round(min(total, 100.0), 2)
        tier = _tier(total, self._cfg.high_threshold, self._cfg.medium_threshold)
        verdict = _verdict(tier)
        routing = _routing(tier)

        log.info(
            "scoring.result",
            total_score=total,
            tier=tier,
            verdict=verdict,
            routing=routing,
            action="score_computed",
        )

        return ScoreResult(
            total_score=total,
            risk_tier=tier,
            verdict=verdict,
            routing_decision=routing,
            explanation=breakdowns,  # always populated — never None
            computed_at=datetime.now(timezone.utc),
        )
