"""Test fixtures and helpers shared across the test suite."""
from __future__ import annotations

import pytest

from app.scoring.config import ScoringConfig
from app.scoring.engine import ScoringEngine
from app.detectors.base import Signal


def make_config(
    high: float = 70.0,
    medium: float = 35.0,
    weights: dict | None = None,
) -> ScoringConfig:
    if weights is None:
        weights = {
            "header": 0.25,
            "content": 0.30,
            "url": 0.25,
            "qrcode": 0.10,
            "threat_intel": 0.10,
        }
    return ScoringConfig(high_threshold=high, medium_threshold=medium, weights=weights)


def make_signal(name: str, raw_score: float, weight: float = 0.0) -> Signal:
    return Signal(name=name, raw_score=raw_score, weight=weight)


@pytest.fixture
def default_config() -> ScoringConfig:
    return make_config()


@pytest.fixture
def scoring_engine(default_config) -> ScoringEngine:
    return ScoringEngine(default_config)


SAMPLE_HEADERS = {
    "From": '"IT Support" <support@micros0ft-helpdesk.com>',
    "To": "employee@company.com",
    "Subject": "URGENT: Account suspended",
    "Reply-To": "attacker@gmail.com",
    "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
}

CLEAN_HEADERS = {
    "From": "Alice <alice@microsoft.com>",
    "To": "bob@company.com",
    "Subject": "Meeting tomorrow",
    "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
}

PHISHING_BODY = (
    "Your account will be suspended immediately. "
    "Verify your password now: http://login-microsoftonline-secure.xyz/verify"
)

CLEAN_BODY = "Hi Bob, are you free for coffee tomorrow at 10am? Best, Alice"
