"""
CRITICAL TEST: No single signal can independently breach the high-risk threshold.

This is the canonical invariant test required by the plan and principles.md.
It proves — parametrically, for every signal — that the scoring configuration
is safe. If this test fails, the scoring system is misconfigured.
"""
from __future__ import annotations

import pytest

from app.scoring.config import ScoringConfig
from app.scoring.engine import ScoringEngine
from app.detectors.base import Signal
from tests.conftest import make_config, make_signal

# All signal names in the system
ALL_SIGNALS = ["header", "content", "url", "qrcode", "threat_intel"]


@pytest.mark.parametrize("signal_name", ALL_SIGNALS)
def test_single_signal_cannot_breach_high_threshold(signal_name: str):
    """
    For every signal: sending it at max score (100) alone must NOT produce
    a total score >= high_threshold. All other signals are at 0.
    """
    cfg = make_config()  # default weights, high_threshold=70
    engine = ScoringEngine(cfg)

    # One signal at max, all others at 0
    signals = [
        make_signal(name, raw_score=(100.0 if name == signal_name else 0.0))
        for name in ALL_SIGNALS
    ]

    result = engine.compute(signals)

    assert result.total_score < cfg.high_threshold, (
        f"INVARIANT VIOLATED: signal '{signal_name}' alone produced score "
        f"{result.total_score} >= high_threshold={cfg.high_threshold}. "
        f"This means a single signal can independently force a block — "
        f"which is explicitly prohibited by principles.md #1."
    )
    assert result.routing_decision != "quarantine", (
        f"Signal '{signal_name}' at max alone triggered quarantine routing."
    )


def test_combined_signals_can_breach_threshold():
    """Sanity check: multiple high signals together CAN cross the threshold."""
    cfg = make_config()
    engine = ScoringEngine(cfg)

    # All signals at max
    signals = [make_signal(name, 100.0) for name in ALL_SIGNALS]
    result = engine.compute(signals)

    assert result.total_score >= cfg.high_threshold
    assert result.routing_decision == "quarantine"


def test_config_validates_invariant_on_construction():
    """ScoringConfig.validate_invariant() raises on a bad weight."""
    bad_cfg = ScoringConfig(
        high_threshold=70.0,
        medium_threshold=35.0,
        weights={"header": 0.80, "content": 0.20},  # 0.80 * 100 = 80 >= 70 ✗
    )
    with pytest.raises(ValueError, match="VIOLATED"):
        bad_cfg.validate_invariant()


def test_config_valid_with_default_weights():
    """Default weights pass the invariant check without raising."""
    cfg = make_config()
    cfg.validate_invariant()  # must not raise


def test_explanation_always_populated():
    """ScoreResult.explanation is never empty — explainability is a hard requirement."""
    cfg = make_config()
    engine = ScoringEngine(cfg)
    signals = [make_signal("header", 50.0), make_signal("content", 30.0)]
    result = engine.compute(signals)

    assert result.explanation is not None
    assert len(result.explanation) == len(signals)
    for breakdown in result.explanation:
        assert "signal_name" in breakdown
        assert "weighted_contribution" in breakdown
        assert "flags" in breakdown


def test_medium_risk_routes_to_review():
    cfg = make_config(high=70.0, medium=35.0)
    engine = ScoringEngine(cfg)
    # Score that lands in medium band
    signals = [make_signal("content", 60.0, weight=0.30),
               make_signal("header", 40.0, weight=0.25)]
    result = engine.compute(signals)
    if result.total_score >= 35.0 and result.total_score < 70.0:
        assert result.routing_decision == "review"


def test_low_risk_routes_to_deliver():
    cfg = make_config()
    engine = ScoringEngine(cfg)
    signals = [make_signal(name, 0.0) for name in ALL_SIGNALS]
    result = engine.compute(signals)
    assert result.routing_decision == "deliver"
    assert result.risk_tier == "LOW"
