"""Content analyzer unit tests — ML classifier is mocked."""
from __future__ import annotations

from unittest.mock import MagicMock
from dataclasses import dataclass

from app.detectors.content import ContentAnalyzer
from tests.conftest import PHISHING_BODY, CLEAN_BODY


@dataclass
class FakeClassificationResult:
    label: str
    confidence: float
    model_version: str = "test-v0.1"


def make_classifier(label="phishing", confidence=0.9):
    clf = MagicMock()
    clf.predict.return_value = FakeClassificationResult(label=label, confidence=confidence)
    return clf


def test_phishing_body_scores_high_with_ml():
    clf = make_classifier(label="phishing", confidence=0.95)
    analyzer = ContentAnalyzer(classifier=clf)
    signal = analyzer.analyse(PHISHING_BODY, weight=0.30)
    assert signal.raw_score > 30
    assert any("ml_phishing" in f for f in signal.flags)


def test_clean_body_scores_low():
    clf = make_classifier(label="legitimate", confidence=0.99)
    analyzer = ContentAnalyzer(classifier=clf)
    signal = analyzer.analyse(CLEAN_BODY, weight=0.30)
    assert signal.raw_score < 30


def test_rules_only_mode_no_classifier():
    """ContentAnalyzer works in rules-only mode when classifier is None."""
    analyzer = ContentAnalyzer(classifier=None)
    signal = analyzer.analyse(PHISHING_BODY, weight=0.30)
    assert signal.raw_score > 0
    assert signal.name == "content"


def test_urgency_language_flagged():
    body = "URGENT: Your account will be suspended immediately."
    analyzer = ContentAnalyzer(classifier=None)
    signal = analyzer.analyse(body, weight=0.30)
    assert any("urgency" in f for f in signal.flags)


def test_credential_request_flagged():
    body = "Please verify your account password to continue."
    analyzer = ContentAnalyzer(classifier=None)
    signal = analyzer.analyse(body, weight=0.30)
    assert any("credential" in f for f in signal.flags)


def test_empty_body_returns_zero():
    analyzer = ContentAnalyzer(classifier=None)
    signal = analyzer.analyse("", weight=0.30)
    assert signal.raw_score == 0.0


def test_ml_error_falls_back_gracefully():
    """If classifier raises, score should still be produced (rules only)."""
    clf = MagicMock()
    clf.predict.side_effect = RuntimeError("model not loaded")
    analyzer = ContentAnalyzer(classifier=clf)
    signal = analyzer.analyse(PHISHING_BODY, weight=0.30)
    assert signal.raw_score >= 0  # no crash


def test_score_capped_at_100():
    clf = make_classifier(label="phishing", confidence=1.0)
    analyzer = ContentAnalyzer(classifier=clf)
    body = " ".join([PHISHING_BODY] * 10)
    signal = analyzer.analyse(body, weight=0.30)
    assert signal.raw_score <= 100.0
