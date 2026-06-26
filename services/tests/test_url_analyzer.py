"""URL analyzer unit tests — WHOIS/RDAP and HTTP calls are mocked."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from app.detectors.url import URLAnalyzer, _is_lookalike, _credential_harvest_heuristic
from app.detectors.domain_intel import DomainIntel


def _mock_intel(is_newly_registered=False, age_days=365):
    intel = DomainIntel(domain="test.com", age_days=age_days,
                        is_newly_registered=is_newly_registered)
    if is_newly_registered:
        intel.flags.append(f"newly_registered_{age_days}d")
    return intel


def test_lookalike_detection():
    assert _is_lookalike("micros0ft.com") is not None
    assert _is_lookalike("microsoftt.com") is not None
    assert _is_lookalike("microsoft.com") is None  # exact match — not lookalike
    assert _is_lookalike("totallylegitimateco.com") is None


def test_credential_harvest_heuristic():
    assert _credential_harvest_heuristic("http://evil.com/login") is True
    assert _credential_harvest_heuristic("http://evil.com/verify") is True
    assert _credential_harvest_heuristic("https://evil.com/login") is False  # HTTPS OK


@patch("app.detectors.url.get_domain_intel")
@patch("app.detectors.url._follow_redirects")
def test_newly_registered_domain_scores(mock_redir, mock_intel):
    mock_redir.return_value = ("http://evil.com/", ["http://evil.com/"])
    mock_intel.return_value = _mock_intel(is_newly_registered=True, age_days=5)

    analyzer = URLAnalyzer()
    body = "Click here: http://evil-new-domain.com/verify"
    signal = analyzer.analyse(body_text=body, body_html="", weight=0.25)

    assert signal.raw_score > 0
    assert any("newly_registered" in f for f in signal.flags)


@patch("app.detectors.url.get_domain_intel")
@patch("app.detectors.url._follow_redirects")
def test_clean_url_low_score(mock_redir, mock_intel):
    mock_redir.return_value = ("https://microsoft.com/", ["https://microsoft.com/"])
    mock_intel.return_value = _mock_intel(is_newly_registered=False, age_days=5000)

    analyzer = URLAnalyzer()
    body = "See https://microsoft.com for details."
    signal = analyzer.analyse(body_text=body, body_html="", weight=0.25)
    assert signal.raw_score < 30


@patch("app.detectors.url.get_domain_intel")
@patch("app.detectors.url._follow_redirects")
def test_score_capped_at_100(mock_redir, mock_intel):
    mock_redir.return_value = (
        "http://evil.com/login",
        ["http://redirect1.com", "http://redirect2.com", "http://evil.com/login"],
    )
    mock_intel.return_value = _mock_intel(is_newly_registered=True, age_days=1)

    analyzer = URLAnalyzer()
    body = " ".join([f"http://evil{i}.com/verify" for i in range(20)])
    signal = analyzer.analyse(body_text=body, body_html="", weight=0.25)
    assert signal.raw_score <= 100.0
