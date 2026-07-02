"""Header analyzer unit tests — DNS calls are mocked."""
from __future__ import annotations

from app.detectors.header import HeaderAnalyzer
from tests.conftest import SAMPLE_HEADERS, CLEAN_HEADERS


def test_phishing_headers_score_nonzero():
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(SAMPLE_HEADERS, weight=0.25)
    assert signal.raw_score > 0
    assert signal.name == "header"
    # At least one flag should fire
    assert len(signal.flags) > 0


def test_reply_to_mismatch_detected():
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(SAMPLE_HEADERS, weight=0.25)
    assert any("reply_to_mismatch" in f for f in signal.flags)


def test_auth_failures_flagged():
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(SAMPLE_HEADERS, weight=0.25)
    assert any("spf_" in f or "dkim_" in f or "dmarc_" in f for f in signal.flags)


def test_clean_headers_low_score():
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(CLEAN_HEADERS, weight=0.25)
    # Clean headers should score much lower
    assert signal.raw_score < 50


def test_lookalike_display_name_detected():
    headers = {
        "From": '"Micros0ft Support" <support@attacker.com>',
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert any("lookalike" in f for f in signal.flags)


def test_score_capped_at_100():
    """Raw score should never exceed 100 regardless of how many flags fire."""
    analyzer = HeaderAnalyzer()
    worst_headers = {
        "From": '"Micros0ft Support" <support@evil.com>',
        "Reply-To": "attacker@gmail.com",
        "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
    }
    signal = analyzer.analyse(worst_headers, weight=0.25)
    assert signal.raw_score <= 100.0


def test_weighted_contribution_correct():
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(SAMPLE_HEADERS, weight=0.25)
    expected = round(signal.raw_score * 0.25, 4)
    assert abs(signal.weighted_contribution - expected) < 0.001


def test_lookalike_sender_domain_detected():
    headers = {
        "From": '"IT Support" <support@micros0ft-helpdesk.com>',
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert any("lookalike_sender_domain" in f for f in signal.flags)


def test_spf_pass_from_received_spf_header():
    """SPF result should be read correctly from Received-SPF header format."""
    headers = {
        "From": "amazon@amazon.com",
        "Received-SPF": "pass (google.com: domain of amazon.com designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4;",
        "Authentication-Results": "dkim=pass dmarc=pass",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert not any("spf_" in f for f in signal.flags), f"SPF should not be flagged but got: {signal.flags}"
