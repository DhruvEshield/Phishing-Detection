"""URL analyzer unit tests — WHOIS/RDAP and HTTP calls are mocked."""
from __future__ import annotations

from unittest.mock import patch

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


def test_homoglyph_lookalike_detected():
    """Punycode domain that decodes to a brand lookalike should be flagged."""
    analyzer = URLAnalyzer()
    # xn--pypal-4ve.com is punycode for a homoglyph of paypal.com
    signal = analyzer.analyse(
        body_text="Click here: http://xn--pypal-4ve.com/login",
        body_html="",
        weight=0.25,
    )
    assert any("homoglyph_lookalike" in f or "lookalike" in f for f in signal.flags), \
        f"Homoglyph lookalike should be flagged but got: {signal.flags}"


def test_raw_ip_host_detected():
    """URLs with raw IP addresses should be flagged."""
    analyzer = URLAnalyzer()
    signal = analyzer.analyse(
        body_text="Click here: http://185.220.101.45/login",
        body_html="",
        weight=0.25,
    )
    assert any("raw_ip_host" in f for f in signal.flags), \
        f"Raw IP should be flagged but got: {signal.flags}"


def test_excessive_subdomains_detected():
    """URLs with excessive subdomains should be flagged."""
    analyzer = URLAnalyzer()
    signal = analyzer.analyse(
        body_text="Click here: http://login.verify.account.microsoft.evil.com/steal",
        body_html="",
        weight=0.25,
    )
    assert any("excessive_subdomains" in f for f in signal.flags), \
        f"Excessive subdomains should be flagged but got: {signal.flags}"


def test_anchor_brand_mismatch_detected():
    """Anchor text claiming a brand but linking elsewhere should be flagged."""
    analyzer = URLAnalyzer()
    body_html = '<a href="https://evil.com/login">Login to Amazon</a>'
    signal = analyzer.analyse(body_text="", body_html=body_html, weight=0.25)
    assert any("anchor_brand_mismatch" in f for f in signal.flags)
    assert signal.raw_score > 0

from unittest.mock import patch
from app.detectors.brand_intel import BrandMatch

@patch("app.detectors.url.check_domain_against_brands")
@patch("app.detectors.url.is_newly_registered_domain")
def test_dnstwist_newly_registered_detected(mock_nrd, mock_dnstwist):
    """Dnstwist match + NRD yields dnstwist_match_newly_registered in URL flags."""
    mock_dnstwist.return_value = BrandMatch("amazon-security.com", "amazon", "addition", "amazon-security.com")
    mock_nrd.return_value = True
    
    analyzer = URLAnalyzer()
    signal = analyzer.analyse(
        body_text="Click here: https://amazon-security.com",
        body_html="",
        weight=0.25,
    )
    
    assert any("dnstwist_match_newly_registered:amazon" in f for f in signal.flags)
    assert signal.raw_score > 0
