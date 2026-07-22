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


def test_brand_impersonation_detected():
    """Display name claims Amazon but sender domain is not amazon.com."""
    headers = {
        "From": '"Amazon" <support@vinciengage.com>',
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert any("brand_impersonation" in f for f in signal.flags), \
        f"Brand impersonation should be flagged but got: {signal.flags}"


# ── Authentication alignment ────────────────────────────────────────────────

def test_auth_pass_but_unaligned():
    """SPF/DKIM both 'pass' but authenticated to attacker.com, not the claimed
    amazon.com From domain — the headline spoof the old code missed."""
    headers = {
        "From": "security@amazon.com",
        "Authentication-Results": (
            "spf=pass smtp.mailfrom=attacker.com; "
            "dkim=pass header.d=attacker.com; dmarc=none"
        ),
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert any("auth_pass_but_unaligned" in f for f in signal.flags), \
        f"Expected unaligned flag, got: {signal.flags}"
    assert signal.metadata["auth_alignment"]["aligned"] is False
    assert signal.raw_score >= 30


def test_dkim_aligned_not_flagged():
    """DKIM d= matches the From registrable domain (subdomain sender) — aligned,
    even with dmarc=none. No unaligned penalty."""
    headers = {
        "From": "noreply@email.amazon.com",
        "Authentication-Results": "dkim=pass header.d=amazon.com; spf=pass smtp.mailfrom=amazon.com; dmarc=none",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert not any("auth_pass_but_unaligned" in f for f in signal.flags), signal.flags
    assert any(f == "fully_authenticated" for f in signal.flags), signal.flags
    assert signal.metadata["auth_alignment"]["aligned"] is True


def test_alignment_unverifiable_no_penalty():
    """spf/dkim pass but no d=/mailfrom/Return-Path to check — inform, don't punish."""
    headers = {
        "From": "someone@example.com",
        "Authentication-Results": "spf=pass dkim=pass dmarc=none",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert "alignment_unverifiable" in signal.flags, signal.flags
    assert not any("auth_pass_but_unaligned" in f for f in signal.flags), signal.flags
    assert signal.raw_score < 15  # only the mild dmarc=none penalty


def test_graduated_auth_scoring():
    """Explicit fail scores strictly higher than softfail, which beats absent."""
    def score(spf_val):
        h = {"From": "a@b.com"}
        if spf_val is not None:
            h["Authentication-Results"] = f"spf={spf_val} dkim=pass dmarc=pass"
        else:
            h["Authentication-Results"] = "dkim=pass dmarc=pass"
        return HeaderAnalyzer().analyse(h, weight=0.25).raw_score

    assert score("fail") > score("softfail") > score(None)


def test_homoglyph_sender_domain_detected():
    """Cyrillic look-alike 'аmazon.com' (Cyrillic а) impersonating amazon."""
    headers = {
        "From": "support@аmazon.com",  # а = Cyrillic 'а'
        "Authentication-Results": "spf=pass dkim=pass dmarc=pass",
    }
    analyzer = HeaderAnalyzer()
    signal = analyzer.analyse(headers, weight=0.25)
    assert any("homoglyph_sender_domain" in f for f in signal.flags), \
        f"Expected homoglyph flag, got: {signal.flags}"
