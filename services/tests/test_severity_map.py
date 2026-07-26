import pytest
from app.scoring.severity_map import (
    get_flag_severity,
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
)

def test_plain_flag_lookup():
    assert get_flag_severity("brand_impersonation:amazon(sender:evil.com,expected:amazon.com)") == CRITICAL
    assert get_flag_severity("brand_url_mismatch:amazon(links_not_going_to:amazon.com)") == CRITICAL
    assert get_flag_severity("dnstwist_brand_match:amazon(type:addition)") == CRITICAL
    assert get_flag_severity("dnstwist_match_newly_registered:amazon") == CRITICAL
    assert get_flag_severity("anchor_brand_mismatch:amazon(text_claims:amazon,href_domain:evil.com)") == CRITICAL
    assert get_flag_severity("anchor_text_href_mismatch:amazon.com!=evil.com") == CRITICAL
    assert get_flag_severity("return_path_mismatch:evil-domain.com!=legit-company.com") == MEDIUM
    assert get_flag_severity("urgency_language(3)") == LOW
    assert get_flag_severity("dkim_fail") == HIGH
    assert get_flag_severity("spf_missing") == LOW
    assert get_flag_severity("dkim_missing") == LOW
    assert get_flag_severity("dmarc_missing") == LOW

def test_qr_inherited_flag():
    assert get_flag_severity("qr>homoglyph_lookalike:evil.com") == CRITICAL
    assert get_flag_severity("qr>suspicious_tld:xyz") == LOW
    assert get_flag_severity("qr>brand_impersonation") == CRITICAL

def test_ml_phishing_high_confidence():
    assert get_flag_severity("ml_phishing(conf=0.92)") == HIGH
    assert get_flag_severity("ml_phishing(conf=0.85)") == HIGH

def test_ml_phishing_low_confidence():
    assert get_flag_severity("ml_phishing(conf=0.84)") == MEDIUM
    assert get_flag_severity("ml_phishing(conf=0.10)") == MEDIUM
    
def test_ml_phishing_no_confidence_defaults_to_high():
    assert get_flag_severity("ml_phishing") == HIGH

def test_excluded_flag():
    assert get_flag_severity("fully_authenticated") is None
    assert get_flag_severity("alignment_unverifiable(reason)") is None

def test_unmapped_unknown_flag():
    assert get_flag_severity("unknown_new_detector_flag:data") is None
    assert get_flag_severity("qr>unknown_flag") is None
