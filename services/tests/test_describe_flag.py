from app.scoring.severity_map import describe_flag

def test_describe_flag_brand_impersonation():
    flag = "brand_impersonation:paypal(sender:evil.com,expected:paypal.com)"
    desc = describe_flag(flag)
    assert desc == "Claims to be paypal, but the sender domain is evil.com instead of the expected paypal.com."

def test_describe_flag_homoglyph_sender_domain():
    flag = "homoglyph_sender_domain:paypa1.com~=paypal"
    desc = describe_flag(flag)
    assert desc == "Sender domain paypa1.com uses look-alike characters to impersonate paypal."

def test_describe_flag_dnstwist_brand_match():
    flag = "dnstwist_brand_match:microsoft(type:insertion)"
    desc = describe_flag(flag)
    assert desc == "Sender domain is a insertion-style look-alike of microsoft, detected via automated domain analysis."

def test_describe_flag_dnstwist_match_newly_registered():
    flag = "dnstwist_match_newly_registered:apple"
    desc = describe_flag(flag)
    assert desc == "Sender domain is a look-alike of apple AND was registered very recently — a strong combined signal of a fresh phishing setup."

def test_describe_flag_auth_pass_but_unaligned():
    flag = "auth_pass_but_unaligned:mail.com!=bank.com"
    desc = describe_flag(flag)
    assert desc == "Email authentication (SPF/DKIM) passed, but for a different domain (mail.com) than the sender's claimed domain (bank.com) — a spoofing technique that basic checks miss."

def test_describe_flag_lookalike_sender_domain():
    flag_no_dist = "lookalike_sender_domain:amazn.com~=amazon"
    assert describe_flag(flag_no_dist) == "Sender domain amazn.com closely resembles amazon."
    
    flag_with_dist = "lookalike_sender_domain:amazn.com~=amazon(dist:1)"
    assert describe_flag(flag_with_dist) == "Sender domain amazn.com closely resembles amazon."

def test_describe_flag_exact_brand_display():
    flag = "exact_brand_display:Support Team==netflix"
    desc = describe_flag(flag)
    assert desc == "Display name exactly matches the brand 'netflix', but this alone doesn't confirm the sender is legitimate."

def test_describe_flag_reply_to_mismatch():
    flag = "reply_to_mismatch:hacker@evil.com!=admin@legit.com"
    desc = describe_flag(flag)
    assert desc == "Reply-To address (hacker@evil.com) differs from the sender's domain (admin@legit.com)."

def test_describe_flag_return_path_mismatch():
    flag = "return_path_mismatch:bounce@spammer.net!=service@company.com"
    desc = describe_flag(flag)
    assert desc == "Return-Path (bounce address) domain (bounce@spammer.net) differs from the sender's domain (service@company.com)."

def test_describe_flag_lookalike_display():
    flag_no_dist = "lookalike_display:Micros0ft~=microsoft"
    assert describe_flag(flag_no_dist) == "Display name 'Micros0ft' closely resembles the brand 'microsoft'."
    
    flag_with_dist = "lookalike_display:Micros0ft~=microsoft(dist:2)"
    assert describe_flag(flag_with_dist) == "Display name 'Micros0ft' closely resembles the brand 'microsoft'."

def test_describe_flag_explicit_fail():
    assert describe_flag("spf_fail") == "SPF authentication explicitly failed — a strong indicator the sender's domain isn't genuine."
    assert describe_flag("dkim_fail") == "DKIM authentication explicitly failed — a strong indicator the sender's domain isn't genuine."
    assert describe_flag("dmarc_fail") == "DMARC authentication explicitly failed — a strong indicator the sender's domain isn't genuine."

def test_describe_flag_inconclusive():
    assert describe_flag("spf_none") == "SPF authentication is missing or inconclusive — weak on its own, but worth noting."
    assert describe_flag("dkim_missing") == "DKIM authentication is missing or inconclusive — weak on its own, but worth noting."
    assert describe_flag("spf_softfail") == "SPF authentication is missing or inconclusive — weak on its own, but worth noting."

def test_describe_flag_fallback():
    flag = "unknown_detector_flag:some_data(123)"
    assert describe_flag(flag) == flag


def test_describe_flag_strips_qr_prefix():
    """QR-embedded URLs reuse the URL analyzer's flags with a 'qr>' prefix
    (see QRCodeDetector). get_flag_severity strips it before matching, so
    describe_flag must too — otherwise a quishing email is graded correctly
    but described to the analyst as a raw flag string."""
    assert describe_flag("qr>brand_impersonation:paypal(sender:evil.com,expected:paypal.com)") == (
        "Claims to be paypal, but the sender domain is evil.com "
        "instead of the expected paypal.com."
    )


def test_describe_flag_strips_qr_prefix_for_all_formats():
    """The prefix, not one lucky format — a second shape must work too."""
    assert describe_flag("qr>lookalike_sender_domain:paypa1.com~=paypal.com") == (
        "Sender domain paypa1.com closely resembles paypal.com."
    )
    assert describe_flag("qr>spf_fail") == (
        "SPF authentication explicitly failed — a strong indicator "
        "the sender's domain isn't genuine."
    )


def test_describe_flag_qr_prefix_unmapped_falls_back_to_raw():
    """An unmapped qr> flag still falls through to the raw-flag fallback."""
    assert describe_flag("qr>unknown_flag:data") == "qr>unknown_flag:data"
