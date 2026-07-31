"""
Severity Map Module

This module centralizes severity grading for detector flags emitted by various detectors.
It assumes that flags are strings composed of a stable prefix followed by dynamic data,
separated by a colon (':') or parenthesis ('('). For example:
"brand_impersonation:amazon(sender:evil.com,expected:amazon.com)" or "urgency_language(3)".

The module maps these stable prefixes to a severity level (Critical, High, Medium, Low)
to allow building a severity-graded issues list per email instead of relying only on a combined score.
"""

import re

CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"

_ML_HIGH_CONFIDENCE_THRESHOLD = 0.85

EXCLUDED_FLAGS = {
    "fully_authenticated",
    "alignment_unverifiable",
}

SEVERITY_MAP: dict[str, str] = {
    "brand_impersonation": CRITICAL,
    "homoglyph_sender_domain": CRITICAL,
    "body_brand_mention": CRITICAL,
    "brand_impersonation_confirmed": CRITICAL,
    "homoglyph_lookalike": CRITICAL,
    "suspicious_form_action": CRITICAL,
    "blocklist_hit": CRITICAL,
    "dangerous_extension": CRITICAL,
    "double_extension": CRITICAL,
    "brand_url_mismatch": CRITICAL,
    "dnstwist_brand_match": CRITICAL,
    "dnstwist_match_newly_registered": CRITICAL,
    "anchor_brand_mismatch": CRITICAL,
    "anchor_text_href_mismatch": CRITICAL,
    
    "auth_pass_but_unaligned": HIGH,
    "lookalike_sender_domain": HIGH,
    "exact_brand_display": HIGH,
    "spf_fail": HIGH,
    "dkim_fail": HIGH,
    "dmarc_fail": HIGH,
    "newly_registered": HIGH,
    "lookalike": HIGH,
    "credential_harvest_page": HIGH,
    "content_type_mismatch": HIGH,
    
    "lookalike_display": MEDIUM,
    "reply_to_mismatch": MEDIUM,
    "return_path_mismatch": MEDIUM,
    "authority_impersonation": MEDIUM,
    "credential_request": MEDIUM,
    "raw_ip_host": MEDIUM,
    "at_trick": MEDIUM,
    "excessive_subdomains": MEDIUM,
    "redirect_chain": MEDIUM,
    "macro_enabled_format": MEDIUM,
    
    "spf_softfail": LOW,
    "spf_none": LOW,
    "spf_neutral": LOW,
    "dkim_none": LOW,
    "dmarc_none": LOW,
    "spf_missing": LOW,
    "dkim_missing": LOW,
    "dmarc_missing": LOW,
    "urgency_language": LOW,
    "qr_codes_found": LOW,
    "suspicious_tld": LOW,
    "url_shortener": LOW,
    "archive_attachment": LOW,
}

_PREFIX_REGEX = re.compile(r"^([a-zA-Z_]+)")
_ML_CONF_REGEX = re.compile(r"ml_phishing\(conf=([0-9.]+)\)")

_QR_PREFIX = "qr>"


def _strip_qr_prefix(flag: str) -> str:
    """QRCodeDetector re-emits the URL analyzer's flags prefixed with 'qr>'.
    Every consumer of a flag string has to unwrap that before matching.

    Shared deliberately: this used to be inlined in get_flag_severity only,
    so describe_flag silently fell through to its raw-flag fallback for every
    QR-embedded URL — graded correctly, but shown to the analyst as
    'qr>brand_impersonation:paypal(...)'.
    """
    return flag[len(_QR_PREFIX):] if flag.startswith(_QR_PREFIX) else flag


def get_flag_severity(flag: str) -> str | None:
    """
    Extract the stable prefix from a flag string and return its severity level.
    Returns None for excluded flags or unmapped flags.
    """
    flag = _strip_qr_prefix(flag)

    if flag.startswith("ml_phishing"):
        match = _ML_CONF_REGEX.search(flag)
        if match:
            try:
                conf = float(match.group(1))
                if conf >= _ML_HIGH_CONFIDENCE_THRESHOLD:
                    return HIGH
                return MEDIUM
            except ValueError:
                pass
        return HIGH
        
    match = _PREFIX_REGEX.match(flag)
    if not match:
        return None
        
    prefix = match.group(1)
    
    if prefix in EXCLUDED_FLAGS:
        return None
        
    return SEVERITY_MAP.get(prefix)

def describe_flag(flag: str) -> str:
    """Generate a human-readable description for a flag."""
    # Match on the unwrapped flag, but fall back to the *original* so an
    # unmapped QR flag keeps its 'qr>' provenance in the analyst-facing text.
    original = flag
    flag = _strip_qr_prefix(flag)

    if flag.startswith("brand_impersonation:"):
        m = re.match(r"brand_impersonation:([^()]+)\(sender:([^,]+),expected:([^)]+)\)", flag)
        if m:
            return f"Claims to be {m.group(1)}, but the sender domain is {m.group(2)} instead of the expected {m.group(3)}."
            
    if flag.startswith("homoglyph_sender_domain:"):
        m = re.match(r"homoglyph_sender_domain:(.+)~=(.+)", flag)
        if m:
            return f"Sender domain {m.group(1)} uses look-alike characters to impersonate {m.group(2)}."
            
    if flag.startswith("dnstwist_brand_match:"):
        m = re.match(r"dnstwist_brand_match:([^()]+)\(type:([^)]+)\)", flag)
        if m:
            return f"Sender domain is a {m.group(2)}-style look-alike of {m.group(1)}, detected via automated domain analysis."
            
    if flag.startswith("dnstwist_match_newly_registered:"):
        brand = flag.split(":", 1)[1]
        return f"Sender domain is a look-alike of {brand} AND was registered very recently — a strong combined signal of a fresh phishing setup."
        
    if flag.startswith("auth_pass_but_unaligned:"):
        m = re.match(r"auth_pass_but_unaligned:(.+)!=(.+)", flag)
        if m:
            return f"Email authentication (SPF/DKIM) passed, but for a different domain ({m.group(1)}) than the sender's claimed domain ({m.group(2)}) — a spoofing technique that basic checks miss."
            
    if flag.startswith("lookalike_sender_domain:"):
        m = re.match(r"lookalike_sender_domain:([^~]+)~=([^()]+)", flag)
        if m:
            return f"Sender domain {m.group(1)} closely resembles {m.group(2)}."
            
    if flag.startswith("exact_brand_display:"):
        m = re.match(r"exact_brand_display:(.+)==(.+)", flag)
        if m:
            return f"Display name exactly matches the brand '{m.group(2)}', but this alone doesn't confirm the sender is legitimate."
            
    if flag.startswith("reply_to_mismatch:"):
        m = re.match(r"reply_to_mismatch:(.+)!=(.+)", flag)
        if m:
            return f"Reply-To address ({m.group(1)}) differs from the sender's domain ({m.group(2)})."
            
    if flag.startswith("return_path_mismatch:"):
        m = re.match(r"return_path_mismatch:(.+)!=(.+)", flag)
        if m:
            return f"Return-Path (bounce address) domain ({m.group(1)}) differs from the sender's domain ({m.group(2)})."
            
    if flag.startswith("lookalike_display:"):
        m = re.match(r"lookalike_display:([^~]+)~=([^()]+)", flag)
        if m:
            return f"Display name '{m.group(1)}' closely resembles the brand '{m.group(2)}'."
            
    if flag in ("spf_fail", "dkim_fail", "dmarc_fail"):
        auth_type = flag.split("_")[0].upper()
        return f"{auth_type} authentication explicitly failed — a strong indicator the sender's domain isn't genuine."
        
    if flag in ("spf_missing", "dkim_missing", "dmarc_missing", "spf_none", "dkim_none", "dmarc_none", "spf_softfail", "spf_neutral"):
        auth_type = flag.split("_")[0].upper()
        return f"{auth_type} authentication is missing or inconclusive — weak on its own, but worth noting."

    return original
