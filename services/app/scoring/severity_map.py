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

def get_flag_severity(flag: str) -> str | None:
    """
    Extract the stable prefix from a flag string and return its severity level.
    Returns None for excluded flags or unmapped flags.
    """
    if flag.startswith("qr>"):
        flag = flag[3:]
        
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
