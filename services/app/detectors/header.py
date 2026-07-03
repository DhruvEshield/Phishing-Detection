"""Header analysis detector.

Checks: SPF/DKIM/DMARC auth failures, reply-to mismatch,
sender routing anomaly, lookalike display-name (Levenshtein).
"""
from __future__ import annotations

import re
from typing import Optional
from Levenshtein import distance as levenshtein_distance
import structlog

from app.detectors.base import Signal
from app.detectors.domain_intel import extract_domain

log = structlog.get_logger()

# Known-good display name fragments to check against (configurable allowlist)
KNOWN_BRANDS = [
    "microsoft", "google", "amazon", "apple", "paypal", "dropbox",
    "linkedin", "facebook", "twitter", "netflix", "docusign",
]

BRAND_DOMAINS: dict[str, str] = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "dropbox": "dropbox.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "twitter": "twitter.com",
    "netflix": "netflix.com",
    "docusign": "docusign.com",
}


def _parse_display_name(from_header: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a From header."""
    m = re.match(r'"?([^"<>]+)"?\s*<([^>]+)>', from_header)
    if m:
        return m.group(1).strip().lower(), m.group(2).strip().lower()
    return "", from_header.strip().lower()


def _spf_result(headers: dict[str, str]) -> Optional[str]:
    """Extract SPF result from Received-SPF or Authentication-Results headers.
    Received-SPF format: 'pass (google.com: ...)' — result is the first word.
    Authentication-Results format: 'spf=pass ...'
    """
    received_spf = headers.get("Received-SPF", "")
    if received_spf:
        m = re.match(r"(\w+)", received_spf.strip(), re.IGNORECASE)
        if m:
            return m.group(1).lower()
    auth = headers.get("Authentication-Results", "")
    m = re.search(r"spf=(\w+)", auth, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return None


def _dkim_result(headers: dict[str, str]) -> Optional[str]:
    auth = headers.get("Authentication-Results", "")
    m = re.search(r"dkim=(\w+)", auth, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _dmarc_result(headers: dict[str, str]) -> Optional[str]:
    auth = headers.get("Authentication-Results", "")
    m = re.search(r"dmarc=(\w+)", auth, re.IGNORECASE)
    return m.group(1).lower() if m else None


class HeaderAnalyzer:
    """
    Analyses email headers and returns a Signal with a raw_score 0–100.
    Each sub-check contributes a fixed amount; flags document what fired.
    """

    # Sub-check contributions (sum of all = 100 worst-case)
    _SPF_FAIL = 20
    _DKIM_FAIL = 20
    _DMARC_FAIL = 15
    _REPLY_TO_MISMATCH = 20
    _LOOKALIKE_DISPLAY = 25
    _EXACT_BRAND_IMPERSONATION = 30
    _BRAND_IMPERSONATION_MISMATCH = 35

    def analyse(self, headers: dict[str, str], weight: float) -> Signal:
        score = 0.0
        flags: list[str] = []
        meta: dict = {}

        from_header = headers.get("From", "")
        reply_to = headers.get("Reply-To", "")
        display_name, sender_email = _parse_display_name(from_header)
        sender_domain = extract_domain(sender_email)

        # ── SPF ──────────────────────────────────────────────────────────────
        spf = _spf_result(headers)
        meta["spf"] = spf
        if spf in ("fail", "softfail", "none", None):
            score += self._SPF_FAIL
            flags.append(f"spf_{spf or 'missing'}")

        # ── DKIM ─────────────────────────────────────────────────────────────
        dkim = _dkim_result(headers)
        meta["dkim"] = dkim
        if dkim in ("fail", "none", None):
            score += self._DKIM_FAIL
            flags.append(f"dkim_{dkim or 'missing'}")

        # ── DMARC ────────────────────────────────────────────────────────────
        dmarc = _dmarc_result(headers)
        meta["dmarc"] = dmarc
        if dmarc in ("fail", "none", None):
            score += self._DMARC_FAIL
            flags.append(f"dmarc_{dmarc or 'missing'}")

        # ── Reply-To mismatch ────────────────────────────────────────────────
        if reply_to:
            reply_domain = extract_domain(reply_to)
            if reply_domain and reply_domain != sender_domain:
                score += self._REPLY_TO_MISMATCH
                flags.append(f"reply_to_mismatch:{reply_domain}!={sender_domain}")
                meta["reply_to_domain"] = reply_domain

        # ── Lookalike display name ───────────────────────────────────────────
        if display_name:
            for word in display_name.split():
                for brand in KNOWN_BRANDS:
                    dist = levenshtein_distance(word, brand)
                    if 0 <= dist <= 2:
                        if dist == 0:
                            score += self._EXACT_BRAND_IMPERSONATION
                            flags.append(f"exact_brand_display:{word}=={brand}")
                        else:
                            score += self._LOOKALIKE_DISPLAY
                            flags.append(f"lookalike_display:{word}~={brand}(dist={dist})")
                        meta["lookalike_brand"] = brand
                        break
                else:
                    continue
                break

        # ── Lookalike sender domain ──────────────────────────────────────────
        if sender_domain:
            sender_root = re.split(r'[.\-]', sender_domain)[0]
            for brand in KNOWN_BRANDS:
                dist = levenshtein_distance(sender_root, brand)
                if 0 < dist <= 2:
                    score += self._LOOKALIKE_DISPLAY
                    flags.append(f"lookalike_sender_domain:{sender_domain}~={brand}(dist={dist})")
                    meta["lookalike_domain"] = sender_domain
                    break

        # ── Brand impersonation — display name claims brand but sender domain doesn't match ───
        if display_name and sender_domain:
            for word in display_name.lower().split():
                if word in BRAND_DOMAINS:
                    expected_domain = BRAND_DOMAINS[word]
                    if not sender_domain.endswith(expected_domain):
                        score += self._BRAND_IMPERSONATION_MISMATCH
                        flags.append(
                            f"brand_impersonation:{word}(sender:{sender_domain},expected:{expected_domain})"
                        )
                        meta["brand_impersonation"] = {
                            "claimed_brand": word,
                            "sender_domain": sender_domain,
                            "expected_domain": expected_domain,
                        }
                        break

        raw_score = min(score, 100.0)
        log.info(
            "detector.header", score=raw_score, flags=flags,
            action="header_analysis", resource_id=sender_email,
        )
        return Signal(name="header", raw_score=raw_score, weight=weight,
                      flags=flags, metadata=meta)
