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
from app.detectors.domain_intel import (
    extract_domain,
    registered_domain,
    normalize_for_homoglyph,
)
from app.detectors.brand_intel import check_domain_against_brands
from app.detectors.nrd_feed import is_newly_registered_domain

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


def _extract_dkim_domain(headers: dict[str, str]) -> Optional[str]:
    """The domain a passing DKIM signature authenticated (the `d=` / header.d=
    value in Authentication-Results). None when absent.
    """
    auth = headers.get("Authentication-Results", "")
    m = re.search(r"header\.d=([A-Za-z0-9.\-]+)", auth, re.IGNORECASE)
    if not m:
        m = re.search(r"\bd=([A-Za-z0-9.\-]+)", auth, re.IGNORECASE)
    return m.group(1).lower() if m else None


def _extract_spf_domain(headers: dict[str, str]) -> Optional[str]:
    """The domain SPF authenticated (envelope-from / Return-Path). None when
    undeterminable. Priority: smtp.mailfrom= in Authentication-Results →
    Return-Path header → 'domain of X' phrase in Received-SPF.
    """
    auth = headers.get("Authentication-Results", "")
    m = re.search(r"smtp\.mailfrom=([A-Za-z0-9.@\-]+)", auth, re.IGNORECASE)
    if m:
        return extract_domain(m.group(1))

    return_path = headers.get("Return-Path", "")
    if return_path:
        dom = extract_domain(return_path.strip().strip("<>"))
        if dom:
            return dom

    received_spf = headers.get("Received-SPF", "")
    m = re.search(r"domain of\s+([A-Za-z0-9.@\-]+)", received_spf, re.IGNORECASE)
    if m:
        return extract_domain(m.group(1))
    return None


class HeaderAnalyzer:
    """
    Analyses email headers and returns a Signal with a raw_score 0–100.
    Each sub-check contributes a fixed amount; flags document what fired.
    """

    # Graduated auth penalties — explicit reject > inconclusive > couldn't-check.
    # `pass` scores 0; unknown non-pass values fall back to the inconclusive bucket.
    _SPF_PENALTY = {"fail": 20, "softfail": 12, "none": 8, "neutral": 8, None: 4}
    _DKIM_PENALTY = {"fail": 20, "none": 8, None: 4}
    _DMARC_PENALTY = {"fail": 15, "none": 8, None: 4}

    # A green SPF/DKIM that authenticated a DIFFERENT domain than From — the
    # spoof that "reads a word" checks miss entirely.
    _AUTH_UNALIGNED = 30

    _REPLY_TO_MISMATCH = 20
    _LOOKALIKE_DISPLAY = 25
    _EXACT_BRAND_IMPERSONATION = 30
    _BRAND_IMPERSONATION_MISMATCH = 35

    @classmethod
    def _auth_penalty(cls, result: Optional[str], table: dict) -> float:
        """Graduated penalty for an auth result. `pass` -> 0; known bad/uncertain
        values use the table; unknown non-pass values -> inconclusive bucket."""
        if result == "pass":
            return 0.0
        if result in table:
            return table[result]
        return table.get("none", 8)

    def analyse(self, headers: dict[str, str], weight: float) -> Signal:
        score = 0.0
        flags: list[str] = []
        meta: dict = {}

        from_header = headers.get("From", "")
        reply_to = headers.get("Reply-To", "")
        display_name, sender_email = _parse_display_name(from_header)
        sender_domain = extract_domain(sender_email)

        # ── SPF / DKIM / DMARC — graduated (fail > inconclusive > absent) ────
        spf = _spf_result(headers)
        meta["spf"] = spf
        if spf != "pass":
            score += self._auth_penalty(spf, self._SPF_PENALTY)
            flags.append(f"spf_{spf or 'missing'}")

        dkim = _dkim_result(headers)
        meta["dkim"] = dkim
        if dkim != "pass":
            score += self._auth_penalty(dkim, self._DKIM_PENALTY)
            flags.append(f"dkim_{dkim or 'missing'}")

        dmarc = _dmarc_result(headers)
        meta["dmarc"] = dmarc
        if dmarc != "pass":
            score += self._auth_penalty(dmarc, self._DMARC_PENALTY)
            flags.append(f"dmarc_{dmarc or 'missing'}")

        # ── Alignment — does a PASSING auth actually cover the From domain? ───
        # DMARC pass inherently means aligned. Otherwise, extract the domains SPF
        # and DKIM authenticated and compare (relaxed / eTLD+1) against From.
        from_reg = registered_domain(sender_domain)
        dkim_domain = _extract_dkim_domain(headers)
        spf_domain = _extract_spf_domain(headers)
        dkim_aligned = (
            dkim == "pass" and dkim_domain is not None
            and registered_domain(dkim_domain) == from_reg
        )
        spf_aligned = (
            spf == "pass" and spf_domain is not None
            and registered_domain(spf_domain) == from_reg
        )
        auth_passed = spf == "pass" or dkim == "pass"
        auth_domain_known = bool(
            (dkim == "pass" and dkim_domain) or (spf == "pass" and spf_domain)
        )

        if dmarc == "pass" or dkim_aligned or spf_aligned:
            # Verified as genuinely from the From domain — a positive trust marker.
            flags.append("fully_authenticated")
            meta["auth_alignment"] = {"aligned": True, "from_domain": from_reg}
        elif auth_passed and auth_domain_known:
            auth_domains = ",".join(
                d for d in (
                    dkim_domain if dkim == "pass" else None,
                    spf_domain if spf == "pass" else None,
                ) if d
            )
            score += self._AUTH_UNALIGNED
            flags.append(f"auth_pass_but_unaligned:{auth_domains}!={from_reg}")
            meta["auth_alignment"] = {
                "aligned": False, "auth_domains": auth_domains, "from_domain": from_reg,
            }
        elif auth_passed:
            # Passed, but we couldn't determine what it authenticated — inform, don't penalize.
            flags.append("alignment_unverifiable")
            meta["auth_alignment"] = {"aligned": None, "from_domain": from_reg}

        # ── Reply-To mismatch ────────────────────────────────────────────────
        # Compare organisational domains, not exact hosts: 'support@help.example.com'
        # replying for 'alice@example.com' is ordinary mail flow, not a mismatch.
        if reply_to:
            reply_domain = extract_domain(reply_to)
            if reply_domain and registered_domain(reply_domain) != from_reg:
                score += self._REPLY_TO_MISMATCH
                flags.append(f"reply_to_mismatch:{reply_domain}!={sender_domain}")
                meta["reply_to_domain"] = reply_domain

        # ── Return-Path domain mismatch ─────────────────────────────────
        # A legitimate sender's bounce address (Return-Path) domain should match
        # the From domain. A mismatch here is a cross-header inconsistency that
        # existing checks (which only look at Reply-To, or SPF/DKIM alignment) miss.
        # Compared at the registered-domain level — ESPs routinely bounce via a
        # subdomain ('bounce@mailer.example.com'), which is not a mismatch.
        return_path = headers.get("Return-Path", "")
        if return_path:
            return_path_domain = extract_domain(return_path.strip().strip("<>"))
            if return_path_domain and registered_domain(return_path_domain) != from_reg:
                score += self._REPLY_TO_MISMATCH
                flags.append(f"return_path_mismatch:{return_path_domain}!={sender_domain}")
                meta["return_path_domain"] = return_path_domain

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

        # ── Homoglyph / punycode sender domain ───────────────────────────────
        # Cross-script look-alikes (Cyrillic/Greek) and punycode collapse to a
        # brand after normalization while the raw domain does not — pure spoof.
        if sender_domain:
            sender_norm = normalize_for_homoglyph(sender_domain)
            norm_root = re.split(r'[.\-]', sender_norm)[0]
            orig_root = re.split(r'[.\-]', sender_domain)[0].lower()
            if norm_root != orig_root:
                for brand in KNOWN_BRANDS:
                    if norm_root == brand:
                        score += self._LOOKALIKE_DISPLAY
                        flags.append(f"homoglyph_sender_domain:{sender_domain}~={brand}")
                        meta["homoglyph_domain"] = sender_domain
                        break

        # ── dnstwist brand impersonation check ──────────────────────────
        # Broader coverage than the Levenshtein/homoglyph checks above — catches
        # typosquat/homoglyph/combosquat permutations generated by dnstwist.
        if sender_domain:
            brand_match = check_domain_against_brands(sender_domain)
            if brand_match:
                score += self._LOOKALIKE_DISPLAY
                flags.append(
                    f"dnstwist_brand_match:{brand_match.matched_brand}"
                    f"(type:{brand_match.permutation_type})"
                )
                meta["dnstwist_brand_match"] = {
                    "matched_brand": brand_match.matched_brand,
                    "permutation_type": brand_match.permutation_type,
                    "matched_domain": brand_match.matched_domain,
                }
                if brand_match and is_newly_registered_domain(sender_domain):
                    score += self._BRAND_IMPERSONATION_MISMATCH
                    flags.append(f"dnstwist_match_newly_registered:{brand_match.matched_brand}")
                    meta["dnstwist_match_newly_registered"] = True

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
