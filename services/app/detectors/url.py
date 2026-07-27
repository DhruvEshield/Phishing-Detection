"""URL analysis detector.

Checks: domain age (via RDAP), redirect chains, lookalike domains,
credential-harvest page heuristics.
Sandbox detonation is Phase 2 — stubbed via SandboxProvider interface.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Optional
import structlog
import httpx
import ipaddress
import tldextract
from Levenshtein import distance as levenshtein_distance

from app.detectors.base import Signal
from app.detectors.domain_intel import (
    get_domain_intel,
    extract_domain,
    ssrf_guard,
    normalize_for_homoglyph,
    domain_matches,
)
from app.detectors.brand_intel import check_domain_against_brands
from app.detectors.nrd_feed import is_newly_registered_domain
from app.config import get_settings

log = structlog.get_logger()

# ── Vendor allowlist for lookalike detection ───────────────────────────────────
VENDOR_DOMAINS = [
    "microsoft.com", "google.com", "amazon.com", "apple.com",
    "paypal.com", "dropbox.com", "linkedin.com", "facebook.com",
    "twitter.com", "netflix.com", "docusign.com", "zoom.us",
    "slack.com", "github.com", "salesforce.com",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".top", ".xyz", ".zip", ".mov",
    ".click", ".link", ".work",
}

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
}

_URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


def _extract_anchor_pairs(body_html: str) -> list[dict]:
    """Extract <a href="...">text</a> pairs for anchor-text-vs-href mismatch detection.
    Step 1: Extraction only (no comparison/flagging logic).
    """
    pairs = []
    try:
        # Match <a> tags with href attributes and capture their inner content.
        anchor_regex = re.compile(r'<a\s+[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        tag_stripper = re.compile(r'<[^>]+>')
        
        matches = anchor_regex.findall(body_html)
        for href, inner_html in matches[:20]:
            # Strip nested tags like <b> or <span>
            anchor_text = tag_stripper.sub('', inner_html)
            # Normalize whitespace
            anchor_text = " ".join(anchor_text.split()).strip()
            
            if anchor_text:
                pairs.append({"href": href, "anchor_text": anchor_text})
                
    except Exception as exc:
        log.warning("url.extract_anchor_pairs_error", error=str(exc))
        
    return pairs


def _check_anchor_mismatch(pairs: list[dict]) -> list[str]:
    """Check extracted anchor pairs for anchor-text-vs-href mismatches.
    Step 2: Takes extracted pairs and returns suspicion flags.
    No HTML parsing here.
    """
    from app.detectors.header import BRAND_DOMAINS
    flags = []
    try:
        domain_shape_re = re.compile(r'([a-z0-9-]+\.[a-z]{2,})')
        
        for pair in pairs:
            anchor_text = pair.get("anchor_text", "").lower()
            href = pair.get("href", "")
            if not anchor_text or not href:
                continue
                
            href_domain = extract_domain(href)
            if not href_domain:
                continue
                
            # Case A: anchor text names a brand, href doesn't match
            for brand, expected_domain in BRAND_DOMAINS.items():
                if re.search(rf'\b{re.escape(brand)}\b', anchor_text):
                    if not domain_matches(href_domain, expected_domain):
                        flags.append(f"anchor_brand_mismatch:{brand}(text_claims:{brand},href_domain:{href_domain})")
                    
            # Case B: anchor text itself looks like a URL/domain
            domain_match = domain_shape_re.search(anchor_text)
            if domain_match:
                text_domain = extract_domain(domain_match.group(1))
                if text_domain and text_domain != href_domain:
                    flags.append(f"anchor_text_href_mismatch:{text_domain}!={href_domain}")
                    
    except Exception as exc:
        log.warning("url.check_anchor_mismatch_error", error=str(exc))
        
    return flags


def _extract_urls(body_text: str, body_html: str) -> list[str]:
    return list(set(_URL_PATTERN.findall(body_text + " " + body_html)))


def _is_lookalike(domain: str, threshold: int = 3) -> Optional[str]:
    """Return the matched vendor if domain looks like one, else None."""
    ext = tldextract.extract(domain)
    registered = f"{ext.domain}.{ext.suffix}"
    for vendor in VENDOR_DOMAINS:
        if registered == vendor:
            return None  # exact match — not a lookalike
        vext = tldextract.extract(vendor)
        v_registered = f"{vext.domain}.{vext.suffix}"
        dist = levenshtein_distance(registered, v_registered)
        if 0 < dist <= threshold:
            return vendor
    return None


def _follow_redirects(url: str, max_hops: int, timeout: float) -> tuple[str, list[str]]:
    """Follow redirect chain; return (final_url, hop_list). SSRF-guarded at each hop."""
    chain = [url]
    current = url
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            for _ in range(max_hops):
                parsed_host = current.split("/")[2] if "://" in current else current
                try:
                    ssrf_guard(parsed_host)
                except ValueError:
                    chain.append("SSRF_BLOCKED")
                    break
                resp = client.get(current)
                if resp.is_redirect:
                    loc = resp.headers.get("location", "")
                    if loc:
                        chain.append(loc)
                        current = loc
                    else:
                        break
                else:
                    break
    except Exception:
        pass
    return current, chain


def _credential_harvest_heuristic(url: str) -> bool:
    """Simple heuristic: non-HTTPS + 'login'/'verify'/'signin' in path."""
    if not url.startswith("https://"):
        path = url.lower()
        return any(k in path for k in ("login", "verify", "signin", "account", "credential"))
    return False


def _inspect_form_action(url: str, timeout: float = 5.0) -> Optional[str]:
    """Fetch page HTML and check if any form submits to a different domain.
    Only called for URLs that already look suspicious.
    Returns suspicious form action URL if found, None otherwise.
    """
    try:
        ssrf_guard(extract_domain(url))
        resp = httpx.get(
            url, timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        html = resp.text
        actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for action in actions:
            if action.startswith("http") or action.startswith("//"):
                action_domain = extract_domain(action)
                url_domain = extract_domain(url)
                if action_domain and url_domain and action_domain != url_domain:
                    return action
    except Exception:
        pass
    return None


def _url_structure_red_flags(url: str) -> list[str]:
    """Check for common URL structure tricks used in phishing.
    Returns list of flags for any red flags found.
    """
    flags = []
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Raw IP as host — legitimate companies never use raw IPs in emails
        try:
            ipaddress.ip_address(hostname)
            flags.append(f"raw_ip_host:{hostname}")
        except ValueError:
            pass

        # @ trick — everything before @ is a fake username, real destination is after
        if "@" in (parsed.netloc or ""):
            flags.append(f"at_trick:{url[:80]}")

        # Excessive subdomains — real domain buried under many subdomains
        parts = [p for p in hostname.split(".") if p]
        if len(parts) > 4:
            flags.append(f"excessive_subdomains({len(parts)}):{hostname}")

    except Exception:
        pass
    return flags


def _tld_and_shortener_flags(url: str) -> list[str]:
    """Check for suspicious TLDs and known URL shortener domains.
    Returns list of flags for any red flags found.
    """
    flags = []
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                flags.append(f"suspicious_tld:{hostname}")
                break

        if hostname in URL_SHORTENER_DOMAINS:
            flags.append(f"url_shortener:{hostname}")

    except Exception:
        pass
    return flags


def _is_homoglyph_lookalike(domain: str) -> Optional[str]:
    """Check if domain uses homoglyphs or punycode to impersonate a known brand."""
    from app.detectors.header import KNOWN_BRANDS
    normalized = normalize_for_homoglyph(domain)
    domain_root = re.split(r'[.\-]', normalized)[0]
    for brand in KNOWN_BRANDS:
        dist = levenshtein_distance(domain_root, brand)
        if 0 < dist <= 2:
            return brand
        # Also check if normalized root exactly matches brand (pure homoglyph)
        if domain_root == brand and domain_root != domain.split('.')[0].lower():
            return brand
    return None


class SandboxProvider:
    """
    Phase 2 stub. Raises NotImplementedError so callers know it's not built yet.
    Swap in a real sandbox adapter in Phase 2 without changing URLAnalyzer.
    """
    def detonate(self, url: str) -> dict:
        raise NotImplementedError(
            "Sandbox detonation is Phase 2 — stub only. "
            "Implement a concrete SandboxProvider and inject it."
        )


class URLAnalyzer:
    def __init__(self, sandbox: Optional[SandboxProvider] = None):
        self._sandbox = sandbox  # None = Phase 1 (no detonation)
        s = get_settings()
        self._timeout = s.http_probe_timeout
        self._max_hops = s.max_redirect_hops

    def analyse(self, body_text: str, body_html: str, weight: float) -> Signal:
        flags: list[str] = []
        meta: dict = {}
        score = 0.0

        urls = _extract_urls(body_text, body_html)
        meta["url_count"] = len(urls)
        suspicious_urls = []

        anchor_pairs = _extract_anchor_pairs(body_html)
        anchor_mismatch_flags = _check_anchor_mismatch(anchor_pairs)
        meta["anchor_pairs_checked"] = len(anchor_pairs)
        if anchor_mismatch_flags:
            flags.extend(anchor_mismatch_flags)
            score += 25 * len(anchor_mismatch_flags)

        domain_cache: dict[str, object] = {}
        for url in urls[:10]:  # cap at 10 to bound latency
            domain = extract_domain(url)
            url_flags: list[str] = []
            
            if domain in domain_cache:
                intel = domain_cache[domain]
            else:
                intel = get_domain_intel(domain, timeout=get_settings().rdap_timeout)
                domain_cache[domain] = intel
            if intel.is_newly_registered:
                url_flags.append(f"newly_registered:{domain}")
                score += 20

            # Lookalike
            matched = _is_lookalike(domain)
            if matched:
                url_flags.append(f"lookalike:{domain}~={matched}")
                score += 25

            # ── Homoglyph/punycode check ──────────────────────────────
            homoglyph_brand = _is_homoglyph_lookalike(domain)
            if homoglyph_brand and not _is_lookalike(domain):
                score += 25
                url_flags.append(f"homoglyph_lookalike:{domain}~={homoglyph_brand}")

            # ── dnstwist brand impersonation check ──────────────────────────
            # Broader coverage than the Levenshtein/homoglyph checks above — catches
            # typosquat/homoglyph/combosquat permutations generated by dnstwist.
            brand_match = check_domain_against_brands(domain)
            if brand_match:
                score += 25
                url_flags.append(
                    f"dnstwist_brand_match:{brand_match.matched_brand}"
                    f"(type:{brand_match.permutation_type})"
                )
                if brand_match and is_newly_registered_domain(domain):
                    score += 35
                    url_flags.append(f"dnstwist_match_newly_registered:{brand_match.matched_brand}")

            # ── URL structure red flags ────────────────────────────────────
            structure_flags = _url_structure_red_flags(url)
            if structure_flags:
                url_flags.extend(structure_flags)
                score += 15 * len(structure_flags)

            # ── TLD and shortener red flags ────────────────────────────────
            tld_flags = _tld_and_shortener_flags(url)
            if tld_flags:
                url_flags.extend(tld_flags)
                score += 10 * len(tld_flags)

            # Redirect chain
            final_url, chain = _follow_redirects(url, self._max_hops, self._timeout)
            if len(chain) > 2:
                url_flags.append(f"redirect_chain({len(chain)}hops)")
                score += 10
            # Store final redirect URL for threat intel handoff
            if final_url != url:
                meta.setdefault("redirect_final_urls", []).append(final_url)

            # Credential harvest heuristic
            if _credential_harvest_heuristic(final_url):
                url_flags.append(f"credential_harvest_page:{final_url[:80]}")
                score += 20

            # ── Form action inspection (only for already-suspicious URLs) ──
            if url_flags:
                suspicious_action = _inspect_form_action(final_url, timeout=self._timeout)
                if suspicious_action:
                    url_flags.append(f"suspicious_form_action:{suspicious_action[:80]}")
                    score += 25

            if url_flags:
                suspicious_urls.append({"url": url[:200], "flags": url_flags})
                flags.extend(url_flags)

        meta["suspicious_urls"] = suspicious_urls

        raw_score = min(score, 100.0)
        log.info("detector.url", score=raw_score, url_count=len(urls),
                 action="url_analysis")
        return Signal(name="url", raw_score=raw_score, weight=weight,
                      flags=flags, metadata=meta)
