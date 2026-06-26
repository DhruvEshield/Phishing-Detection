"""URL analysis detector.

Checks: domain age (via RDAP), redirect chains, lookalike domains,
credential-harvest page heuristics.
Sandbox detonation is Phase 2 — stubbed via SandboxProvider interface.
"""
from __future__ import annotations

import re
from typing import Optional
import structlog
import httpx
import tldextract
from Levenshtein import distance as levenshtein_distance

from app.detectors.base import Signal
from app.detectors.domain_intel import get_domain_intel, extract_domain, ssrf_guard
from app.config import get_settings

log = structlog.get_logger()

# ── Vendor allowlist for lookalike detection ───────────────────────────────────
VENDOR_DOMAINS = [
    "microsoft.com", "google.com", "amazon.com", "apple.com",
    "paypal.com", "dropbox.com", "linkedin.com", "facebook.com",
    "twitter.com", "netflix.com", "docusign.com", "zoom.us",
    "slack.com", "github.com", "salesforce.com",
]

_URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


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

        for url in urls[:10]:  # cap at 10 to bound latency
            domain = extract_domain(url)
            url_flags: list[str] = []

            # Domain age via RDAP
            intel = get_domain_intel(domain, timeout=get_settings().rdap_timeout)
            if intel.is_newly_registered:
                url_flags.append(f"newly_registered:{domain}")
                score += 20

            # Lookalike
            matched = _is_lookalike(domain)
            if matched:
                url_flags.append(f"lookalike:{domain}~={matched}")
                score += 25

            # Redirect chain
            final_url, chain = _follow_redirects(url, self._max_hops, self._timeout)
            if len(chain) > 2:
                url_flags.append(f"redirect_chain({len(chain)}hops)")
                score += 10

            # Credential harvest heuristic
            if _credential_harvest_heuristic(final_url):
                url_flags.append(f"credential_harvest_page:{final_url[:80]}")
                score += 20

            if url_flags:
                suspicious_urls.append({"url": url[:200], "flags": url_flags})
                flags.extend(url_flags)

        meta["suspicious_urls"] = suspicious_urls

        raw_score = min(score, 100.0)
        log.info("detector.url", score=raw_score, url_count=len(urls),
                 action="url_analysis")
        return Signal(name="url", raw_score=raw_score, weight=weight,
                      flags=flags, metadata=meta)
