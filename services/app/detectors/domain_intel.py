"""Domain intelligence module — RDAP + DNS analysis with SSRF guard.

Replaces python-whois per phishskill-integration.md §1:
  - RDAP (not raw whois) for domain age
  - One self-protecting parser per signal
  - Mandatory SSRF guard before any outbound probe
  - Single structured DomainIntel output object per domain
"""
from __future__ import annotations

import ipaddress
import socket
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog
import json
import redis
import tldextract

log = structlog.get_logger()


def registered_domain(domain: str) -> str:
    """Return the registrable domain (eTLD+1) for *domain*, e.g.
    'email.amazon.co.uk' -> 'amazon.co.uk'. Falls back to the input, lowercased,
    when extraction yields nothing (bare hostnames, malformed input).
    """
    if not domain:
        return ""
    ext = tldextract.extract(domain)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return domain.strip().lower()


def domain_matches(host: str, expected: str) -> bool:
    """True when *host* is exactly *expected* or a subdomain of it.

    A plain `host.endswith(expected)` is a detection bypass: 'evilamazon.com'
    ends with 'amazon.com', so a lookalike link would pass a brand check.
    Require a label boundary — either an exact match or a '.'-prefixed suffix.
    """
    if not host or not expected:
        return False
    host = host.strip().lower().rstrip(".")
    expected = expected.strip().lower().rstrip(".")
    return host == expected or host.endswith(f".{expected}")


# Common cross-script confusables used in IDN homograph attacks. NFKD does not
# map these to Latin (different scripts), so they need an explicit table.
_CONFUSABLES = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "к": "k", "н": "h", "в": "b", "т": "t",
    "м": "m", "ԁ": "d", "ɡ": "g",
    # Greek → Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v", "τ": "t", "υ": "u",
    "ι": "i", "κ": "k",
}


def normalize_for_homoglyph(domain: str) -> str:
    """Normalize a domain to expose homoglyph and punycode impersonation.
    Decodes punycode (xn--...) to unicode, maps common cross-script confusables
    (Cyrillic/Greek look-alikes) to Latin, then decomposes and strips combining
    marks so accented look-alikes collapse to their ASCII equivalents.
    """
    try:
        decoded = domain.encode("ascii").decode("idna")
    except Exception:
        decoded = domain
    decoded = decoded.lower()
    decoded = "".join(_CONFUSABLES.get(c, c) for c in decoded)
    normalized = unicodedata.normalize("NFKD", decoded)
    normalized = "".join(c for c in normalized if unicodedata.category(c) != "Mn")
    return normalized

# ── SSRF Guard ────────────────────────────────────────────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network(r) for r in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def ssrf_guard(hostname: str) -> None:
    """
    Resolve hostname and block if it maps to a private/loopback address.
    Raises ValueError on SSRF risk — callers must catch and treat as safe-fail.
    """
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        for net in _PRIVATE_NETWORKS:
            if ip in net:
                raise ValueError(
                    f"SSRF blocked: {hostname!r} resolves to private IP {ip_str}"
                )
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for {hostname!r}: {exc}") from exc


# ── RDAP domain age ───────────────────────────────────────────────────────────
RDAP_BOOTSTRAP = "https://rdap.iana.org/domain/"


@dataclass
class DomainIntel:
    domain: str
    age_days: Optional[int] = None          # None = could not determine
    registrar: Optional[str] = None
    is_newly_registered: bool = False       # age_days < 30
    rdap_error: Optional[str] = None
    spf_pass: Optional[bool] = None
    dmarc_record: Optional[str] = None
    mx_records: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


def get_domain_intel(domain: str, timeout: float = 5.0) -> DomainIntel:
    """
    Fetch RDAP data for *domain*. SSRF guard fires first.
    Results cached in Redis for 24 hours to avoid repeated slow lookups.
    Safe-fails: on any error returns DomainIntel with rdap_error set.
    """
    intel = DomainIntel(domain=domain)

    # ── SSRF guard ────────────────────────────────────────────────────────
    try:
        ssrf_guard(domain)
    except ValueError as exc:
        intel.rdap_error = str(exc)
        intel.flags.append("ssrf_blocked")
        log.warning("domain_intel.ssrf_blocked", domain=domain, reason=str(exc))
        return intel

    # ── Redis cache check ─────────────────────────────────────────────────
    cache_key = f"rdap:{domain}"
    try:
        r = _get_redis_client()
        cached = r.get(cache_key)
        if cached:
            data = json.loads(cached)
            intel.age_days = data.get("age_days")
            intel.registrar = data.get("registrar")
            intel.is_newly_registered = data.get("is_newly_registered", False)
            intel.flags = data.get("flags", [])
            log.info("domain_intel.cache_hit", domain=domain)
            return intel
    except Exception as exc:
        log.warning("domain_intel.redis_error", error=str(exc))

    # ── RDAP lookup ───────────────────────────────────────────────────────
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(f"{RDAP_BOOTSTRAP}{domain}")
            resp.raise_for_status()
            data = resp.json()

        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                raw_date = event.get("eventDate", "")
                try:
                    reg_dt = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - reg_dt).days
                    intel.age_days = age
                    if age < 30:
                        intel.is_newly_registered = True
                        intel.flags.append(f"newly_registered_{age}d")
                except (ValueError, TypeError):
                    pass

        intel.registrar = (data.get("entities") or [{}])[0].get("fn")

        # ── Cache result in Redis for 24 hours ────────────────────────────
        try:
            r = _get_redis_client()
            cache_data = {
                "age_days": intel.age_days,
                "registrar": intel.registrar,
                "is_newly_registered": intel.is_newly_registered,
                "flags": intel.flags,
            }
            r.setex(cache_key, 86400, json.dumps(cache_data))
            log.info("domain_intel.cached", domain=domain)
        except Exception as exc:
            log.warning("domain_intel.redis_cache_error", error=str(exc))

    except httpx.HTTPError as exc:
        intel.rdap_error = str(exc)
        log.warning("domain_intel.rdap_error", domain=domain, error=str(exc))

    # Cache result even on failure to avoid repeated slow lookups
    try:
        r = _get_redis_client()
        cache_data = {
            "age_days": intel.age_days,
            "registrar": intel.registrar,
            "is_newly_registered": intel.is_newly_registered,
            "flags": intel.flags,
        }
        r.setex(cache_key, 3600, json.dumps(cache_data))  # 1 hour for failed lookups
        log.info("domain_intel.cached_failure", domain=domain)
    except Exception as exc:
        log.warning("domain_intel.redis_cache_error", error=str(exc))

    return intel


def extract_domain(url_or_address: str) -> str:
    """Best-effort domain extraction from a URL or bare email address."""
    if "://" in url_or_address:
        return urlparse(url_or_address).hostname or url_or_address
    if "@" in url_or_address:
        return url_or_address.split("@")[-1].strip().strip("<>").lower()
    return url_or_address.strip().lower()


def _get_redis_client() -> redis.Redis:
    """Get Redis client from config."""
    from app.config import get_settings
    settings = get_settings()
    return redis.from_url(settings.redis_url, decode_responses=True)
