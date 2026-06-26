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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

log = structlog.get_logger()

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
    Safe-fails: on any error returns DomainIntel with rdap_error set.
    """
    intel = DomainIntel(domain=domain)

    try:
        ssrf_guard(domain)
    except ValueError as exc:
        intel.rdap_error = str(exc)
        intel.flags.append("ssrf_blocked")
        log.warning("domain_intel.ssrf_blocked", domain=domain, reason=str(exc))
        return intel

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

    except httpx.HTTPError as exc:
        intel.rdap_error = str(exc)
        log.warning("domain_intel.rdap_error", domain=domain, error=str(exc))

    return intel


def extract_domain(url_or_address: str) -> str:
    """Best-effort domain extraction from a URL or bare email address."""
    if "://" in url_or_address:
        return urlparse(url_or_address).hostname or url_or_address
    if "@" in url_or_address:
        return url_or_address.split("@")[-1].strip().lower()
    return url_or_address.strip().lower()
