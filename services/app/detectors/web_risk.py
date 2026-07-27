"""Google Web Risk Lookup API URL checker utility.

Web Risk is Google Cloud's commercially-licensed successor to Safe Browsing —
functionally similar (checks URLs against known-malicious threat lists) but
billed via Google Cloud and licensed for commercial use, unlike Safe Browsing
which is non-commercial-only.
"""
from __future__ import annotations
import hashlib
import structlog
import httpx
from app.config import get_settings

log = structlog.get_logger()

_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


def check_url(url: str) -> dict | None:
    """
    Checks a URL against Google Web Risk's Lookup API (uris.search).
    Returns:
        - {"flagged": True, "threat_types": [...]} if flagged.
        - {"flagged": False} if not flagged (safe).
        - None if the API call fails, key is missing, or there is a network error.
    """
    settings = get_settings()
    api_key = settings.google_web_risk_key
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

    if not api_key:
        log.error("web_risk.missing_key", action="check_url", url_hash=url_hash)
        return None

    endpoint = "https://webrisk.googleapis.com/v1/uris:search"
    params = {
        "uri": url,
        "threatTypes": _THREAT_TYPES,
        "key": api_key,
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            response = client.get(endpoint, params=params)
            if response.status_code != 200:
                log.error(
                    "web_risk.api_error",
                    status_code=response.status_code,
                    text=response.text,
                    action="check_url",
                    url_hash=url_hash,
                )
                return None
            data = response.json()
            threat = data.get("threat")
            if not threat:
                log.info("web_risk.clean", action="check_url", url_hash=url_hash)
                return {"flagged": False}
            threat_types = threat.get("threatTypes", [])
            log.info("web_risk.flagged", threat_types=threat_types, action="check_url", url_hash=url_hash)
            return {"flagged": True, "threat_types": threat_types}
    except httpx.TimeoutException:
        log.error("web_risk.timeout", action="check_url", url_hash=url_hash)
        return None
    except Exception as e:
        log.error("web_risk.exception", error=str(e), action="check_url", url_hash=url_hash)
        return None
