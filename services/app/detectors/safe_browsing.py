"""Google Safe Browsing v5 URL checker utility."""
from __future__ import annotations

import hashlib
import structlog
import httpx

from app.config import get_settings

log = structlog.get_logger()


def check_url(url: str) -> dict | None:
    """
    Checks a URL against Google Safe Browsing v5.
    
    Returns:
        - {"flagged": True, "threat_types": [...]} if flagged.
        - {"flagged": False} if not flagged (safe).
        - None if the API call fails or there is a network error.
    """
    settings = get_settings()
    api_key = settings.google_safe_browsing_key

    # Hash the URL for logging to avoid dumping raw malicious URLs or PII to logs
    url_hash = hashlib.md5(url.encode()).hexdigest()[:8]

    if not api_key:
        log.error("safe_browsing.missing_key", action="check_url", url_hash=url_hash)
        return None

    endpoint = "https://safebrowsing.googleapis.com/v5/urls:search"
    
    # Note: Google Safe Browsing v5 specifies 'uri' as the query parameter for the target URL
    params = {
        "uri": url,
        "key": api_key
    }

    try:
        # 4.0s timeout to prevent hanging the pipeline
        with httpx.Client(timeout=4.0) as client:
            response = client.get(endpoint, params=params)
            
            if response.status_code != 200:
                log.error(
                    "safe_browsing.api_error",
                    status_code=response.status_code,
                    text=response.text,
                    action="check_url",
                    url_hash=url_hash
                )
                return None

            data = response.json()
            
            # An empty response ({}) indicates no threats found
            matches = data.get("threats", [])
            if not matches:
                log.info("safe_browsing.clean", action="check_url", url_hash=url_hash)
                return {"flagged": False}

            # In v5 urls:search, each match under 'threats' contains a list of 'threatTypes'
            threat_types_set = set()
            for m in matches:
                for tt in m.get("threatTypes", []):
                    threat_types_set.add(tt)
            
            threat_types = list(threat_types_set)
            log.info("safe_browsing.flagged", threat_types=threat_types, action="check_url", url_hash=url_hash)
            
            return {"flagged": True, "threat_types": threat_types}

    except httpx.TimeoutException:
        log.error("safe_browsing.timeout", action="check_url", url_hash=url_hash)
        return None
    except Exception as e:
        log.error("safe_browsing.exception", error=str(e), action="check_url", url_hash=url_hash)
        return None
