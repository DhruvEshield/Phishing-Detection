"""Newly Registered Domains (NRD) feed ingestor.

Ingests WhoisDS's free, no-auth Newly Registered Domains feed, which publishes a daily
zip file containing a plain-text list of domains registered roughly 2 days ago.
NRD membership is a supporting signal (not blocklist-worthy on its own) meant to
combine with lookalike/brand-match detection later.
"""
from __future__ import annotations

import io
import time
import zipfile
from datetime import datetime, timedelta, timezone
from threading import Thread

import httpx
import redis
import structlog
from app.config import get_settings

log = structlog.get_logger()

_HEADERS = {
    "User-Agent": "PhishDetect-Bot/1.0",
}


def _fetch_nrd_feed() -> list[str]:
    """
    Downloads the daily NRD zip via httpx, extracts it in-memory, and returns
    a list of domain strings (stripped, lowercased, skipping empty lines).
    The URL uses the date 2 days ago in YYYY-MM-DD format.
    """
    try:
        # WhoisDS publishes data with a 2-day lag
        target_date = datetime.now(timezone.utc) - timedelta(days=2)
        date_str = target_date.strftime("%Y-%m-%d")
        url = f"https://whoisds.com/whois-database/newly-registered-domains/{date_str}.zip/nrd"
        
        with httpx.Client(timeout=30.0, headers=_HEADERS) as client:
            response = client.get(url)
            if response.status_code != 200:
                log.warning("nrd_feed.fetch_failed", status_code=response.status_code, url=url)
                return []
            
            # Extract zip in memory
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                txt_filename = f"{date_str}.txt"
                if txt_filename not in z.namelist():
                    log.warning("nrd_feed.missing_txt_file", filename=txt_filename, contents=z.namelist())
                    return []
                    
                with z.open(txt_filename) as f:
                    domains = []
                    for line in f:
                        decoded_line = line.decode('utf-8', errors='ignore').strip().lower()
                        if decoded_line:
                            domains.append(decoded_line)
                    return domains
                    
    except Exception as e:
        log.warning("nrd_feed.exception", error=str(e))
        return []


def refresh_nrd_cache() -> int:
    """
    Calls _fetch_nrd_feed() and stores the domains in a Redis set 'nrd:current'.
    Sets a 48-hour expiry.
    Returns the count of domains cached (0 on failure).
    """
    domains = _fetch_nrd_feed()
    if not domains:
        return 0

    try:
        settings = get_settings()
        r = redis.from_url(settings.redis_url, decode_responses=True)
        key = "nrd:current"
        
        # Batch sadd to avoid one giant command
        batch_size = 1000
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            r.sadd(key, *batch)
            
        r.expire(key, 48 * 3600)  # 48 hours
        
        log.info("nrd_feed.refreshed", count=len(domains))
        return len(domains)
    except Exception as e:
        log.warning("nrd_feed.redis_error", error=str(e))
        return 0


def is_newly_registered_domain(domain: str) -> bool:
    """
    Checks Redis set membership for the given domain in 'nrd:current'.
    Safe-fail: returns False on any Redis error.
    """
    try:
        settings = get_settings()
        r = redis.from_url(settings.redis_url, decode_responses=True)
        return bool(r.sismember("nrd:current", domain.lower()))
    except Exception as e:
        log.warning("nrd_feed.check_error", error=str(e), domain=domain)
        return False


def start_nrd_refresh_thread(interval_seconds: int = 86400) -> None:
    """
    Starts a daemon background thread that periodically refreshes the NRD cache.
    """
    def _loop():
        log.info("nrd_feed.thread_started", interval=interval_seconds)
        while True:
            try:
                refresh_nrd_cache()
            except Exception as e:
                log.error("nrd_feed.thread_error", error=str(e))
            time.sleep(interval_seconds)

    t = Thread(target=_loop, daemon=True, name="NRDRefreshThread")
    t.start()
