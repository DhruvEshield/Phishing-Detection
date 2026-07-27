"""Newly Registered Domains (NRD) feed ingestor.

Ingests WhoisDS's free, no-auth Newly Registered Domains feed, which publishes a daily
zip file containing a plain-text list of domains registered roughly 2 days ago.
NRD membership is a supporting signal (not blocklist-worthy on its own) meant to
combine with lookalike/brand-match detection later.
"""
from __future__ import annotations

import base64
import io
import time
import uuid
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

# Fixed name of the .txt member inside the WhoisDS daily archive.
_ARCHIVE_MEMBER = "domain-names.txt"

_CACHE_KEY = "nrd:current"


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
        # WhoisDS base64-encodes '<date>.zip' into the path segment. The plain
        # '<date>.zip' path is not a 404 — it returns 200 with an empty body,
        # so getting this wrong fails *open* (no NRD ever matches) rather than
        # raising. Asserted by test_fetch_nrd_feed_requests_encoded_url.
        encoded_filename = base64.b64encode(f"{date_str}.zip".encode()).decode()
        url = (
            "https://www.whoisds.com/whois-database/newly-registered-domains/"
            f"{encoded_filename}/nrd"
        )

        with httpx.Client(timeout=30.0, headers=_HEADERS) as client:
            response = client.get(url)
            if response.status_code != 200:
                log.warning("nrd_feed.fetch_failed", status_code=response.status_code, url=url)
                return []
            
            # Extract zip in memory. The archive member has a fixed name —
            # 'domain-names.txt', not '<date>.txt' (verified against the live
            # feed). Fall back to a sole .txt member if the provider renames it.
            with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                txt_filename = _ARCHIVE_MEMBER
                if txt_filename not in z.namelist():
                    candidates = [n for n in z.namelist() if n.endswith(".txt")]
                    if len(candidates) != 1:
                        log.warning("nrd_feed.missing_txt_file", filename=txt_filename, contents=z.namelist())
                        return []
                    txt_filename = candidates[0]

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

        # Build into a temp key and RENAME over the live one. Adding straight
        # into 'nrd:current' only ever *grows* the set — domains from every
        # prior refresh would linger until the TTL happened to lapse, and each
        # refresh resets that TTL, so in practice they never expire.
        build_key = f"nrd:build:{uuid.uuid4().hex}"
        try:
            batch_size = 1000
            for i in range(0, len(domains), batch_size):
                r.sadd(build_key, *domains[i:i + batch_size])

            r.expire(build_key, 48 * 3600)  # 48 hours
            # RENAME is atomic: readers see the old set until it swaps.
            r.rename(build_key, _CACHE_KEY)
        except Exception:
            r.delete(build_key)
            raise

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
        return bool(r.sismember(_CACHE_KEY, domain.lower()))
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
