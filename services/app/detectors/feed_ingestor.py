"""Feed ingestor — downloads threat intel feeds and persists to blocklist_entries.

Sources:
- OpenPhish: free, no auth, plain text, refreshes every 6 hours
- PhishTank: free with API key, CSV format, refreshes every 6 hours
- URLhaus: free, no auth, CSV format, refreshes every 5 minutes

This module is called by a background thread on API startup.
It populates blocklist_entries so LocalBlocklistAdapter can check them
during email analysis without making external API calls.
"""
from __future__ import annotations

import csv
import io
import time
import threading
import structlog
import httpx
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.blocklist import BlocklistEntry
from app.config import get_settings

log = structlog.get_logger()

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"

_HEADERS = {"User-Agent": "PhishDetect/1.0 (security-research)"}
_TIMEOUT = 30.0


def _normalize_url(url: str) -> str:
    """Normalize URL for consistent storage."""
    return url.strip().lower()


def _normalize_domain(url: str) -> str:
    """Extract and normalize domain from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return (parsed.hostname or "").lower().strip()
    except Exception:
        return ""


def _upsert_indicator(
    db: Session,
    indicator: str,
    indicator_type: str,
    source: str,
    expiry_days: int = 30,
) -> None:
    """Insert or refresh expiry for a blocklist entry."""
    if not indicator or len(indicator) > 512:
        return
    try:
        existing = db.query(BlocklistEntry).filter(
            BlocklistEntry.indicator == indicator,
            BlocklistEntry.indicator_type == indicator_type,
            BlocklistEntry.source == source,
        ).first()
        now = datetime.now(timezone.utc)
        if existing:
            existing.expires_at = now + timedelta(days=expiry_days)
        else:
            db.add(BlocklistEntry(
                indicator=indicator,
                indicator_type=indicator_type,
                source=source,
                expires_at=now + timedelta(days=expiry_days),
            ))
    except Exception as exc:
        log.warning("feed_ingestor.upsert_error", error=str(exc), indicator=indicator)


def ingest_openphish(db: Session) -> int:
    """Download and ingest OpenPhish feed. Returns count of entries processed."""
    try:
        resp = httpx.get(OPENPHISH_URL, headers=_HEADERS, timeout=_TIMEOUT)
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            _upsert_indicator(db, _normalize_url(url), "url", "openphish")
            domain = _normalize_domain(url)
            if domain:
                _upsert_indicator(db, domain, "domain", "openphish")
            count += 1
        db.commit()
        log.info("feed_ingestor.openphish.done", count=count)
        return count
    except Exception as exc:
        db.rollback()
        log.error("feed_ingestor.openphish.error", error=str(exc))
        return 0


def ingest_urlhaus(db: Session) -> int:
    """Download and ingest URLhaus feed. Returns count of entries processed."""
    try:
        resp = httpx.get(URLHAUS_URL, headers=_HEADERS, timeout=_TIMEOUT)
        resp.raise_for_status()
        count = 0
        reader = csv.reader(io.StringIO(resp.text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 3:
                continue
            url = row[2].strip().strip('"')
            if not url or not url.startswith("http"):
                continue
            _upsert_indicator(db, _normalize_url(url), "url", "urlhaus")
            domain = _normalize_domain(url)
            if domain:
                _upsert_indicator(db, domain, "domain", "urlhaus")
            count += 1
        db.commit()
        log.info("feed_ingestor.urlhaus.done", count=count)
        return count
    except Exception as exc:
        db.rollback()
        log.error("feed_ingestor.urlhaus.error", error=str(exc))
        return 0


def ingest_all_feeds() -> None:
    """Run all feed ingestors. Called by background thread."""
    db: Session = SessionLocal()
    try:
        log.info("feed_ingestor.start")
        openphish_count = ingest_openphish(db)
        urlhaus_count = ingest_urlhaus(db)
        log.info(
            "feed_ingestor.complete",
            openphish=openphish_count,
            urlhaus=urlhaus_count,
        )
    except Exception as exc:
        log.error("feed_ingestor.fatal", error=str(exc))
    finally:
        db.close()


def start_feed_refresh_thread(interval_seconds: int = 21600) -> None:
    """Start background thread that refreshes feeds every interval_seconds (default 6 hours)."""
    def _worker():
        while True:
            ingest_all_feeds()
            time.sleep(interval_seconds)

    thread = threading.Thread(target=_worker, daemon=True, name="feed-refresh")
    thread.start()
    log.info("feed_ingestor.thread_started", interval_seconds=interval_seconds)
