"""Threat intelligence module.

ThreatIntelProvider interface → LocalBlocklistAdapter (queries DB).
External feed adapter is a documented stub — swap in without changing the interface.
"""
from __future__ import annotations

import re
import structlog
from abc import ABC, abstractmethod
from typing import Optional
from sqlalchemy.orm import Session

from app.detectors.base import Signal
from app.detectors.domain_intel import extract_domain

log = structlog.get_logger()


# ── Interface ─────────────────────────────────────────────────────────────────
class ThreatIntelProvider(ABC):
    """
    Pluggable interface. LocalBlocklistAdapter is the Phase 1 implementation.
    Swap to a commercial feed (VirusTotal, AlienVault OTX, etc.) by implementing
    this interface and injecting it — no changes to ThreatIntelModule.
    """
    @abstractmethod
    def is_blocked(self, indicator: str, indicator_type: str) -> tuple[bool, Optional[str]]:
        """Returns (is_blocked, source_note)."""
        ...


class LocalBlocklistAdapter(ThreatIntelProvider):
    """Checks the local blocklist_entries table (Phase 1 implementation)."""

    def __init__(self, db: Session):
        self._db = db

    def is_blocked(self, indicator: str, indicator_type: str) -> tuple[bool, Optional[str]]:
        from app.models.blocklist import BlocklistEntry
        from datetime import datetime, timezone

        entries = self._db.query(BlocklistEntry).filter(
            BlocklistEntry.indicator == indicator.lower(),
            BlocklistEntry.indicator_type == indicator_type,
            (BlocklistEntry.expires_at.is_(None)) | (BlocklistEntry.expires_at > datetime.now(timezone.utc)),
        ).all()
        if entries:
            sources = list({e.source for e in entries})
            return True, f"blocklist:{','.join(sorted(sources))}(hits:{len(entries)})"
        return False, None


class ExternalFeedAdapter(ThreatIntelProvider):
    """
    Phase 1 implementation for an external threat intel feed using Google Web Risk.
    Persists confirmed hits to the local blocklist.
    """
    def __init__(self, db: Session):
        self._db = db

    def is_blocked(self, indicator: str, indicator_type: str) -> tuple[bool, Optional[str]]:
        from datetime import datetime, timedelta, timezone
        from app.detectors.web_risk import check_url
        from app.models.blocklist import BlocklistEntry
        
        # Prepare URL for Web Risk. If bare domain, prepend scheme and append trailing slash.
        check_target = indicator
        if indicator_type == "domain":
            check_target = f"https://{indicator}/"
            
        result = check_url(check_target)
        
        if result is None:
            # Network error, timeout, or missing key -> fail open and log warning
            log.warning("threat_intel.web_risk.failed", indicator=indicator, indicator_type=indicator_type)
            return False, None
            
        if not result.get("flagged"):
            # URL is clean -> do not persist
            return False, None
            
        # URL is flagged -> check if it already exists in the blocklist
        existing = (
            self._db.query(BlocklistEntry)
            .filter(
                BlocklistEntry.indicator == indicator.lower(),
                BlocklistEntry.indicator_type == indicator_type
            )
            .first()
        )
        
        now = datetime.now(timezone.utc)
        if existing:
            # Option (a): Update existing row to a fresh 30 days.
            # This prevents stale database bloat while keeping the entry active.
            existing.expires_at = now + timedelta(days=30)
            existing.source = "web_risk"
            try:
                self._db.commit()
            except Exception as e:
                self._db.rollback()
                log.error("threat_intel.web_risk.db_update_error", error=str(e), indicator=indicator)
        else:
            new_entry = BlocklistEntry(
                indicator=indicator.lower(),
                indicator_type=indicator_type,
                source="web_risk",
                expires_at=now + timedelta(days=30)
            )
            self._db.add(new_entry)
            try:
                self._db.commit()
                log.info("threat_intel.web_risk.persisted", indicator=indicator, indicator_type=indicator_type)
            except Exception as e:
                self._db.rollback()
                log.error("threat_intel.web_risk.db_error", error=str(e), indicator=indicator)
                
        return True, "web_risk"


class ChainedThreatIntelProvider(ThreatIntelProvider):
    """
    Composes LocalBlocklistAdapter and ExternalFeedAdapter.
    Checks the local blocklist first to avoid unnecessary external API calls.
    """
    def __init__(self, db: Session):
        self._local = LocalBlocklistAdapter(db)
        self._external = ExternalFeedAdapter(db)

    def is_blocked(self, indicator: str, indicator_type: str) -> tuple[bool, Optional[str]]:
        try:
            blocked, source = self._local.is_blocked(indicator, indicator_type)
            if blocked:
                return blocked, source
        except Exception as e:
            log.error("threat_intel.chained.local_error", error=str(e), indicator=indicator)
            
        try:
            return self._external.is_blocked(indicator, indicator_type)
        except Exception as e:
            log.error("threat_intel.chained.external_error", error=str(e), indicator=indicator)
            
        return False, None


# ── Detector ──────────────────────────────────────────────────────────────────
_URL_PATTERN = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)


class ThreatIntelModule:
    def __init__(self, provider: ThreatIntelProvider):
        self._provider = provider

    def analyse(self, headers: dict[str, str], body_text: str,
                body_html: str, weight: float) -> Signal:
        flags: list[str] = []
        meta: dict = {}
        score = 0.0

        indicators: list[tuple[str, str]] = []

        # Sender domain
        sender = headers.get("From", "")
        sender_domain = extract_domain(sender)
        if sender_domain:
            indicators.append((sender_domain, "domain"))

        # URLs in body
        for url in _URL_PATTERN.findall(body_text + " " + body_html)[:20]:
            domain = extract_domain(url)
            if domain:
                indicators.append((domain, "domain"))
            indicators.append((url[:512], "url"))

        # Deduplicate indicators to avoid redundant Safe Browsing calls
        indicators = list(dict.fromkeys(indicators))
        blocked_found: list[str] = []
        for indicator, itype in indicators:
            try:
                blocked, source = self._provider.is_blocked(indicator, itype)
                if blocked:
                    blocked_found.append(f"{itype}:{indicator}({source})")
            except NotImplementedError:
                pass  # stub — skip silently
            except Exception as exc:
                log.error("detector.threat_intel.error", error=str(exc),
                          indicator=indicator, action="threat_intel_check")

        if blocked_found:
            score = min(40.0 + 10.0 * len(blocked_found), 100.0)
            flags = [f"blocklist_hit:{b}" for b in blocked_found]
            meta["blocked"] = blocked_found

        log.info("detector.threat_intel", score=score, hits=len(blocked_found),
                 action="threat_intel_analysis")
        return Signal(name="threat_intel", raw_score=score, weight=weight,
                      flags=flags, metadata=meta)
