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
        from sqlalchemy import and_, or_
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        entry = (
            self._db.query(BlocklistEntry)
            .filter(
                and_(
                    BlocklistEntry.indicator == indicator.lower(),
                    BlocklistEntry.indicator_type == indicator_type,
                    or_(
                        BlocklistEntry.expires_at.is_(None),
                        BlocklistEntry.expires_at > now,
                    ),
                )
            )
            .first()
        )
        if entry:
            return True, f"blocklist:{entry.source}"
        return False, None


class ExternalFeedAdapter(ThreatIntelProvider):
    """
    Phase 1 stub for an external threat intel feed.
    Implement by replacing this class body with real API calls.
    """
    def is_blocked(self, indicator: str, indicator_type: str) -> tuple[bool, Optional[str]]:
        raise NotImplementedError(
            "ExternalFeedAdapter is a Phase 1 stub. "
            "Implement with VirusTotal / OTX / etc. and inject via DI."
        )


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
