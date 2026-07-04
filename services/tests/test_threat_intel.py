"""Threat intel unit tests — DB is mocked."""
from __future__ import annotations

from app.detectors.threat_intel import ThreatIntelModule, ThreatIntelProvider


class MockProvider(ThreatIntelProvider):
    def __init__(self, blocked_indicators: set[str]):
        self._blocked = blocked_indicators

    def is_blocked(self, indicator, indicator_type):
        if indicator in self._blocked:
            return True, "test_source"
        return False, None


def test_known_bad_domain_scores():
    provider = MockProvider({"evil-phishing.com"})
    module = ThreatIntelModule(provider)
    headers = {"From": "attacker@evil-phishing.com"}
    signal = module.analyse(headers, body_text="", body_html="", weight=0.10)
    assert signal.raw_score > 0
    assert any("blocklist_hit" in f for f in signal.flags)


def test_clean_email_zero_score():
    provider = MockProvider(set())
    module = ThreatIntelModule(provider)
    headers = {"From": "alice@microsoft.com"}
    signal = module.analyse(headers, body_text="Visit https://microsoft.com",
                            body_html="", weight=0.10)
    assert signal.raw_score == 0.0
    assert len(signal.flags) == 0


def test_blocklist_url_in_body_detected():
    provider = MockProvider({"evil-phishing.com"})
    module = ThreatIntelModule(provider)
    headers = {}
    body = "Click here: http://evil-phishing.com/steal-creds"
    signal = module.analyse(headers, body_text=body, body_html="", weight=0.10)
    assert signal.raw_score > 0


def test_stub_provider_does_not_crash():
    """ExternalFeedAdapter raises NotImplementedError — module should not crash."""
    from unittest.mock import MagicMock
    from app.detectors.threat_intel import ExternalFeedAdapter
    mock_db = MagicMock()
    module = ThreatIntelModule(ExternalFeedAdapter(mock_db))
    signal = module.analyse({"From": "x@y.com"}, "", "", 0.10)
    assert signal.raw_score == 0.0  # stub skipped silently


def test_multiple_hits_increase_score():
    provider = MockProvider({"evil.com", "phish.net", "badactor.org"})
    module = ThreatIntelModule(provider)
    headers = {"From": "x@evil.com"}
    body = "http://phish.net/go http://badactor.org/x"
    signal = module.analyse(headers, body, "", 0.10)
    assert signal.raw_score > 40
