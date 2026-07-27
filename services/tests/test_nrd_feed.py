"""Tests for the Newly Registered Domains (NRD) feed module."""
from __future__ import annotations

import base64
import io
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import httpx
import pytest

from app.detectors.nrd_feed import _fetch_nrd_feed, refresh_nrd_cache, is_newly_registered_domain


def _create_mock_zip(domains: list[str], member: str = "domain-names.txt") -> bytes:
    """Build an in-memory zip mirroring the real WhoisDS archive.

    The member is 'domain-names.txt' — a fixed name, NOT '{date}.txt'.
    Verified against the live feed; the previous helper encoded the bug it
    was meant to catch, which is why the broken extraction shipped green.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(member, "\n".join(domains).encode("utf-8"))
    return buf.getvalue()


class _FakeRedis:
    """Minimal in-memory stand-in for the set operations refresh uses, so the
    two-refresh regression exercises real replace-vs-accumulate semantics
    instead of asserting on mock call order."""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}

    def sadd(self, key: str, *members: str) -> None:
        self.sets.setdefault(key, set()).update(members)

    def expire(self, key: str, ttl: int) -> None:
        pass

    def rename(self, src: str, dst: str) -> None:
        self.sets[dst] = self.sets.pop(src)

    def delete(self, *keys: str) -> None:
        for k in keys:
            self.sets.pop(k, None)

    def sismember(self, key: str, member: str) -> bool:
        return member in self.sets.get(key, set())


def _expected_url() -> str:
    """The URL the fetcher must request: WhoisDS base64-encodes '<date>.zip'
    into the path segment. The plain '<date>.zip' path returns 200 with an
    empty body, so a wrong URL here fails open rather than loudly."""
    target_date = datetime.now(timezone.utc) - timedelta(days=2)
    encoded = base64.b64encode(
        f"{target_date.strftime('%Y-%m-%d')}.zip".encode()
    ).decode()
    return (
        "https://www.whoisds.com/whois-database/newly-registered-domains/"
        f"{encoded}/nrd"
    )


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_requests_encoded_url(mock_get):
    """The provider's base64-encoded download path must be requested exactly."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = _create_mock_zip(["evil.com"])
    mock_get.return_value = mock_resp

    _fetch_nrd_feed()

    assert mock_get.call_args.args[0] == _expected_url()


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_empty_body_returns_no_domains(mock_get):
    """A 200 with an empty body (what the wrong URL returns) must yield []
    rather than appearing to succeed."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b""
    mock_get.return_value = mock_resp

    assert _fetch_nrd_feed() == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_success(mock_get):
    """Test parsing a valid zip file from the mocked HTTP endpoint."""
    mock_zip_content = _create_mock_zip(["evil.com", "phish.net", ""])
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = mock_zip_content
    mock_get.return_value = mock_resp

    domains = _fetch_nrd_feed()
    assert len(domains) == 2
    assert "evil.com" in domains
    assert "phish.net" in domains


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_http_error(mock_get):
    """Test safe handling of non-200 responses."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    domains = _fetch_nrd_feed()
    assert domains == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_network_error(mock_get):
    """Test safe handling of network exceptions."""
    mock_get.side_effect = httpx.ConnectError("Connection refused")

    domains = _fetch_nrd_feed()
    assert domains == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_bad_zip(mock_get):
    """Test safe handling of malformed zip data."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"not a zip file"
    mock_get.return_value = mock_resp

    domains = _fetch_nrd_feed()
    assert domains == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_no_txt_member(mock_get):
    """No .txt member at all — nothing safe to infer, so return []."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.md", b"nothing here")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = buf.getvalue()
    mock_get.return_value = mock_resp

    assert _fetch_nrd_feed() == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_ambiguous_txt_members(mock_get):
    """Several .txt members — refuse to guess which one is the feed."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.txt", b"evil.com")
        z.writestr("b.txt", b"other.com")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = buf.getvalue()
    mock_get.return_value = mock_resp

    assert _fetch_nrd_feed() == []


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_renamed_sole_txt_member(mock_get):
    """If the provider renames the member but it's unambiguous, recover.

    This bug arose from hardcoding a guessed filename; a sole-.txt fallback
    is what would have survived it. Deliberate contract change — a rename no
    longer silently zeroes out every NRD lookup."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = _create_mock_zip(["evil.com"], member="renamed.txt")
    mock_get.return_value = mock_resp

    assert _fetch_nrd_feed() == ["evil.com"]


@patch("app.detectors.nrd_feed._fetch_nrd_feed")
@patch("app.detectors.nrd_feed.redis.from_url")
def test_refresh_nrd_cache_success(mock_redis, mock_fetch):
    """Test that domains are batched into sadd and expire is set."""
    mock_fetch.return_value = [f"domain{i}.com" for i in range(1500)]
    
    mock_r = MagicMock()
    mock_redis.return_value = mock_r
    
    count = refresh_nrd_cache()

    assert count == 1500
    # Should be called twice for 1500 items with batch size 1000
    assert mock_r.sadd.call_count == 2
    # Built under a temp key, TTL'd, then renamed over the live key.
    build_key = mock_r.sadd.call_args.args[0]
    assert build_key != "nrd:current"
    mock_r.expire.assert_called_once_with(build_key, 48 * 3600)
    mock_r.rename.assert_called_once_with(build_key, "nrd:current")


@patch("app.detectors.nrd_feed._fetch_nrd_feed")
@patch("app.detectors.nrd_feed.redis.from_url")
def test_refresh_nrd_cache_replaces_rather_than_accumulates(mock_redis, mock_fetch):
    """Two refreshes: a domain present in the first but absent from the second
    must not survive. Adding into the live key would leave it there forever."""
    fake = _FakeRedis()
    mock_redis.return_value = fake

    mock_fetch.return_value = ["stale.com", "keep.com"]
    refresh_nrd_cache()
    assert fake.sismember("nrd:current", "stale.com")

    mock_fetch.return_value = ["keep.com", "fresh.com"]
    refresh_nrd_cache()

    assert not fake.sismember("nrd:current", "stale.com")
    assert fake.sismember("nrd:current", "keep.com")
    assert fake.sismember("nrd:current", "fresh.com")


@patch("app.detectors.nrd_feed._fetch_nrd_feed")
def test_refresh_nrd_cache_empty(mock_fetch):
    """Test that an empty fetch returns 0 and doesn't hit Redis."""
    mock_fetch.return_value = []
    
    with patch("app.detectors.nrd_feed.redis.from_url") as mock_redis:
        count = refresh_nrd_cache()
        assert count == 0
        mock_redis.assert_not_called()


@patch("app.detectors.nrd_feed._fetch_nrd_feed")
@patch("app.detectors.nrd_feed.redis.from_url")
def test_refresh_nrd_cache_redis_error(mock_redis, mock_fetch):
    """Test safe handling of Redis errors during refresh."""
    mock_fetch.return_value = ["evil.com"]
    mock_redis.side_effect = Exception("Redis down")
    
    count = refresh_nrd_cache()
    assert count == 0


@patch("app.detectors.nrd_feed.redis.from_url")
def test_is_newly_registered_domain(mock_redis):
    """Test standard Redis lookup."""
    mock_r = MagicMock()
    mock_r.sismember.return_value = 1
    mock_redis.return_value = mock_r
    
    assert is_newly_registered_domain("evil.com") is True
    mock_r.sismember.assert_called_once_with("nrd:current", "evil.com")


@patch("app.detectors.nrd_feed.redis.from_url")
def test_is_newly_registered_domain_error(mock_redis):
    """Test safe handling of Redis errors during lookup."""
    mock_redis.side_effect = Exception("Redis down")
    
    assert is_newly_registered_domain("evil.com") is False
