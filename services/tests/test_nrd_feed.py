"""Tests for the Newly Registered Domains (NRD) feed module."""
from __future__ import annotations

import io
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import httpx
import pytest

from app.detectors.nrd_feed import _fetch_nrd_feed, refresh_nrd_cache, is_newly_registered_domain


def _create_mock_zip(date_str: str, domains: list[str]) -> bytes:
    """Helper to create an in-memory zip file matching the expected format."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{date_str}.txt", "\n".join(domains).encode("utf-8"))
    return buf.getvalue()


@patch("app.detectors.nrd_feed.httpx.Client.get")
def test_fetch_nrd_feed_success(mock_get):
    """Test parsing a valid zip file from the mocked HTTP endpoint."""
    target_date = datetime.now(timezone.utc) - timedelta(days=2)
    date_str = target_date.strftime("%Y-%m-%d")
    
    mock_zip_content = _create_mock_zip(date_str, ["evil.com", "phish.net", ""])
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
def test_fetch_nrd_feed_missing_txt(mock_get):
    """Test safe handling when the zip doesn't contain the expected date.txt file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("wrong_name.txt", b"evil.com")
        
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = buf.getvalue()
    mock_get.return_value = mock_resp

    domains = _fetch_nrd_feed()
    assert domains == []


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
    mock_r.expire.assert_called_once_with("nrd:current", 48 * 3600)


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
