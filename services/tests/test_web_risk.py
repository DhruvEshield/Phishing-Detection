"""Tests for Google Web Risk detector utility."""
from __future__ import annotations

import httpx
import pytest
from unittest.mock import patch, MagicMock

from app.detectors.web_risk import check_url


@pytest.fixture
def mock_settings():
    """Fixture to mock config so we don't need a real .env for tests."""
    with patch("app.detectors.web_risk.get_settings") as mock_get:
        settings = MagicMock()
        settings.google_web_risk_key = "test_api_key_123"
        mock_get.return_value = settings
        yield settings


@patch("app.detectors.web_risk.httpx.Client")
def test_clean_url(mock_client_class, mock_settings):
    """1. A known-clean URL returns {"flagged": False}"""
    mock_client = mock_client_class.return_value.__enter__.return_value
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_client.get.return_value = mock_response

    result = check_url("http://clean.com")
    
    assert result == {"flagged": False}


@patch("app.detectors.web_risk.httpx.Client")
def test_flagged_url(mock_client_class, mock_settings):
    """2. A mocked "flagged" response with threats + threatTypes returns correct dict"""
    mock_client = mock_client_class.return_value.__enter__.return_value
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "threat": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"]
        }
    }
    mock_client.get.return_value = mock_response

    result = check_url("http://evil.com")
    
    assert result is not None
    assert result["flagged"] is True
    # Verify the values were extracted correctly
    assert set(result["threat_types"]) == {"SOCIAL_ENGINEERING", "MALWARE"}


@patch("app.detectors.web_risk.httpx.Client")
def test_non_200_response_returns_none(mock_client_class, mock_settings):
    """4. A non-200 API response returns None (not False)"""
    mock_client = mock_client_class.return_value.__enter__.return_value
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_client.get.return_value = mock_response

    result = check_url("http://error.com")
    
    assert result is None


@patch("app.detectors.web_risk.httpx.Client")
def test_timeout_returns_none(mock_client_class, mock_settings):
    """5. A timeout (mock httpx.TimeoutException) returns None (not False)"""
    mock_client = mock_client_class.return_value.__enter__.return_value
    mock_client.get.side_effect = httpx.TimeoutException("Timeout")

    result = check_url("http://slow.com")
    
    assert result is None


@patch("app.detectors.web_risk.httpx.Client")
def test_missing_api_key_returns_none(mock_client_class, mock_settings):
    """6. A missing/empty API key returns None and logs an error, without network call"""
    mock_settings.google_web_risk_key = None

    result = check_url("http://nokey.com")
    
    assert result is None
    # 7. Confirm no network call was made
    mock_client_class.assert_not_called()
