"""Integration test for the full ingest → queue → verdict pipeline.
All external calls (DB, ML classifier) are mocked.
"""
from __future__ import annotations
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

SAMPLE_EMAIL = {
    "headers": {
        "From": "\"IT Support\" <support@micros0ft-helpdesk.com>",
        "To": "employee@company.com",
        "Subject": "URGENT: Your account will be suspended",
        "Reply-To": "attacker@gmail.com",
        "Authentication-Results": "spf=fail dkim=fail dmarc=fail",
    },
    "body_text": (
        "Your Microsoft 365 account will be suspended immediately. "
        "Verify your credentials now: http://login-microsoftonline-secure.xyz/verify"
    ),
    "body_html": "",
    "attachments": [],
    "raw_mime": None,
    "metadata": {"source": "test", "tenant_id": None},
}


def test_ingest_returns_score_and_explanation():
    """POST /api/v1/emails/ingest returns risk_score, explanation, routing_decision."""
    with patch("app.services.detection_service._get_classifier", return_value=None), \
         patch("app.api.ingest.get_db") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_db.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter.return_value.first.return_value = None
        mock_session.flush = MagicMock()
        mock_session.commit = MagicMock()
        mock_session.refresh = MagicMock()

        response = client.post("/api/v1/emails/ingest", json=SAMPLE_EMAIL)

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "risk_score" in data["data"]
    assert "explanation" in data["data"]
    assert "routing_decision" in data["data"]
    assert data["data"]["risk_score"] >= 0
    assert data["data"]["routing_decision"] in ("deliver", "review", "quarantine")


def test_health_endpoint():
    """GET /health returns 200 with status ok."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
