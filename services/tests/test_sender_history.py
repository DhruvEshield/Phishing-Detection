"""Unit tests for SenderHistory tracking in DetectionService."""
from __future__ import annotations

from unittest.mock import MagicMock
from app.services.detection_service import DetectionService
from app.models.sender_history import SenderHistory

def test_new_sender_history_created():
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    svc = DetectionService(db=mock_db)
    svc._record_sender_history("alice@example.com", "tenant-1")
    
    mock_db.add.assert_called_once()
    added_obj = mock_db.add.call_args[0][0]
    assert isinstance(added_obj, SenderHistory)
    assert added_obj.sender == "alice@example.com"
    assert added_obj.tenant_id == "tenant-1"
    assert added_obj.email_count == 1

def test_existing_sender_history_updated():
    mock_db = MagicMock()
    existing_history = SenderHistory(
        sender="bob@example.com", 
        tenant_id="tenant-1",
        email_count=1
    )
    mock_db.query.return_value.filter.return_value.first.return_value = existing_history
    
    svc = DetectionService(db=mock_db)
    svc._record_sender_history("bob@example.com", "tenant-1")
    
    # Should not add a new row
    mock_db.add.assert_not_called()
    # Should increment existing email_count
    assert existing_history.email_count == 2
