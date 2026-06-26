"""SQLAlchemy ORM models — all tables under the 'phishdetect' schema."""
from app.models.email import Email
from app.models.analysis import AnalysisResult
from app.models.queue_entry import QueueEntry
from app.models.verdict import Verdict
from app.models.blocklist import BlocklistEntry, FeedbackEvent, AuditLog

__all__ = [
    "Email", "AnalysisResult", "QueueEntry", "Verdict",
    "BlocklistEntry", "FeedbackEvent", "AuditLog",
]
