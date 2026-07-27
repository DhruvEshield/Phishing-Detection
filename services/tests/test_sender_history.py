"""Tests for SenderHistory tracking in DetectionService.

The upsert is a PostgreSQL ON CONFLICT statement, so the behaviour that
matters — conflict handling, first_seen_at preservation, count increments —
cannot be exercised against mocks or SQLite. These tests run against a real
Postgres when DATABASE_URL points at one and skip otherwise, matching the
existing convention for test_ingest_endpoint.py (see .github/workflows/ci.yml:
CI has no Postgres service, so these run locally).

_canonical_sender is pure and is tested unconditionally.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models.sender_history import SenderHistory
from app.services.detection_service import DetectionService, _canonical_sender


# ── Canonicalisation (pure, always runs) ─────────────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("alice@example.com", "alice@example.com"),
    ("Alice <alice@example.com>", "alice@example.com"),
    ('"Alice A." <alice@example.com>', "alice@example.com"),
    ("  alice@example.com  ", "alice@example.com"),
    ("Alice <ALICE@Example.COM>", "alice@example.com"),
    ("", ""),
])
def test_canonical_sender(raw, expected):
    """A display name or stray case must not fork the history key."""
    assert _canonical_sender(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    # parseaddr salvages a token from loose input rather than returning ''.
    ("not an address", "not"),
    ("garbage", "garbage"),
    # These it genuinely cannot parse — fall back to the raw header so a
    # malformed sender still records something instead of being dropped.
    ("<<>>", "<<>>"),
    ("a@b@c", "a@b@c"),
])
def test_canonical_sender_malformed_input(raw, expected):
    """Malformed headers are recorded deterministically, never dropped."""
    assert _canonical_sender(raw) == expected


# ── Persistence (needs Postgres) ─────────────────────────────────────────────

DB_URL = os.environ.get("DATABASE_URL", "")

pg_only = pytest.mark.skipif(
    not DB_URL.startswith("postgresql"),
    reason="needs a live Postgres (ON CONFLICT upsert); set DATABASE_URL",
)


@pytest.fixture
def db():
    engine = create_engine(DB_URL)
    session = sessionmaker(bind=engine)()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def sender():
    """A unique address per test so runs don't collide in a persistent DB."""
    return f"alice-{uuid.uuid4().hex[:8]}@example.com"


@pg_only
def test_first_record_creates_row(db, sender):
    svc = DetectionService(db=db)
    svc._record_sender_history(f"Alice <{sender}>", "tenant-1")
    db.commit()

    row = db.query(SenderHistory).filter_by(sender=sender, tenant_id="tenant-1").one()
    assert row.email_count == 1
    assert row.first_seen_at == row.last_seen_at


@pg_only
def test_repeat_increments_and_preserves_first_seen(db, sender):
    """first_seen_at must survive later upserts; last_seen_at must advance."""
    svc = DetectionService(db=db)
    svc._record_sender_history(sender, "tenant-1")
    db.commit()
    original = db.query(SenderHistory).filter_by(sender=sender).one()
    first_seen, earlier = original.first_seen_at, original.last_seen_at

    # Push last_seen_at back so any advance is unambiguous.
    db.execute(
        text("UPDATE phishdetect.sender_history SET last_seen_at = :t WHERE sender = :s"),
        {"t": earlier - timedelta(hours=1), "s": sender},
    )
    db.commit()

    svc._record_sender_history(sender, "tenant-1")
    db.commit()
    db.expire_all()

    row = db.query(SenderHistory).filter_by(sender=sender).one()
    assert row.email_count == 2
    assert row.first_seen_at == first_seen
    assert row.last_seen_at > earlier - timedelta(hours=1)


@pg_only
def test_display_name_shares_one_history_row(db, sender):
    """'Alice <a@x>' and 'a@x' are the same sender — one row, count 2."""
    svc = DetectionService(db=db)
    svc._record_sender_history(f"Alice <{sender}>", "tenant-1")
    db.commit()
    svc._record_sender_history(sender, "tenant-1")
    db.commit()
    db.expire_all()

    row = db.query(SenderHistory).filter_by(sender=sender, tenant_id="tenant-1").one()
    assert row.email_count == 2


@pg_only
def test_tenantless_senders_share_one_row(db, sender):
    """The '' sentinel keeps tenant-less senders in a single scope. With a
    nullable tenant_id these would be two rows with counts split, because
    NULL != NULL defeats the unique constraint."""
    svc = DetectionService(db=db)
    svc._record_sender_history(sender, None)
    db.commit()
    svc._record_sender_history(sender, None)
    db.commit()
    db.expire_all()

    rows = db.query(SenderHistory).filter_by(sender=sender).all()
    assert len(rows) == 1
    assert rows[0].email_count == 2
    assert rows[0].tenant_id == ""


@pg_only
def test_tenants_are_scoped_separately(db, sender):
    svc = DetectionService(db=db)
    svc._record_sender_history(sender, "tenant-1")
    svc._record_sender_history(sender, "tenant-2")
    db.commit()

    counts = {r.tenant_id: r.email_count for r in db.query(SenderHistory).filter_by(sender=sender)}
    assert counts == {"tenant-1": 1, "tenant-2": 1}


@pg_only
def test_concurrent_insert_does_not_escape(db, sender):
    """A racing insert from another session must not raise out of
    _record_sender_history — previously the conflict surfaced at the caller's
    commit(), outside the try, failing the entire email analysis."""
    other = sessionmaker(bind=create_engine(DB_URL))()
    try:
        now = datetime.now(timezone.utc)
        other.add(SenderHistory(
            sender=sender, tenant_id="tenant-1",
            first_seen_at=now, last_seen_at=now, email_count=1,
        ))
        other.commit()

        # Same row now exists; the upsert must absorb the conflict.
        DetectionService(db=db)._record_sender_history(sender, "tenant-1")
        db.commit()

        db.expire_all()
        row = db.query(SenderHistory).filter_by(sender=sender, tenant_id="tenant-1").one()
        assert row.email_count == 2
    finally:
        other.query(SenderHistory).filter_by(sender=sender).delete()
        other.commit()
        other.close()


@pg_only
def test_error_is_swallowed_without_logging_pii(db, sender, caplog):
    """The handler must not emit the raw address or DB exception text."""
    svc = DetectionService(db=db)
    db.close()  # force a failure inside the method

    svc._record_sender_history(sender, "tenant-1")

    assert sender not in caplog.text
