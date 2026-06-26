"""Initial schema — all phishdetect tables.

Revision ID: 0001
Revises: —
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMA = "phishdetect"


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")

    op.create_table(
        "emails",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("dedup_hash", sa.String(32), nullable=False, index=True),
        sa.Column("raw_headers_json", JSONB, nullable=False),
        sa.Column("body_text", sa.Text, nullable=False, server_default=""),
        sa.Column("body_html", sa.Text, nullable=False, server_default=""),
        sa.Column("attachments_json", JSONB, nullable=False, server_default="[]"),
        sa.Column("sender", sa.String(512), nullable=False, server_default=""),
        sa.Column("subject", sa.String(998), nullable=False, server_default=""),
        sa.Column("routing_decision", sa.String(20), nullable=False, server_default=""),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        schema=SCHEMA,
    )

    op.create_table(
        "analysis_results",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", UUID(as_uuid=False),
                  sa.ForeignKey(f"{SCHEMA}.emails.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("risk_tier", sa.String(20), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("explanation_json", JSONB, nullable=False),
        sa.Column("model_version", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        schema=SCHEMA,
    )

    op.create_table(
        "queue_entries",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", UUID(as_uuid=False),
                  sa.ForeignKey(f"{SCHEMA}.emails.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )

    op.create_table(
        "verdicts",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", UUID(as_uuid=False),
                  sa.ForeignKey(f"{SCHEMA}.emails.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("analyst_id", sa.String(256), nullable=True),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        schema=SCHEMA,
    )

    op.create_table(
        "blocklist_entries",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("indicator", sa.String(512), nullable=False, index=True),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("source", sa.String(128), nullable=False, server_default="internal"),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )

    op.create_table(
        "feedback_events",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("verdict_id", UUID(as_uuid=False),
                  sa.ForeignKey(f"{SCHEMA}.verdicts.id", ondelete="SET NULL"),
                  nullable=True, index=True),
        sa.Column("event_type", sa.String(64), nullable=False,
                  server_default="analyst_verdict"),
        sa.Column("payload_json", JSONB, nullable=False),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("actor", sa.String(256), nullable=False, server_default="system"),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("resource_id", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("detail_json", JSONB, nullable=False, server_default="{}"),
        sa.Column("tenant_id", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        schema=SCHEMA,
    )


def downgrade() -> None:
    for table in ("audit_logs", "feedback_events", "blocklist_entries",
                  "verdicts", "queue_entries", "analysis_results", "emails"):
        op.drop_table(table, schema=SCHEMA)
