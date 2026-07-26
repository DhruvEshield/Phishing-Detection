"""add sender_history table

Revision ID: 000c742f90b7
Revises: 0001
Create Date: 2026-07-26 15:49:27.045534

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '000c742f90b7'
down_revision: Union[str, None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('sender_history',
    sa.Column('id', sa.UUID(as_uuid=False), nullable=False),
    sa.Column('sender', sa.String(length=512), nullable=False),
    sa.Column('tenant_id', sa.String(length=128), nullable=True),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('email_count', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('sender', 'tenant_id', name='uq_sender_tenant'),
    schema='phishdetect'
    )
    op.create_index(op.f('ix_phishdetect_sender_history_sender'), 'sender_history', ['sender'], unique=False, schema='phishdetect')


def downgrade() -> None:
    op.drop_index(op.f('ix_phishdetect_sender_history_sender'), table_name='sender_history', schema='phishdetect')
    op.drop_table('sender_history', schema='phishdetect')