"""breach_monitor_and_biometric

Revision ID: 2a3b4c5d6e7f
Revises: 16557111881b
Create Date: 2026-05-08 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '2a3b4c5d6e7f'
down_revision: Union[str, None] = '16557111881b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'breach_alerts',
        sa.Column('id', sa.String(128), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('alert_type', sa.String(16), nullable=False),
        sa.Column('value_hash', sa.String(128), nullable=False),
        sa.Column('value_preview', sa.String(8), nullable=False),
        sa.Column('breach_count', sa.Integer(), nullable=False),
        sa.Column('severity', sa.String(16), nullable=False),
        sa.Column('status', sa.String(32), nullable=False, server_default='new'),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Index('ix_breach_alerts_user_status', 'user_id', 'status'),
    )

    op.create_table(
        'monitored_items',
        sa.Column('id', sa.String(128), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('item_type', sa.String(16), nullable=False),
        sa.Column('value_hash', sa.String(128), nullable=False),
        sa.Column('last_checked', sa.DateTime(timezone=True), nullable=True),
        sa.Column('check_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.add_column('webauthn_credentials', sa.Column('authenticator_type', sa.String(32), nullable=True))
    op.add_column('webauthn_credentials', sa.Column('aaguid', sa.String(36), nullable=True))
    op.add_column('webauthn_credentials', sa.Column('is_biometric', sa.Boolean(), nullable=True))

    op.execute("UPDATE webauthn_credentials SET authenticator_type = 'cross-platform', is_biometric = 0")

    op.alter_column('webauthn_credentials', 'authenticator_type', nullable=False)
    op.alter_column('webauthn_credentials', 'is_biometric', nullable=False)


def downgrade() -> None:
    op.drop_column('webauthn_credentials', 'is_biometric')
    op.drop_column('webauthn_credentials', 'aaguid')
    op.drop_column('webauthn_credentials', 'authenticator_type')
    op.drop_table('monitored_items')
    op.drop_table('breach_alerts')