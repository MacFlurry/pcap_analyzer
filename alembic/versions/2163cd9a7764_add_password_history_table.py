"""add_password_history_table

Revision ID: 2163cd9a7764
Revises: eba0e1bcc7ec
Create Date: 2025-12-21 23:17:24.698430

Adds password_history table for Issue #23 (Enhanced Password Policy):
- Tracks last 5 passwords per user (prevents reuse)
- Stores hashed passwords with timestamps
- CASCADE delete when user is deleted

Also adds password_must_change column to users table (was missing in initial migration).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '2163cd9a7764'
down_revision: Union[str, Sequence[str], None] = 'eba0e1bcc7ec'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Detect database type
    bind = op.get_bind()
    is_postgres = bind.dialect.name == 'postgresql'

    # Define ID type based on database
    if is_postgres:
        id_type = postgresql.UUID(as_uuid=False)  # Store as string for compatibility
    else:
        id_type = sa.String(36)  # SQLite: TEXT with 36 chars (UUID length)

    # 1. Add password_must_change column to users table (missing from initial migration)
    op.add_column('users', sa.Column('password_must_change', sa.Boolean(), nullable=False, server_default='0'))

    # 2. Create password_history table
    op.create_table(
        'password_history',
        sa.Column('id', id_type, primary_key=True, nullable=False),
        sa.Column('user_id', id_type, nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    # Add foreign key for user_id with CASCADE delete
    if is_postgres:
        op.create_foreign_key(
            'fk_password_history_user_id',
            'password_history', 'users',
            ['user_id'], ['id'],
            ondelete='CASCADE'
        )

    # Create indexes for password_history
    op.create_index('idx_password_history_user_id', 'password_history', ['user_id'])
    op.create_index('idx_password_history_user_created', 'password_history', ['user_id', 'created_at'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop password_history table (indexes dropped automatically)
    op.drop_table('password_history')

    # Drop password_must_change column from users
    op.drop_column('users', 'password_must_change')
