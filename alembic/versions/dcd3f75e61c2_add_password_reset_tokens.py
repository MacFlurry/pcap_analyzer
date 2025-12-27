"""add_password_reset_tokens

Revision ID: dcd3f75e61c2
Revises: 2bc03b947812
Create Date: 2025-12-27 18:34:02.817945

Adds password_reset_tokens table for self-service password recovery:
- Stores cryptographically secure token hashes (SHA-256)
- Links to users with CASCADE delete
- Tracks IP and User Agent for security auditing
- Enforces single-use and expiration (1 hour default)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'dcd3f75e61c2'
down_revision: Union[str, Sequence[str], None] = '2bc03b947812'
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

    # Create password_reset_tokens table
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', id_type, primary_key=True, nullable=False),
        sa.Column('user_id', id_type, nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False),  # SHA-256 is 64 hex chars
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),  # IPv6 can be 45 chars
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.CheckConstraint('expires_at > created_at', name='token_expiry_check')
    )

    # Add foreign key with CASCADE delete
    if is_postgres:
        op.create_foreign_key(
            'fk_password_reset_tokens_user_id',
            'password_reset_tokens', 'users',
            ['user_id'], ['id'],
            ondelete='CASCADE'
        )
    # Note: SQLite foreign keys are handled via the table definition if using declarative,
    # but Alembic op.create_table doesn't always handle them automatically for SQLite
    # unless specified in the table. However, existing migrations seem to only
    # add FKs explicitly for Postgres.

    # Create indexes for performance and lookup
    op.create_index('idx_password_reset_tokens_user_id', 'password_reset_tokens', ['user_id'])
    op.create_index('idx_password_reset_tokens_token_hash', 'password_reset_tokens', ['token_hash'])
    op.create_index('idx_password_reset_tokens_expires_at', 'password_reset_tokens', ['expires_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('password_reset_tokens')