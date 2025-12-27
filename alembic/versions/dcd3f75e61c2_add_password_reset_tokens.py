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
revision: str = "dcd3f75e61c2"
down_revision: Union[str, Sequence[str], None] = "2bc03b947812"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Detect database type
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # Define types based on database
    if is_postgres:
        id_type = postgresql.UUID(as_uuid=False)
        timestamp_type = sa.DateTime(timezone=True)
    else:
        id_type = sa.String(36)
        timestamp_type = sa.DateTime()

    # Define table arguments
    table_args = [sa.CheckConstraint("expires_at > created_at", name="token_expiry_check")]

    # For SQLite, we must define Foreign Keys inline during table creation
    # as ALTER TABLE ADD CONSTRAINT is not supported
    if not is_postgres:
        table_args.append(
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"], name="fk_password_reset_tokens_user_id", ondelete="CASCADE"
            )
        )

    # Create password_reset_tokens table
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", id_type, primary_key=True, nullable=False),
        sa.Column("user_id", id_type, nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),  # SHA-256 is 64 hex chars
        sa.Column("created_at", timestamp_type, nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", timestamp_type, nullable=False),
        sa.Column("used_at", timestamp_type, nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),  # IPv6 can be 45 chars
        sa.Column("user_agent", sa.Text(), nullable=True),
        *table_args,
    )

    # For PostgreSQL, we can use the separate command which allows for named constraints
    # and is the pattern used in previous migrations
    if is_postgres:
        op.create_foreign_key(
            "fk_password_reset_tokens_user_id",
            "password_reset_tokens",
            "users",
            ["user_id"],
            ["id"],
            ondelete="CASCADE",
        )

    # Create indexes for performance and lookup
    op.create_index("idx_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index("idx_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"])
    op.create_index("idx_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("password_reset_tokens")
