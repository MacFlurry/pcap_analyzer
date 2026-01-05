"""add_2fa_columns_to_users

Revision ID: 2bc03b947812
Revises: c0989c735473
Create Date: 2025-12-26 10:57:22.741689

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2bc03b947812"
down_revision: Union[str, Sequence[str], None] = "c0989c735473"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("users", sa.Column("is_2fa_enabled", sa.Boolean(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("totp_secret", sa.String(), nullable=True))
    op.add_column("users", sa.Column("backup_codes", sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("users", "backup_codes")
    op.drop_column("users", "totp_secret")
    op.drop_column("users", "is_2fa_enabled")
