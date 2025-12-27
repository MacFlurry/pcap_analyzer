"""add_idx_users_created_at

Revision ID: c0989c735473
Revises: 2163cd9a7764
Create Date: 2025-12-24 22:45:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c0989c735473"
down_revision: Union[str, Sequence[str], None] = "2163cd9a7764"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create index on users.created_at for optimized pagination
    op.create_index("idx_users_created_at", "users", ["created_at"])


def downgrade() -> None:
    # Drop index
    op.drop_index("idx_users_created_at", table_name="users")
