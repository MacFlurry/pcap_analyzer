"""initial_schema_with_user_approval

Revision ID: eba0e1bcc7ec
Revises:
Create Date: 2025-12-20 23:10:07.283115

This migration creates the initial schema for pcap_analyzer with:
- users table (with approval workflow fields)
- tasks table (with owner_id foreign key)
- progress_snapshots table

PostgreSQL enhancements:
- UUID primary keys (instead of TEXT)
- ON DELETE CASCADE for foreign keys
- User approval workflow fields
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "eba0e1bcc7ec"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Detect database type
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    # Define ID type based on database
    if is_postgres:
        id_type = postgresql.UUID(as_uuid=False)  # Store as string for compatibility
    else:
        id_type = sa.String(36)  # SQLite: TEXT with 36 chars (UUID length)

    # Create users table
    op.create_table(
        "users",
        sa.Column("id", id_type, primary_key=True, nullable=False),
        sa.Column("username", sa.String(50), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("is_approved", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("approved_by", id_type, nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("role IN ('admin', 'user')", name="role_check"),
    )

    # Add foreign key for approved_by (self-referential)
    if is_postgres:
        op.create_foreign_key("fk_users_approved_by", "users", "users", ["approved_by"], ["id"], ondelete="SET NULL")

    # Create indexes for users
    op.create_index("idx_users_username", "users", ["username"], unique=True)
    op.create_index("idx_users_email", "users", ["email"], unique=True)
    op.create_index("idx_users_role", "users", ["role"])

    # Create tasks table
    op.create_table(
        "tasks",
        sa.Column("task_id", id_type, primary_key=True, nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("total_packets", sa.Integer(), nullable=True),
        sa.Column("health_score", sa.Float(), nullable=True),
        sa.Column("report_html_path", sa.String(500), nullable=True),
        sa.Column("report_json_path", sa.String(500), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress_percent", sa.Integer(), server_default="0"),
        sa.Column("current_phase", sa.String(50), nullable=True),
        sa.Column("owner_id", id_type, nullable=True),
    )

    # Add foreign key for owner_id with CASCADE delete
    if is_postgres:
        op.create_foreign_key("fk_tasks_owner_id", "tasks", "users", ["owner_id"], ["id"], ondelete="CASCADE")

    # Create indexes for tasks
    op.create_index("idx_status", "tasks", ["status"])
    op.create_index("idx_uploaded_at", "tasks", ["uploaded_at"])
    op.create_index("idx_tasks_heartbeat", "tasks", ["last_heartbeat"])
    op.create_index("idx_tasks_owner_id", "tasks", ["owner_id"])

    # Create progress_snapshots table
    op.create_table(
        "progress_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("task_id", id_type, nullable=False),
        sa.Column("phase", sa.String(50), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("packets_processed", sa.Integer(), nullable=True),
        sa.Column("total_packets", sa.Integer(), nullable=True),
        sa.Column("current_analyzer", sa.String(100), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )

    # Add foreign key for task_id with CASCADE delete
    if is_postgres:
        op.create_foreign_key(
            "fk_progress_snapshots_task_id", "progress_snapshots", "tasks", ["task_id"], ["task_id"], ondelete="CASCADE"
        )

    # Create indexes for progress_snapshots
    op.create_index("idx_progress_task_id", "progress_snapshots", ["task_id"])
    op.create_index("idx_progress_timestamp", "progress_snapshots", ["timestamp"])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop tables in reverse order (respect foreign keys)
    op.drop_table("progress_snapshots")
    op.drop_table("tasks")
    op.drop_table("users")
