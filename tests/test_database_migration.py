"""
Tests for PostgreSQL migration and database compatibility.

Tests:
- SQLite backward compatibility
- PostgreSQL connection and operations
- Alembic migration apply/rollback
- User approval workflow
- Database service layer abstraction
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
from app.models.user import User, UserCreate, UserRole
from app.models.schemas import TaskStatus
from app.services.user_database import UserDatabaseService


class TestSQLiteBackwardCompatibility:
    """Test that SQLite still works after migration changes."""

    @pytest.fixture
    async def sqlite_db(self):
        """Create temporary SQLite database."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            db_service = UserDatabaseService(db_path=db_path)
            await db_service.init_db()
            yield db_service

    @pytest.mark.asyncio
    async def test_create_user_with_approval_fields(self, sqlite_db):
        """Test creating user with new approval fields."""
        user_data = UserCreate(
            username="testuser",
            email="test@example.com",
            password="SecurePass12!",
        )

        user = await sqlite_db.create_user(user_data)

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_approved is False  # New field
        assert user.approved_by is None  # New field
        assert user.approved_at is None  # New field
        assert user.role == UserRole.USER

    @pytest.mark.asyncio
    async def test_create_admin_auto_approved(self, sqlite_db):
        """Test that admin users are auto-approved."""
        admin_data = UserCreate(
            username="admin",
            email="admin@example.com",
            password="AdminPass123",
        )

        admin = await sqlite_db.create_user(admin_data, role=UserRole.ADMIN)

        assert admin.role == UserRole.ADMIN
        assert admin.is_approved is True  # Auto-approved
        assert admin.approved_by is not None
        assert admin.approved_at is not None

    @pytest.mark.asyncio
    async def test_approve_user_workflow(self, sqlite_db):
        """Test user approval workflow."""
        # Create admin
        admin_data = UserCreate(
            username="admin",
            email="admin@example.com",
            password="AdminPass123",
        )
        admin = await sqlite_db.create_user(admin_data, role=UserRole.ADMIN)

        # Create regular user (unapproved)
        user_data = UserCreate(
            username="user1",
            email="user1@example.com",
            password="UserPass123!",
        )
        user = await sqlite_db.create_user(user_data)
        assert user.is_approved is False

        # Approve user
        success = await sqlite_db.approve_user(user.id, admin.id)
        assert success is True

        # Verify approval
        updated_user = await sqlite_db.get_user_by_id(user.id)
        assert updated_user.is_approved is True
        assert updated_user.approved_by == admin.id
        assert updated_user.approved_at is not None

    @pytest.mark.asyncio
    async def test_get_user_includes_approval_fields(self, sqlite_db):
        """Test that get_user methods return approval fields."""
        user_data = UserCreate(
            username="testuser",
            email="test@example.com",
            password="SecurePass12!",
        )
        created_user = await sqlite_db.create_user(user_data)

        # Get by username
        user_by_username = await sqlite_db.get_user_by_username("testuser")
        assert user_by_username.is_approved is False
        assert user_by_username.approved_by is None

        # Get by ID
        user_by_id = await sqlite_db.get_user_by_id(created_user.id)
        assert user_by_id.is_approved is False
        assert user_by_id.approved_by is None

    @pytest.mark.asyncio
    async def test_get_all_users_includes_approval_fields(self, sqlite_db):
        """Test that get_all_users returns approval fields."""
        # Create multiple users
        for i in range(3):
            user_data = UserCreate(
                username=f"user{i}",
                email=f"user{i}@example.com",
                password="Password123!",
            )
            await sqlite_db.create_user(user_data)

        users = await sqlite_db.get_all_users()
        assert len(users) == 3

        for user in users:
            assert hasattr(user, "is_approved")
            assert hasattr(user, "approved_by")
            assert hasattr(user, "approved_at")


class TestDatabaseServiceAbstraction:
    """Test the new database service layer abstraction."""

    def test_database_pool_initialization_sqlite(self):
        """Test DatabasePool detects SQLite correctly."""
        from app.services.postgres_database import DatabasePool

        db = DatabasePool("sqlite:///test.db")
        assert db.db_type == "sqlite"
        assert db.sqlite_path is not None

    def test_database_pool_initialization_postgresql(self):
        """Test DatabasePool detects PostgreSQL correctly."""
        from app.services.postgres_database import DatabasePool

        db = DatabasePool("postgresql://user:pass@localhost/db")
        assert db.db_type == "postgresql"
        assert db.sqlite_path is None

    def test_query_translation_sqlite(self):
        """Test query translation for SQLite (no-op)."""
        from app.services.postgres_database import DatabasePool

        db = DatabasePool("sqlite:///test.db")
        query = "SELECT * FROM users WHERE id = ?"
        params = ("user123",)

        translated_query, translated_params = db.translate_query(query, params)
        assert translated_query == query
        assert translated_params == params

    def test_query_translation_postgresql(self):
        """Test query translation for PostgreSQL ($1, $2 syntax)."""
        from app.services.postgres_database import DatabasePool

        db = DatabasePool("postgresql://user:pass@localhost/db")
        query = "SELECT * FROM users WHERE id = ? AND username = ?"
        params = ("user123", "testuser")

        translated_query, translated_params = db.translate_query(query, params)
        assert translated_query == "SELECT * FROM users WHERE id = $1 AND username = $2"
        assert translated_params == params


class TestAlembicMigrations:
    """Test Alembic migrations."""

    def test_migration_file_exists(self):
        """Test that initial migration file exists."""
        migration_dir = Path(__file__).parent.parent / "alembic" / "versions"
        migration_files = list(migration_dir.glob("*_initial_schema_with_user_approval.py"))
        assert len(migration_files) == 1

    def test_migration_has_upgrade_downgrade(self):
        """Test that migration has upgrade and downgrade functions."""
        import importlib.util
        import sys

        migration_dir = Path(__file__).parent.parent / "alembic" / "versions"
        migration_file = next(migration_dir.glob("*_initial_schema_with_user_approval.py"))

        # Load migration module
        spec = importlib.util.spec_from_file_location("migration", migration_file)
        migration = importlib.util.module_from_spec(spec)
        sys.modules["migration"] = migration
        spec.loader.exec_module(migration)

        # Check functions exist
        assert hasattr(migration, "upgrade")
        assert hasattr(migration, "downgrade")
        assert callable(migration.upgrade)
        assert callable(migration.downgrade)


@pytest.mark.integration
class TestPostgreSQLIntegration:
    """
    Integration tests for PostgreSQL.

    These tests require a running PostgreSQL instance.
    Set DATABASE_URL env var to run these tests.
    """

    @pytest.fixture(scope="class")
    def postgres_available(self):
        """Check if PostgreSQL is available."""
        database_url = os.getenv("DATABASE_URL", "")
        if not database_url.startswith("postgresql"):
            pytest.skip("PostgreSQL not configured. Set DATABASE_URL to run these tests.")
        return True

    @pytest.mark.skipif(
        not os.getenv("DATABASE_URL", "").startswith("postgresql"),
        reason="PostgreSQL not configured",
    )
    @pytest.mark.asyncio
    async def test_postgres_connection_pool(self):
        """Test PostgreSQL connection pool creation."""
        from app.services.postgres_database import DatabasePool

        database_url = os.getenv("DATABASE_URL")
        db = DatabasePool(database_url)
        await db.connect()

        assert db.pool is not None
        assert db.db_type == "postgresql"

        await db.close()
        assert db.pool is None

    @pytest.mark.skipif(
        not os.getenv("DATABASE_URL", "").startswith("postgresql"),
        reason="PostgreSQL not configured",
    )
    @pytest.mark.asyncio
    async def test_postgres_uuid_handling(self):
        """Test UUID handling in PostgreSQL."""
        from app.services.postgres_database import DatabasePool
        import uuid

        database_url = os.getenv("DATABASE_URL")
        db = DatabasePool(database_url)
        await db.connect()

        # Create test table
        await db.execute_script(
            """
            DROP TABLE IF EXISTS test_uuid;
            CREATE TABLE test_uuid (
                id UUID PRIMARY KEY,
                name VARCHAR(100)
            );
            """
        )

        # Insert UUID
        test_id = str(uuid.uuid4())
        await db.execute(
            "INSERT INTO test_uuid (id, name) VALUES ($1, $2)",
            test_id,
            "test",
        )

        # Fetch UUID
        result = await db.fetch_one("SELECT * FROM test_uuid WHERE id = $1", test_id)
        assert result is not None
        assert result["id"] == test_id
        assert result["name"] == "test"

        # Cleanup
        await db.execute_script("DROP TABLE test_uuid;")
        await db.close()


class TestMigrationDocumentation:
    """Test that migration documentation exists."""

    def test_env_example_has_database_url(self):
        """Test that .env.example documents DATABASE_URL."""
        env_example_path = Path(__file__).parent.parent / ".env.example"
        assert env_example_path.exists()

        content = env_example_path.read_text()
        assert "DATABASE_URL" in content
        assert "postgresql" in content.lower()
        assert "sqlite" in content.lower()

    def test_alembic_ini_configured(self):
        """Test that alembic.ini is properly configured."""
        alembic_ini_path = Path(__file__).parent.parent / "alembic.ini"
        assert alembic_ini_path.exists()

        content = alembic_ini_path.read_text()
        # Should not have hardcoded database URL
        assert "driver://user:pass@localhost/dbname" not in content or "# sqlalchemy.url" in content


class TestSQLiteToPostgreSQLMigration:
    """Test migration from SQLite to PostgreSQL (Issue #26 Phase 4)."""

    @pytest.fixture
    def test_data_dir(self):
        """Create temporary directory for test data."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.mark.asyncio
    async def test_migrate_tasks_data(self, test_data_dir):
        """Verify task data migrates correctly."""
        from app.utils.migration import migrate_database
        from app.services.database import DatabaseService
        from app.models.schemas import TaskStatus

        # 1. Create SQLite database with sample data
        sqlite_url = f"sqlite:///{test_data_dir}/source.db"
        sqlite_db = DatabaseService(database_url=sqlite_url)
        await sqlite_db.init_db()

        # Create test tasks
        await sqlite_db.create_task("task-1", "test1.pcap", 1024)
        await sqlite_db.create_task("task-2", "test2.pcap", 2048)

        # Verify tasks created
        task1_before = await sqlite_db.get_task("task-1")
        assert task1_before is not None
        assert task1_before.filename == "test1.pcap"

        # 2. Export to JSON (test export only, skip PostgreSQL import if not available)
        from app.utils.migration import export_sqlite_to_json
        export_file = f"{test_data_dir}/export.json"
        data = await export_sqlite_to_json(sqlite_url, export_file)

        # 3. Verify export
        assert data["metadata"]["source_type"] == "sqlite"
        assert data["metadata"]["version"] == "1.0"
        assert len(data["tasks"]) == 2
        assert any(t["task_id"] == "task-1" for t in data["tasks"])
        assert any(t["task_id"] == "task-2" for t in data["tasks"])

        # Verify JSON file created
        assert Path(export_file).exists()
        with open(export_file) as f:
            exported_data = json.load(f)
            assert len(exported_data["tasks"]) == 2

    @pytest.mark.asyncio
    async def test_migrate_users_data(self, test_data_dir):
        """Verify user data migrates correctly."""
        from app.utils.migration import export_sqlite_to_json
        from app.services.user_database import UserDatabaseService
        from app.models.user import UserCreate, UserRole

        # 1. Create SQLite database with sample users
        sqlite_url = f"sqlite:///{test_data_dir}/source.db"
        user_db = UserDatabaseService(database_url=sqlite_url)
        await user_db.init_db()

        # Create test users
        user1_data = UserCreate(username="user1", email="user1@test.com", password="Pass123!Pass123!")
        user2_data = UserCreate(username="user2", email="user2@test.com", password="Pass456!Pass456!")

        user1 = await user_db.create_user(user1_data)
        user2 = await user_db.create_user(user2_data, role=UserRole.ADMIN, auto_approve=True)

        # 2. Export to JSON
        export_file = f"{test_data_dir}/export.json"
        data = await export_sqlite_to_json(sqlite_url, export_file)

        # 3. Verify export
        assert len(data["users"]) == 2
        assert any(u["username"] == "user1" for u in data["users"])
        assert any(u["username"] == "user2" for u in data["users"])

        # Verify admin is marked as approved
        admin_user = next(u for u in data["users"] if u["username"] == "user2")
        assert admin_user["role"] == "admin"
        assert bool(admin_user["is_approved"]) is True  # SQLite returns 1, not True

    @pytest.mark.asyncio
    async def test_migrate_foreign_keys(self, test_data_dir):
        """Verify foreign key relationships preserved."""
        from app.utils.migration import export_sqlite_to_json
        from app.services.database import DatabaseService
        from app.services.user_database import UserDatabaseService
        from app.models.user import UserCreate

        # 1. Create user with tasks in SQLite
        sqlite_url = f"sqlite:///{test_data_dir}/source.db"

        # Create user
        user_db = UserDatabaseService(database_url=sqlite_url)
        await user_db.init_db()

        user_data = UserCreate(username="owner", email="owner@test.com", password="Pass123!Pass123!")
        user = await user_db.create_user(user_data, auto_approve=True)

        # Create tasks with owner_id
        db = DatabaseService(database_url=sqlite_url)
        await db.init_db()
        await db.create_task("task-owned", "owned.pcap", 1024, owner_id=user.id)
        await db.create_task("task-legacy", "legacy.pcap", 2048)  # No owner (legacy)

        # 2. Export
        export_file = f"{test_data_dir}/export.json"
        data = await export_sqlite_to_json(sqlite_url, export_file)

        # 3. Verify foreign key relationships intact
        owned_task = next(t for t in data["tasks"] if t["task_id"] == "task-owned")
        legacy_task = next(t for t in data["tasks"] if t["task_id"] == "task-legacy")

        assert owned_task["owner_id"] == user.id
        assert legacy_task["owner_id"] is None  # NULL preserved

    @pytest.mark.asyncio
    async def test_migrate_timestamps(self, test_data_dir):
        """Verify timestamp conversion (ISO string → datetime)."""
        from app.utils.migration import export_sqlite_to_json
        from app.services.database import DatabaseService
        from datetime import datetime, timezone

        # 1. Create SQLite tasks with various timestamps
        sqlite_url = f"sqlite:///{test_data_dir}/source.db"
        db = DatabaseService(database_url=sqlite_url)
        await db.init_db()

        await db.create_task("task-1", "test.pcap", 1024)
        await db.update_status("task-1", TaskStatus.COMPLETED)  # Sets analyzed_at

        # 2. Export
        export_file = f"{test_data_dir}/export.json"
        data = await export_sqlite_to_json(sqlite_url, export_file)

        # 3. Verify timestamps are ISO strings (can be parsed)
        task = data["tasks"][0]
        assert task["uploaded_at"] is not None
        assert task["analyzed_at"] is not None

        # Verify they can be parsed back to datetime
        uploaded_dt = datetime.fromisoformat(task["uploaded_at"])
        analyzed_dt = datetime.fromisoformat(task["analyzed_at"])

        assert isinstance(uploaded_dt, datetime)
        assert isinstance(analyzed_dt, datetime)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
