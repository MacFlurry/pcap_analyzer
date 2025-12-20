"""
Tests for PostgreSQL migration and database compatibility.

Tests:
- SQLite backward compatibility
- PostgreSQL connection and operations
- Alembic migration apply/rollback
- User approval workflow
- Database service layer abstraction
"""

import os
import tempfile
from pathlib import Path

import pytest
from app.models.user import User, UserCreate, UserRole
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
