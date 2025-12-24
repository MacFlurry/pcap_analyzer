import pytest
from sqlalchemy import create_engine, inspect
from tests.integration.postgres_conftest import postgres_container, postgres_db_url, apply_migrations

@pytest.mark.integration
def test_migrations_apply_successfully(postgres_db_url, apply_migrations):
    """
    Verify that Alembic migrations applied successfully to the test container.
    """
    # Connect using sync driver for inspection
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    engine = create_engine(sync_url)
    inspector = inspect(engine)
    
    # Get list of tables
    tables = inspector.get_table_names()
    
    # Check for expected tables
    assert "users" in tables
    assert "tasks" in tables
    assert "alembic_version" in tables
    
    # Check columns in users table to verify schema version
    columns = [c["name"] for c in inspector.get_columns("users")]
    assert "username" in columns
    assert "role" in columns
