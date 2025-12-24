import pytest
import os
import asyncio
from testcontainers.postgres import PostgresContainer
from alembic.config import Config
from alembic import command

@pytest.fixture(scope="session")
def postgres_container():
    """
    Spins up a PostgreSQL container for integration tests.
    Returns the connection URL.
    """
    # Use postgres:15-alpine to match production recommendation
    with PostgresContainer("postgres:15-alpine") as postgres:
        # testcontainers waits for the container to be ready
        
        # Get connection URL
        # Driver is usually psycopg2 by default in connection string from testcontainers
        db_url = postgres.get_connection_url()
        
        # Ensure compatibility with asyncpg (used by the app)
        if db_url.startswith("postgresql+psycopg2://"):
            async_db_url = db_url.replace("postgresql+psycopg2://", "postgresql://")
        else:
            async_db_url = db_url
            
        yield async_db_url

@pytest.fixture(scope="session")
def postgres_db_url(postgres_container):
    """
    Sets the DATABASE_URL environment variable to the container's URL.
    This ensures that any code reading os.environ["DATABASE_URL"] gets the test container.
    """
    os.environ["DATABASE_URL"] = postgres_container
    return postgres_container

@pytest.fixture(scope="session")
def apply_migrations(postgres_db_url):
    """
    Applies Alembic migrations to the test container.
    """
    # Create Alembic configuration
    # Assuming alembic.ini is in the root project directory
    alembic_cfg = Config("alembic.ini")
    
    # Override the sqlalchemy.url in the configuration
    # We need to use the sync driver (psycopg2) for Alembic
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    alembic_cfg.set_main_option("sqlalchemy.url", sync_url)
    
    # Run migrations
    command.upgrade(alembic_cfg, "head")
    
    yield
    
    # Optional: Downgrade on teardown if needed, but container destruction covers cleanup
    # command.downgrade(alembic_cfg, "base")
