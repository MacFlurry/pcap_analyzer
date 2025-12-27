"""
E2E testing configuration and fixtures (Sync with Process isolation).
Uses a separate process for DB operations to avoid event loop conflicts.
"""

import os
import socket
import threading
import time
import uuid
import subprocess
import json
import sys
from typing import Generator

import pytest
import uvicorn
from alembic import command
from alembic.config import Config
from testcontainers.postgres import PostgresContainer

from app.models.user import User

from tests.conftest import test_data_dir


def run_db_action(action, db_url, *args):
    """Run a DB action in a separate process."""
    cmd = ["python3", "scripts/db_helper.py", action, db_url] + list(args)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"DB Action Failed: {e.stderr}", file=sys.stderr)
        raise


@pytest.fixture(scope="session")
def postgres_container():
    with PostgresContainer("postgres:15-alpine") as postgres:
        db_url = postgres.get_connection_url()
        if db_url.startswith("postgresql+psycopg2://"):
            async_db_url = db_url.replace("postgresql+psycopg2://", "postgresql://")
        else:
            async_db_url = db_url

        # Set it early for the session
        os.environ["DATABASE_URL"] = async_db_url
        yield async_db_url


@pytest.fixture(scope="session")
def postgres_db_url(postgres_container):
    return postgres_container


@pytest.fixture(scope="session")
def apply_migrations(postgres_db_url):
    alembic_cfg = Config("alembic.ini")
    sync_url = postgres_db_url.replace("postgresql://", "postgresql+psycopg2://")
    # env.py prefers DATABASE_URL env var, so we must set it to sync_url for migration to work
    os.environ["DATABASE_URL"] = sync_url
    alembic_cfg.set_main_option("sqlalchemy.url", sync_url)
    command.upgrade(alembic_cfg, "head")

    # Restore async URL for the app
    os.environ["DATABASE_URL"] = postgres_db_url
    yield


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class UvicornThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=8000):
        super().__init__()
        self.server = uvicorn.Server(config=uvicorn.Config(app, host=host, port=port, log_level="error"))
        self.daemon = True

    def run(self):
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.server.run()

    def stop(self):
        self.server.should_exit = True


@pytest.fixture(scope="session")
def server_url(postgres_db_url, apply_migrations, tmp_path_factory) -> Generator[str, None, None]:
    data_dir = tmp_path_factory.mktemp("e2e_data")
    os.environ["DATA_DIR"] = str(data_dir)
    os.environ["DATABASE_URL"] = postgres_db_url
    os.environ["SECRET_KEY"] = "test_secret_key_must_be_32_chars_long_min"

    # Import app here after env vars are set
    from app.main import app

    # Reset all singletons to pick up new environment variables
    from app.services import database, worker, user_database, postgres_database, analyzer, password_reset_service

    database._db_service = None
    worker._worker = None
    user_database._user_db_service = None
    postgres_database._db_pool = None
    analyzer._analyzer_service = None
    password_reset_service._password_reset_service = None

    port = get_free_port()
    host = "127.0.0.1"
    url = f"http://{host}:{port}"

    thread = UvicornThread(app, host=host, port=port)
    thread.start()

    max_retries = 30
    for i in range(max_retries):
        try:
            with socket.create_connection((host, port), timeout=1):
                break
        except OSError:
            time.sleep(0.5)

    yield url
    thread.stop()


@pytest.fixture(scope="session")
def base_url(server_url):
    return server_url


@pytest.fixture(scope="session")
def admin_user(postgres_db_url, apply_migrations):
    username = f"admin_{uuid.uuid4().hex[:4]}"
    password = "SecurePassword123!"

    user_json = run_db_action(
        "create_user", postgres_db_url, username, f"{username}@test.com", password, "admin", "true"
    )
    user = User.parse_raw(user_json)
    return user, password


# Wrapper class for user_db to be used in sync tests
class SyncUserDb:
    def __init__(self, db_url):
        self.db_url = db_url

    def create_user(self, username, email, password, role="user", auto_approve="false"):
        user_json = run_db_action(
            "create_user", self.db_url, username, email, password, role, str(auto_approve).lower()
        )
        return User.parse_raw(user_json)

    def block_user(self, user_id):
        run_db_action("block_user", self.db_url, user_id)


@pytest.fixture(scope="session")
def sync_user_db(postgres_db_url):
    return SyncUserDb(postgres_db_url)
