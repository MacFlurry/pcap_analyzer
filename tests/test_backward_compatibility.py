"""
Backward compatibility tests to ensure SQLite still works as dev mode.

Tests verify that SQLite remains functional after PostgreSQL becomes
the production default database.
"""

import os
import pytest
from pathlib import Path

from app.services.postgres_database import DatabasePool
from app.services.database import DatabaseService, _parse_timestamp
from datetime import datetime


@pytest.mark.asyncio
async def test_default_database_is_sqlite(monkeypatch):
    """Verify application defaults to SQLite when DATABASE_URL not set."""
    # 1. Unset DATABASE_URL
    monkeypatch.delenv("DATABASE_URL", raising=False)

    # 2. Create DatabasePool (should auto-detect SQLite)
    pool = DatabasePool()

    # 3. Verify db_type == "sqlite"
    assert pool.db_type == "sqlite"

    # 4. Verify database_url contains "sqlite://"
    assert "sqlite://" in pool.database_url


@pytest.mark.asyncio
async def test_sqlite_query_no_translation():
    """Verify SQLite queries use ? placeholders (no translation)."""
    pool = DatabasePool(database_url="sqlite:///test.db")

    query = "SELECT * FROM tasks WHERE task_id = ? AND status = ?"
    params = ("task-1", "pending")

    translated_query, translated_params = pool.translate_query(query, params)

    # SQLite queries should NOT be translated
    assert translated_query == query
    assert translated_params == params


@pytest.mark.asyncio
async def test_postgresql_query_translation():
    """Verify PostgreSQL queries translate ? to $1, $2."""
    pool = DatabasePool(database_url="postgresql://localhost/test")

    query = "SELECT * FROM tasks WHERE task_id = ? AND status = ?"
    params = ("task-1", "pending")

    translated_query, translated_params = pool.translate_query(query, params)

    # PostgreSQL queries should be translated
    assert translated_query == "SELECT * FROM tasks WHERE task_id = $1 AND status = $2"
    assert translated_params == params


@pytest.mark.asyncio
async def test_parse_timestamp_sqlite_string():
    """Verify _parse_timestamp handles SQLite ISO strings."""
    timestamp_str = "2025-12-21T20:00:00.123456"
    result = _parse_timestamp(timestamp_str)

    assert isinstance(result, datetime)
    assert result.year == 2025
    assert result.month == 12
    assert result.day == 21


@pytest.mark.asyncio
async def test_parse_timestamp_postgresql_datetime():
    """Verify _parse_timestamp handles PostgreSQL datetime objects."""
    timestamp_obj = datetime.now()
    result = _parse_timestamp(timestamp_obj)

    # Should return the same datetime object
    assert result == timestamp_obj
    assert isinstance(result, datetime)


@pytest.mark.asyncio
async def test_parse_timestamp_none():
    """Verify _parse_timestamp handles NULL values."""
    result = _parse_timestamp(None)
    assert result is None
