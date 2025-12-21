"""
SQLite to PostgreSQL data migration utility.

Handles export/import of users, tasks, and progress_snapshots tables
with proper type conversions (UUID, timestamps).
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from app.services.database import DatabaseService
from app.services.user_database import UserDatabaseService


async def export_sqlite_to_json(sqlite_url: str, output_file: str) -> Dict[str, Any]:
    """
    Export SQLite database to JSON file.

    Args:
        sqlite_url: SQLite database URL (e.g., sqlite:///data/pcap_analyzer.db)
        output_file: Path to output JSON file

    Returns:
        Dictionary with exported data
    """
    db = DatabaseService(database_url=sqlite_url)
    await db.init_db()

    user_db = UserDatabaseService(database_url=sqlite_url)
    await user_db.init_db()

    export_data = {
        "metadata": {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "source_type": "sqlite",
            "version": "1.0"
        },
        "users": [],
        "tasks": [],
        "progress_snapshots": []
    }

    # Export users
    rows = await user_db.pool.fetch_all("SELECT * FROM users")
    for row in rows:
        export_data["users"].append(dict(row))

    # Export tasks
    rows = await db.pool.fetch_all("SELECT * FROM tasks")
    for row in rows:
        export_data["tasks"].append(dict(row))

    # Export progress snapshots
    rows = await db.pool.fetch_all("SELECT * FROM progress_snapshots")
    for row in rows:
        export_data["progress_snapshots"].append(dict(row))

    # Write to file
    with open(output_file, 'w') as f:
        json.dump(export_data, f, indent=2, default=str)

    return export_data


async def import_json_to_postgresql(postgres_url: str, input_file: str) -> None:
    """
    Import JSON data to PostgreSQL database.

    Args:
        postgres_url: PostgreSQL database URL
        input_file: Path to input JSON file

    Handles:
    - UUID conversion (TEXT → UUID)
    - Timestamp conversion (ISO string → datetime)
    - NULL owner_id preservation
    """
    with open(input_file, 'r') as f:
        data = json.load(f)

    db = DatabaseService(database_url=postgres_url)
    await db.init_db()

    user_db = UserDatabaseService(database_url=postgres_url)
    await user_db.init_db()

    # Import users
    for user in data["users"]:
        await user_db.pool.execute("""
            INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO NOTHING
        """,
            user["id"], user["username"], user["email"], user["hashed_password"],
            user["role"], user["is_active"], user["is_approved"],
            datetime.fromisoformat(user["created_at"])
        )

    # Import tasks
    for task in data["tasks"]:
        await db.pool.execute("""
            INSERT INTO tasks (
                task_id, filename, status, uploaded_at, analyzed_at,
                file_size_bytes, total_packets, health_score,
                report_html_path, report_json_path, error_message,
                created_at, last_heartbeat, progress_percent, current_phase, owner_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            ON CONFLICT (task_id) DO NOTHING
        """,
            task["task_id"], task["filename"], task["status"],
            datetime.fromisoformat(task["uploaded_at"]) if task["uploaded_at"] else None,
            datetime.fromisoformat(task["analyzed_at"]) if task.get("analyzed_at") else None,
            task["file_size_bytes"], task.get("total_packets"), task.get("health_score"),
            task.get("report_html_path"), task.get("report_json_path"), task.get("error_message"),
            datetime.fromisoformat(task["created_at"]) if task.get("created_at") else None,
            datetime.fromisoformat(task["last_heartbeat"]) if task.get("last_heartbeat") else None,
            task.get("progress_percent", 0), task.get("current_phase"),
            task.get("owner_id")  # May be NULL for legacy data
        )

    # Import progress snapshots
    for snapshot in data["progress_snapshots"]:
        await db.pool.execute("""
            INSERT INTO progress_snapshots (
                task_id, phase, progress_percent, packets_processed,
                total_packets, current_analyzer, message, timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
            snapshot["task_id"], snapshot["phase"], snapshot["progress_percent"],
            snapshot.get("packets_processed"), snapshot.get("total_packets"),
            snapshot.get("current_analyzer"), snapshot.get("message"),
            datetime.fromisoformat(snapshot["timestamp"])
        )


async def migrate_database(sqlite_url: str, postgres_url: str, temp_file: str = "/tmp/migration.json") -> Dict[str, int]:
    """
    Full migration from SQLite to PostgreSQL.

    Args:
        sqlite_url: Source SQLite database URL
        postgres_url: Target PostgreSQL database URL
        temp_file: Temporary JSON file for export

    Returns:
        Statistics: {"users": count, "tasks": count, "progress_snapshots": count}
    """
    # Export SQLite data
    data = await export_sqlite_to_json(sqlite_url, temp_file)

    # Import to PostgreSQL
    await import_json_to_postgresql(postgres_url, temp_file)

    # Return statistics
    return {
        "users": len(data["users"]),
        "tasks": len(data["tasks"]),
        "progress_snapshots": len(data["progress_snapshots"])
    }
