"""
Helper script to perform async DB operations from a sync environment.
Used by E2E tests to avoid event loop conflicts.
"""

import asyncio
import json
import sys
import os
import uuid

# Add current directory to path to allow importing app
sys.path.append(os.getcwd())

from app.services.user_database import UserDatabaseService
from app.services.database import DatabaseService
from app.models.user import UserCreate, UserRole
from app.models.schemas import TaskStatus


async def main():
    if len(sys.argv) < 2:
        print("Usage: db_helper.py <action> [args...]")
        sys.exit(1)

    action = sys.argv[1]
    db_url = sys.argv[2]

    user_service = UserDatabaseService(database_url=db_url)
    task_service = DatabaseService(database_url=db_url)

    try:
        await user_service.init_db()
        await task_service.init_db()

        if action == "create_user":
            username = sys.argv[3]
            email = sys.argv[4]
            password = sys.argv[5]
            role = sys.argv[6] if len(sys.argv) > 6 else "user"
            auto_approve = sys.argv[7] == "true" if len(sys.argv) > 7 else False

            user = await user_service.create_user(
                UserCreate(username=username, email=email, password=password),
                role=UserRole(role),
                auto_approve=auto_approve,
            )
            print(user.json())

        elif action == "create_task":
            # task_id, filename, file_size, owner_id
            task_id = sys.argv[3]
            filename = sys.argv[4]
            file_size = int(sys.argv[5])
            owner_id = sys.argv[6]

            task = await task_service.create_task(
                task_id=task_id, filename=filename, file_size_bytes=file_size, owner_id=owner_id
            )
            # Mark as completed to show in history
            await task_service.update_status(task_id, TaskStatus.COMPLETED)
            print("success")

        elif action == "raw_execute":
            query = sys.argv[3]
            # Convert args to tuple if present and parse datetimes
            from datetime import datetime

            raw_params = sys.argv[4:]
            params = []
            for p in raw_params:
                try:
                    # Try to parse as ISO datetime if it looks like one
                    if isinstance(p, str) and (p.count("-") >= 2 and "T" in p):
                        params.append(datetime.fromisoformat(p.replace("Z", "+00:00")))
                    else:
                        params.append(p)
                except ValueError:
                    params.append(p)

            params = tuple(params)
            query, params = user_service.pool.translate_query(query, params)
            await user_service.pool.execute(query, *params)
            print("success")

        elif action == "fetch_val":
            query = sys.argv[3]
            params = tuple(sys.argv[4:])
            query, params = user_service.pool.translate_query(query, params)
            row = await user_service.pool.fetch_one(query, *params)
            if row:
                # Print first column value
                print(list(row.values())[0])
            else:
                print("None")

        elif action == "block_user":
            user_id = sys.argv[3]
            await user_service.block_user(user_id)
            print("success")

        elif action == "init":
            print("success")

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
    finally:
        if user_service.pool.pool:
            await user_service.pool.close()
        if task_service.pool.pool:
            await task_service.pool.close()


if __name__ == "__main__":
    asyncio.run(main())
