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
from app.models.user import UserCreate, UserRole

async def main():
    if len(sys.argv) < 2:
        print("Usage: db_helper.py <action> [args...]")
        sys.exit(1)
        
    action = sys.argv[1]
    db_url = sys.argv[2]
    
    service = UserDatabaseService(database_url=db_url)
    try:
        await service.init_db()
        
        if action == "create_user":
            username = sys.argv[3]
            email = sys.argv[4]
            password = sys.argv[5]
            role = sys.argv[6] if len(sys.argv) > 6 else "user"
            auto_approve = sys.argv[7] == "true" if len(sys.argv) > 7 else False
            
            user = await service.create_user(
                UserCreate(username=username, email=email, password=password),
                role=UserRole(role),
                auto_approve=auto_approve
            )
            print(user.json())
            
        elif action == "block_user":
            user_id = sys.argv[3]
            await service.block_user(user_id)
            print("success")
            
        elif action == "init":
            print("success")
            
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)
    finally:
        if service.pool.pool:
            await service.pool.close()

if __name__ == "__main__":
    asyncio.run(main())