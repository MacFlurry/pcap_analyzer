import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.user_database import UserDatabaseService, get_user_db_service
import pyotp
import asyncio
from unittest.mock import AsyncMock
from fastapi_csrf_protect import CsrfProtect
from app.auth import get_current_user, get_current_admin_user
from unittest.mock import MagicMock

@pytest.fixture
def auth_client(test_data_dir, monkeypatch):
    """Client for auth testing (no auth mocks)"""
    # Setup DATA_DIR override
    monkeypatch.setenv("DATA_DIR", str(test_data_dir))
    
    # Mock Worker to avoid FS access
    from app.services import worker
    mock_worker = MagicMock()
    mock_worker.start = AsyncMock()
    mock_worker.stop = AsyncMock()
    app.dependency_overrides[worker.get_worker] = lambda: mock_worker
    
    # Mock CleanupScheduler in app.main (module level var)
    from app import main
    main.cleanup_scheduler = MagicMock()
    main.cleanup_scheduler.start = MagicMock()
    main.cleanup_scheduler.stop = MagicMock()
    
    # Setup DB
    db_path = test_data_dir / "test_auth.db"
    db_url = f"sqlite:///{db_path}"
    
    user_db = UserDatabaseService(db_url)
    
    # Also override the singleton to ensure app uses the same instance
    from app.services import user_database
    user_database._user_db_service = user_db
    
    # Initialize DB (async)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(user_db.init_db())
    
    # Create an admin user for the test
    from app.models.user import UserCreate, UserRole
    loop.run_until_complete(user_db.create_user(
        UserCreate(username="admin", email="admin@test.com", password="StrongPassword123!"),
        role=UserRole.ADMIN,
        auto_approve=True
    ))
    
    # Override dependency
    app.dependency_overrides[get_user_db_service] = lambda: user_db

    
    # Mock CSRF
    mock_csrf = AsyncMock()
    mock_csrf.validate_csrf = AsyncMock(return_value=None)
    app.dependency_overrides[CsrfProtect] = lambda: mock_csrf
    
    # Remove auth overrides if any (from conftest)
    # We need to explicitly pop them because conftest might have set them up
    # However, fixtures run before tests. But app.dependency_overrides is global.
    # So we must clean it up.
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_admin_user, None)
    
    with TestClient(app) as client:
        yield client
        
    # Cleanup
    app.dependency_overrides = {}
    loop.close()

def test_2fa_flow(auth_client, test_data_dir):

    user_username = "testuser"

    user_email = "2fa@example.com"

    password = "StrongPassword123!"



    # 1. Login as Admin

    admin_login_res = auth_client.post("/api/token", data={

        "username": "admin",

        "password": "StrongPassword123!"

    })

    assert admin_login_res.status_code == 200

    admin_token = admin_login_res.json()["access_token"]

    admin_headers = {"Authorization": f"Bearer {admin_token}"}



    # 2. Register User

    reg_res = auth_client.post("/api/register", json={

        "username": user_username,

        "email": user_email,

        "password": password

    })

    assert reg_res.status_code == 201

    user_id = reg_res.json()["id"]

    

    # 3. Approve User via Admin API

    approve_res = auth_client.put(f"/api/admin/users/{user_id}/approve", headers=admin_headers)

    assert approve_res.status_code == 200

    

    # 4. Login as User (should succeed without 2FA)

    login_res = auth_client.post("/api/token", data={

        "username": user_username,

        "password": password

    })

    assert login_res.status_code == 200

    token = login_res.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}

    

    # 5. Setup 2FA

    setup_res = auth_client.post("/api/users/me/2fa/setup", headers=headers)

    assert setup_res.status_code == 200

    secret = setup_res.json()["secret"]

    assert secret

    

    # 6. Enable 2FA

    totp = pyotp.TOTP(secret)

    code = totp.now()

    enable_res = auth_client.post("/api/users/me/2fa/enable", headers=headers, json={

        "secret": secret,

        "code": code

    })

    assert enable_res.status_code == 200

    backup_codes = enable_res.json()["backup_codes"]

    assert len(backup_codes) == 10

    

    # 7. Login without 2FA (should fail with 401 MFA Required)

    fail_res = auth_client.post("/api/token", data={

        "username": user_username,

        "password": password

    })

    assert fail_res.status_code == 401

    assert fail_res.headers.get("X-MFA-Required") == "true"

    

    # 8. Login with 2FA (should succeed)

    code = totp.now()

    success_res = auth_client.post("/api/token", data={

        "username": user_username,

        "password": password,

        "totp_code": code

    })

    assert success_res.status_code == 200

    

    # 9. Login with backup code

    backup_code = backup_codes[0]

    backup_res = auth_client.post("/api/token", data={

        "username": user_username,

        "password": password,

        "totp_code": backup_code

    })

    assert backup_res.status_code == 200

    

    # 10. Disable 2FA

    new_token = backup_res.json()["access_token"]

    new_headers = {"Authorization": f"Bearer {new_token}"}

    

    disable_res = auth_client.post("/api/users/me/2fa/disable", headers=new_headers, json={

        "password": password

    })

    assert disable_res.status_code == 200

    

    # 11. Login without 2FA (should succeed again)

    final_res = auth_client.post("/api/token", data={

        "username": user_username,

        "password": password

    })

    assert final_res.status_code == 200





