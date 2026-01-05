import pytest
from app.auth import create_access_token
from app.models.user import UserCreate, UserRole
from app.services.user_database import get_user_db_service


@pytest.fixture
async def test_user(async_client):
    """
    Creates a regular test user in the database.
    Requires async_client to ensure DB services are initialized.
    """
    user_db = get_user_db_service()

    user_data = UserCreate(
        username="security_test_user", email="security@test.com", password="CorrectHorseBatteryStaple123!@#"
    )

    try:
        # Use auto_approve=True so we can login
        user = await user_db.create_user(user_data, role=UserRole.USER, auto_approve=True)
        return user
    except ValueError:
        return await user_db.get_user_by_username("security_test_user")


@pytest.fixture
def test_user_token_headers(test_user):
    access_token = create_access_token(test_user)
    return {"Authorization": f"Bearer {access_token}"}
