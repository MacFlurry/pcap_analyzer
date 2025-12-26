import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_sets_cookie(async_client: AsyncClient, test_user):
    """
    Test that the login endpoint sets an HttpOnly access_token cookie
    alongside the standard JSON response.
    """
    # 1. Login with valid credentials
    login_data = {
        "username": test_user.username,
        "password": "CorrectHorseBatteryStaple123!@#"
    }

    # The endpoint is /api/token (OAuth2 standard)
    response = await async_client.post(
        "/api/token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )    
    # 2. Verify success
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    
    # 3. Verify Cookie presence
    assert "access_token" in response.cookies
    cookie = response.cookies["access_token"]
    assert cookie == data["access_token"]

@pytest.mark.asyncio
async def test_logout_clears_cookie(async_client: AsyncClient, test_user_token_headers):
    """
    Test that logout clears the access_token cookie.
    """
    # 1. Manually set a cookie
    async_client.cookies.set("access_token", "fake_token", domain="localhost")

    # 2. Call logout (New endpoint we need to create)
    # Note: We assume /api/logout will be created.
    # Current behavior might be 404.
    response = await async_client.post(
        "/api/logout",
        headers=test_user_token_headers
    )    
    assert response.status_code == 200
    
    # 3. Verify cookie is cleared
    # In httpx, checking if key exists or value is empty
    val = response.cookies.get("access_token")
    # Either the key is gone, or value is empty
    assert not val