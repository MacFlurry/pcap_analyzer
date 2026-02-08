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

    # 2. Call logout
    response = await async_client.post(
        "/api/logout",
        headers=test_user_token_headers
    )
    assert response.status_code == 200
    
    # 3. Verify cookie is cleared in response headers
    # response.delete_cookie sets the cookie with an empty value and Max-Age=0
    set_cookie = response.headers.get("set-cookie", "")
    assert 'access_token="";' in set_cookie or 'access_token=;' in set_cookie or 'access_token=deleted' in set_cookie
    assert "Max-Age=0" in set_cookie

@pytest.mark.asyncio
async def test_protected_html_route_redirects_anonymous(async_client: AsyncClient):
    """
    Test that protected HTML routes redirect anonymous users to login.
    """
    protected_routes = ["/", "/history", "/admin", "/profile", "/change-password"]
    
    for route in protected_routes:
        response = await async_client.get(route, follow_redirects=False)
        
        # Should return 307 Temporary Redirect
        assert response.status_code == 307
        assert "Location" in response.headers
        assert "/login" in response.headers["Location"]
        assert f"returnUrl={route}" in response.headers["Location"]

@pytest.mark.asyncio
async def test_protected_html_route_loads_with_cookie(async_client: AsyncClient, test_user):
    """
    Test that protected HTML routes load correctly when access_token cookie is present.
    """
    # 1. Login to get a valid token
    login_data = {
        "username": test_user.username,
        "password": "CorrectHorseBatteryStaple123!@#"
    }
    login_resp = await async_client.post(
        "/api/token",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert login_resp.status_code == 200
    
    # async_client should now have the cookie from the login response
    assert "access_token" in async_client.cookies
    
    # 2. Access a protected route
    response = await async_client.get("/history", follow_redirects=True)
    
    # 3. Should land on an HTML page
    assert response.status_code == 200
    assert "text/html" in response.headers["Content-Type"]
    assert "pcap" in response.text.lower()
