"""
E2E tests for the Admin Panel edge cases.
"""

import pytest
import uuid
import re
from playwright.sync_api import expect

@pytest.mark.e2e
def test_unauthorized_access(page, server_url, sync_user_db):
    """Test that non-admin users cannot access the admin panel."""
    username = f"user_{uuid.uuid4().hex[:4]}"
    password = "SecurePassword123!"
    sync_user_db.create_user(username, f"{username}@test.com", password, auto_approve=True)
    
    page.goto(f"{server_url}/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page.locator("#admin-nav-link")).not_to_be_visible()
    
    page.goto(f"{server_url}/admin")
    expect(page).to_have_url(f"{server_url}/login?returnUrl=/admin")

@pytest.mark.e2e
def test_backend_error_handling(page, server_url, admin_user):
    """Test UI behavior when API returns 500."""
    admin, password = admin_user
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    # Mock ONLY /api/users?limit=50... (the data fetch)
    page.route("**/api/users?limit=50*", lambda route: route.fulfill(
        status=500,
        content_type="application/json",
        body='{"detail": "Internal error"}'
    ))
    
    page.goto(f"{server_url}/admin")
    expect(page.locator("#empty-state")).to_be_visible(timeout=15000)

@pytest.mark.e2e
def test_empty_user_list(page, server_url, admin_user):
    """Test UI behavior when no users exist."""
    admin, password = admin_user
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    # Mock ONLY /api/users?limit=50...
    page.route("**/api/users?limit=50*", lambda route: route.fulfill(
        status=200,
        content_type="application/json",
        body='{"users": [], "total": 0, "limit": 50, "offset": 0}'
    ))
    
    page.goto(f"{server_url}/admin")
    expect(page.locator("#empty-state")).to_be_visible(timeout=15000)
