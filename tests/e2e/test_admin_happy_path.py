"""
E2E tests for the Admin Panel happy path scenarios.
"""

import pytest
import uuid
from playwright.sync_api import expect

@pytest.mark.e2e
def test_admin_full_workflow(page, server_url, admin_user, sync_user_db):
    """
    Test complete admin workflow:
    1. Login
    2. View user list
    3. Create user (pending)
    4. Approve user
    5. Block/Unblock user
    """
    admin, password = admin_user
    
    # 1. Login
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    # 2. Go to Admin Panel
    page.goto(f"{server_url}/admin")
    page.wait_for_selector("h1:has-text('Admin Panel')")
    
    # 3. Create a new user (via helper to ensure it's PENDING)
    target_username = f"pending_{uuid.uuid4().hex[:4]}"
    sync_user_db.create_user(target_username, f"{target_username}@test.com", "SecurePassword123!", auto_approve=False)
    
    # 4. Filter by pending and approve
    page.reload() 
    page.wait_for_selector("#filter-pending")
    page.click("#filter-pending")
    page.fill("#search-input", target_username)
    
    user_row = page.locator(f"tr:has-text('{target_username}')")
    expect(user_row).to_be_visible(timeout=10000)
    
    # Click approve
    user_row.locator(".action-btn-approve").click()
    page.wait_for_timeout(2000)
    
    # 5. Filter by approved and block
    page.reload()
    page.wait_for_selector("#filter-approved")
    page.click("#filter-approved")
    page.fill("#search-input", target_username)
    
    expect(user_row).to_be_visible(timeout=10000)
    expect(user_row.locator(".status-badge")).to_contain_text("Approved")
    
    # Block
    page.on("dialog", lambda dialog: dialog.accept())
    user_row.locator(".action-btn-block").click()
    page.wait_for_timeout(2000)
    
    # Verify Blocked state
    page.reload()
    page.click("#filter-blocked")
    page.fill("#search-input", target_username)
    expect(user_row).to_be_visible(timeout=10000)
    expect(user_row.locator(".status-badge")).to_contain_text("Blocked")
    
    # 6. Unblock
    user_row.locator(".action-btn-unblock").click()
    page.wait_for_timeout(2000)
    page.reload()
    page.click("#filter-approved")
    page.fill("#search-input", target_username)
    expect(user_row.locator(".status-badge")).to_contain_text("Approved", timeout=10000)

@pytest.mark.e2e
def test_admin_create_user_modal_behavior(page, server_url, admin_user):
    """Test modal open, cancel, and Escape key behavior."""
    admin, password = admin_user
    
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    page.goto(f"{server_url}/admin")
    page.wait_for_selector("h1:has-text('Admin Panel')")
    
    # 1. Open and Cancel
    page.wait_for_selector("#create-user-btn", state="visible")
    page.click("#create-user-btn")
    expect(page.locator("#create-user-modal")).to_be_visible()
    
    page.click("#cancel-create-user")
    expect(page.locator("#create-user-modal")).to_be_hidden()
    
    # 2. Open and Escape
    page.click("#create-user-btn")
    expect(page.locator("#create-user-modal")).to_be_visible()
    page.keyboard.press("Escape")
    expect(page.locator("#create-user-modal")).to_be_hidden()

@pytest.mark.e2e
def test_admin_bulk_actions(page, server_url, admin_user, sync_user_db):
    """Test bulk approval and blocking."""
    admin, password = admin_user
    u1_name = f"bulk1_{uuid.uuid4().hex[:4]}"
    u2_name = f"bulk2_{uuid.uuid4().hex[:4]}"
    
    sync_user_db.create_user(u1_name, f"{u1_name}@test.com", "SecurePassword123!", auto_approve=False)
    sync_user_db.create_user(u2_name, f"{u2_name}@test.com", "SecurePassword123!", auto_approve=False)
    
    # 1. Login
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    # 2. Go to Admin Panel
    page.goto(f"{server_url}/admin")
    page.wait_for_selector("h1:has-text('Admin Panel')")
    
    # 3. Reload to see new users
    page.reload()
    page.wait_for_selector("#filter-pending")
    page.click("#filter-pending")
    page.fill("#search-input", "bulk")
    
    # Wait for rows
    page.wait_for_selector(f"tr:has-text('{u1_name}')")
    page.wait_for_selector(f"tr:has-text('{u2_name}')")
    
    page.locator(f"tr:has-text('{u1_name}') .user-checkbox").check()
    page.locator(f"tr:has-text('{u2_name}') .user-checkbox").check()
    
    expect(page.locator("#bulk-actions-bar")).to_be_visible()
    
    # Bulk approve
    page.on("dialog", lambda dialog: dialog.accept())
    page.click("#bulk-approve")
    page.wait_for_timeout(3000)
    
    # Verify approved
    page.reload()
    page.click("#filter-approved")
    page.fill("#search-input", "bulk")
    
    expect(page.locator(f"tr:has-text('{u1_name}')")).to_be_visible(timeout=10000)
    expect(page.locator(f"tr:has-text('{u2_name}')")).to_be_visible(timeout=10000)
