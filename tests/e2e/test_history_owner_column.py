"""
End-to-end tests for the history owner column.
Verifies that admins see the owner column while regular users do not.
"""

import pytest
from playwright.sync_api import Page, expect
import re
from tests.e2e.conftest import run_db_action
import json
from uuid import uuid4

def test_admin_sees_owner_column(page: Page, postgres_db_url, base_url, apply_migrations):
    """Admin should see the OWNER column in history view."""

    # 1. Setup: Create admin and 2 regular users
    admin_username = f"admin_{uuid4().hex[:8]}"
    user1_username = f"user1_{uuid4().hex[:8]}"
    user2_username = f"user2_{uuid4().hex[:8]}"

    password = "Strong-Password-123!"

    admin_json = run_db_action("create_user", postgres_db_url, admin_username,
                                f"{admin_username}@example.com", password, "admin", "true")
    user1_json = run_db_action("create_user", postgres_db_url, user1_username,
                                f"{user1_username}@example.com", password, "user", "true")
    user2_json = run_db_action("create_user", postgres_db_url, user2_username,
                                f"{user2_username}@example.com", password, "user", "true")

    user1_id = json.loads(user1_json)["id"]
    user2_id = json.loads(user2_json)["id"]

    # 2. Create tasks for both users
    task1_id = uuid4().hex
    task2_id = uuid4().hex
    run_db_action("create_task", postgres_db_url, task1_id, "user1_capture.pcap", "1024", user1_id)
    run_db_action("create_task", postgres_db_url, task2_id, "user2_capture.pcap", "2048", user2_id)

    # 3. Login as admin
    page.goto(f"{base_url}/login")
    page.fill("#username", admin_username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/$"))

    # 4. Go to history page
    page.goto(f"{base_url}/history")
    
    # Wait for history container to be visible and not hidden
    # In history.html it starts with class "hidden"
    page.wait_for_selector("#history-container:not(.hidden)", timeout=10000)

    # 5. Verify OWNER column header is visible
    owner_header = page.locator("#owner-column-header")
    expect(owner_header).to_be_visible()
    expect(owner_header).to_have_text("PROPRIÉTAIRE")

    # 6. Verify owner usernames are displayed
    # Check that rows show correct usernames
    expect(page.locator(f"text={user1_username}")).to_be_visible()
    expect(page.locator(f"text={user2_username}")).to_be_visible()


def test_regular_user_does_not_see_owner_column(page: Page, postgres_db_url, base_url, apply_migrations):
    """Regular user should NOT see the OWNER column in history view."""

    # 1. Setup: Create regular user
    username = f"user_{uuid4().hex[:8]}"
    password = "Strong-Password-123!"

    user_json = run_db_action("create_user", postgres_db_url, username,
                               f"{username}@example.com", password, "user", "true")
    user_id = json.loads(user_json)["id"]

    # 2. Create a task
    task_id = uuid4().hex
    run_db_action("create_task", postgres_db_url, task_id, "my_capture.pcap", "1024", user_id)

    # 3. Login as user
    page.goto(f"{base_url}/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/$"))

    # 4. Go to history page
    page.goto(f"{base_url}/history")
    page.wait_for_selector("#history-container:not(.hidden)", timeout=10000)

    # 5. Verify OWNER column header is HIDDEN
    owner_header = page.locator("#owner-column-header")
    expect(owner_header).to_have_class(re.compile(r"hidden"))

    # 6. Verify no owner cells are visible
    # The grid cells for owner have class .grid-cell-owner
    # Non-admin users shouldn't have any visible ones
    owner_cells = page.locator(".grid-cell-owner:not(.hidden)")
    expect(owner_cells).to_have_count(0)
