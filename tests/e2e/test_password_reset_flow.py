"""
End-to-end tests for password reset functionality.
"""

import pytest
from playwright.sync_api import Page, expect
from app.models.user import UserCreate, UserRole
import re
from tests.e2e.conftest import run_db_action
import json
from uuid import uuid4
from datetime import datetime, timedelta, timezone
import hashlib

def test_complete_password_reset_flow(page: Page, postgres_db_url, base_url, apply_migrations):
    """
    Test complete self-service password reset flow:
    1. Login page -> Forgot password link
    2. Request reset -> check success message
    3. Inject/Get token (simulating email)
    4. Reset password page -> validation
    5. Submit new password
    6. Login with new password
    7. Verify user menu is visible (Non-regression)
    """
    
    # 1. Setup user via helper script
    username = f"reset_user_{uuid4().hex[:8]}"
    email = f"{username}@example.com"
    old_password = "Correct-Horse-Battery-Staple-123!"
    new_password = "Another-Strong-Password-456!"
    
    user_json = run_db_action(
        "create_user", 
        postgres_db_url, 
        username, 
        email, 
        old_password, 
        "user", 
        "true"
    )
    user_id = json.loads(user_json)["id"]
    
    # 2. Go to login page
    page.goto(f"{base_url}/login")
    page.click("text=Mot de passe oublié ?")
    expect(page).to_have_url(re.compile(r"/forgot-password"))
    
    # 3. Request reset
    page.fill("input[name='email']", email)
    page.click("button[type='submit']")
    
    # 4. Check success message
    expect(page.locator("#success-message")).to_be_visible()
    
    # 5. Inject known token (since we can't reverse hash)
    known_token_plaintext = "test-token-1234567890"
    known_token_hash = hashlib.sha256(known_token_plaintext.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    
    run_db_action(
        "raw_execute",
        postgres_db_url,
        "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
        str(uuid4()), user_id, known_token_hash, expires_at
    )
    
    # 6. Go to reset page with known token
    page.goto(f"{base_url}/reset-password?token={known_token_plaintext}")
    
    # 7. Validate form loaded (valid token)
    expect(page.locator("#reset-form-container")).to_be_visible()
    expect(page.locator("#user-email")).to_contain_text(f"{username[0]}***")
    
    # 8. Enter new password
    page.fill("#new_password", new_password)
    page.fill("#confirm_password", new_password)
    
    # Check strength meter
    expect(page.locator("#strength-text")).to_contain_text("Excellent") 
    
    page.click("button[type='submit']")
    
    # 9. Success redirect to login
    page.wait_for_url(re.compile(r"/login"))
    
    # 10. Login with new password
    page.fill("#username", username)
    page.fill("#password", new_password)
    page.click("button[type='submit']")
    
    # Should login successfully
    page.wait_for_url(re.compile(r"/$"))
    
    # 11. Verify user menu is visible (Non-regression)
    user_menu = page.locator("#user-menu")
    expect(user_menu).not_to_have_class(re.compile(r"hidden"))
    
    # 12. Verify initials
    user_initials = page.locator("#user-initials")
    expect(user_initials).to_be_visible()
    
    # 13. Verify logout functional
    page.click("#user-menu-button")
    page.click("#logout-btn")
    page.wait_for_url(re.compile(r"/login"))


def test_admin_reset_user_password(page: Page, postgres_db_url, base_url, apply_migrations):
    """
    Test admin resetting user password via UI and verifying menu visibility after forced change.
    """
    # 1. Setup admin and user
    admin_name = f"admin_{uuid4().hex[:8]}"
    user_name = f"user_{uuid4().hex[:8]}"
    
    admin_password = "Admin-Strong-Password-123!"
    user_password = "User-Strong-Password-123!"
    
    admin_json = run_db_action("create_user", postgres_db_url, admin_name, f"{admin_name}@example.com", admin_password, "admin", "true")
    user_json = run_db_action("create_user", postgres_db_url, user_name, f"{user_name}@example.com", user_password, "user", "true")
    
    # 2. Login as admin
    page.goto(f"{base_url}/login")
    page.fill("#username", admin_name)
    page.fill("#password", admin_password)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/$"))
    
    # 3. Go to admin panel
    page.goto(f"{base_url}/admin")
    
    # 4. Find user and click reset
    page.fill("#search-input", user_name)
    page.click("#refresh-btn") 
    page.wait_for_selector(f"text={user_name}")
    
    row = page.locator("tr", has_text=user_name)
    reset_btn = row.locator("button[title='Reset Password']")
    reset_btn.click()
    
    # 5. Modal interaction
    expect(page.locator("#reset-password-modal")).to_be_visible()
    page.uncheck("#reset-send-email")
    page.click("#confirm-reset-password")
    
    # 6. Check temp password modal
    expect(page.locator("#temp-password-modal")).to_be_visible()
    temp_password = page.locator("#temp-password").text_content()
    assert len(temp_password) > 8
    
    page.click("#close-temp-password-modal")
    
    # 7. Logout admin
    page.goto(f"{base_url}/logout")
    
    # 8. Login as user with temp password
    page.goto(f"{base_url}/login")
    page.fill("#username", user_name)
    page.fill("#password", temp_password)
    page.click("button[type='submit']")
    
    # 9. Should redirect to change-password
    page.wait_for_url(re.compile(r"/change-password"))
    
    # 10. Change password
    page.fill("#current-password", temp_password)
    page.fill("#new-password", "New-Strong-Password-999!")
    page.fill("#confirm-password", "New-Strong-Password-999!")
    page.click("button[type='submit']")
    
    # 11. Should redirect to home
    page.wait_for_url(re.compile(r"/$"))
    
    # 🐛 BUG VERIFICATION: Verify user menu is visible
    # This should fail BEFORE the fix
    user_menu = page.locator("#user-menu")
    expect(user_menu).not_to_have_class(re.compile(r"hidden"))
    
    # 12. Verify initials
    user_initials = page.locator("#user-initials")
    expect(user_initials).to_be_visible()
    expect(user_initials).to_have_text(user_name[:2].upper())
    
    # 13. Dropdown interaction
    page.click("#user-menu-button")
    user_dropdown = page.locator("#user-menu-dropdown")
    expect(user_dropdown).not_to_have_class(re.compile(r"hidden"))
    
    # 14. Verify logout functional
    logout_btn = page.locator("#logout-btn")
    expect(logout_btn).to_be_visible()
    page.click("#logout-btn")
    page.wait_for_url(re.compile(r"/login"))
