import pytest
import uuid
import pyotp
import os
import re
from playwright.sync_api import Page, expect

@pytest.mark.e2e
def test_full_lifecycle_workflow(page: Page, server_url, admin_user):
    """
    Complete workflow: Registration -> Approval -> 2FA -> Analysis
    """
    # Enable console logging
    page.on("console", lambda msg: print(f"BROWSER CONSOLE: {msg.type}: {msg.text}"))
    page.on("pageerror", lambda exc: print(f"BROWSER ERROR: {exc}"))
    
    admin, admin_password = admin_user
    username = f"user_{uuid.uuid4().hex[:6]}"
    email = f"{username}@example.com"
    password = "SecurePassword123!"
    
    # 1. Registration
    page.goto(f"{server_url}/register")
    page.fill("#username", username)
    page.fill("#email", email)
    page.fill("#password", password)
    page.fill("#confirm-password", password)
    page.click("button[type='submit']")
    
    # Wait for success message
    expect(page.locator("#success-message")).to_be_visible()
    expect(page.locator("#success-text")).to_contain_text("Inscription réussie")
    
    # 2. Try Login (Should fail - pending approval)
    page.goto(f"{server_url}/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    expect(page.locator("#error-message")).to_be_visible()
    expect(page.locator("#error-text")).to_contain_text("pending approval")
    
    # 3. Admin Approval
    # Login as admin
    page.goto(f"{server_url}/login")
    page.fill("#username", admin.username)
    page.fill("#password", admin_password)
    page.click("button[type='submit']")
    expect(page).to_have_url(f"{server_url}/")
    
    # Go to admin panel and approve
    page.goto(f"{server_url}/admin")
    page.click("#filter-pending")
    page.fill("#search-input", username)
    
    user_row = page.locator(f"tr:has-text('{username}')")
    expect(user_row).to_be_visible(timeout=10000)
    user_row.locator(".action-btn-approve").click()
    page.wait_for_timeout(1000) # Wait for animation/API
    
    # Logout admin
    page.click("#user-menu-button")
    page.click("#logout-btn")
    expect(page).to_have_url(f"{server_url}/login")
    
    # 4. User Login & 2FA Setup
    page.goto(f"{server_url}/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-button")
    
    # Wait for redirect to home
    expect(page).to_have_url(f"{server_url}/", timeout=10000)
    
    # Go to profile
    page.goto(f"{server_url}/profile")
    page.wait_for_selector("#toggle-2fa-btn")
    page.click("#toggle-2fa-btn")
    
    # Wait for modal
    setup_modal = page.locator('[id="2fa-setup-modal"]')
    expect(setup_modal).to_be_visible(timeout=10000)
    
    # Extract secret key
    secret_key = page.locator("#secret-key-display").text_content()
    assert secret_key
    
    # Generate TOTP and verify
    totp = pyotp.TOTP(secret_key)
    code = totp.now()
    page.fill("#verify-code", code)
    page.click("#verify-2fa-form button[type='submit']")
    
    # Should see success screen
    expect(page.locator("#setup-step-2")).to_be_visible(timeout=10000)
    page.click("#setup-step-2 button") # Click Finish (reloads)
    
    # Verify 2FA badge is ENABLED
    page.wait_for_selector('[id="2fa-status-badge"]')
    expect(page.locator('[id="2fa-status-badge"]')).to_contain_text("ACTIVÉ")
    
    # 5. Logout and Login with 2FA
    page.click("#user-menu-button")
    page.click("#logout-btn")
    expect(page).to_have_url(f"{server_url}/login")
    
    # Enter credentials
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    
    # Should see 2FA prompt
    expect(page.locator("#mfa-section")).to_be_visible()
    
    # Enter valid TOTP
    code = totp.now()
    page.fill("#totp_code", code)
    page.click("#login-button")
    expect(page).to_have_url(f"{server_url}/")
    
    # 6. Perform Analysis
    # Upload PCAP
    pcap_path = os.path.abspath("tests/test_data/test_bidirectional.pcap")
    page.set_input_files("#file-input", pcap_path)
    
    # Click upload button (starts analysis)
    page.wait_for_selector("#upload-btn")
    page.click("#upload-btn")
    
    # Wait for analysis to complete
    expect(page).to_have_url(re.compile(r".*/progress/.*"), timeout=15000)
    # Wait for completion (action buttons show up)
    expect(page.locator("#action-buttons")).to_be_visible(timeout=30000)
    expect(page.locator("#progress-percent")).to_contain_text("100%")
    
    # Go to report (opens in new tab)
    with page.context.expect_page() as new_page_info:
        page.click("#view-report-btn")
    
    new_page = new_page_info.value
    new_page.wait_for_load_state()
    
    expect(new_page).to_have_url(re.compile(r".*/reports/.*"), timeout=10000)
    expect(new_page.locator("h1")).to_contain_text("PCAP Analysis Report")
    
    # Close new page and go back to history on main page
    new_page.close()
    
    # 7. Cleanup
    # Delete report from history
    page.goto(f"{server_url}/history")
    
    # Wait for table to load (loading spinner disappears)
    page.wait_for_selector("#loading", state="hidden", timeout=10000)
    
    # Wait for delete button to appear
    delete_btn = page.locator(".btn-delete").first
    expect(delete_btn).to_be_visible(timeout=10000)
    
    # Click delete and accept dialog
    page.on("dialog", lambda dialog: dialog.accept())
    delete_btn.click()
    
    # Wait for empty state
    expect(page.locator("#empty-state")).to_be_visible(timeout=10000)
