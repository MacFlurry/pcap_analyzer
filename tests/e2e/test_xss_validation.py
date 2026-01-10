import pytest
from playwright.sync_api import Page, expect

def test_toast_xss_protection(page: Page, server_url):
    """
    Vérifie que les messages de toast sont échappés.
    C est le test le plus fiable car window.toast est global.
    """
    page.goto(f"{server_url}/login")
    page.wait_for_load_state("networkidle")
    
    # Injecter un toast via console avec un payload XSS
    xss_payload = "<b id='xss-target-toast'>XSS_PROTECTED</b>"
    page.evaluate(f"window.toast.info(\"{xss_payload}\")")
    
    # Vérifier que le texte est présent (signifie qu il est affiché)
    expect(page.get_by_text("XSS_PROTECTED")).to_be_visible()
    
    # Vérifier que l element <b> n existe PAS dans le DOM (signifie qu il a été échappé)
    b_tag_count = page.locator("#toast-container b#xss-target-toast").count()
    assert b_tag_count == 0, "XSS payload was executed in toast (malicious b tag found)"

def test_security_utils_available(page: Page, server_url):
    """
    Vérifie que SecurityUtils est bien chargé et fonctionnel.
    """
    page.goto(f"{server_url}/login")
    page.wait_for_load_state("networkidle")
    
    # Tester l existence de l objet utils
    is_utils_defined = page.evaluate("typeof window.utils !== 'undefined'")
    assert is_utils_defined, "window.utils should be defined"
    
    # Tester l echappement
    xss_payload = "<div>test</div>"
    escaped = page.evaluate(f"window.utils.escapeHtml('{xss_payload}')")
    assert "&lt;div&gt;test&lt;/div&gt;" in escaped
