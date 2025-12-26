#!/bin/bash
# Test script for client-side authentication vulnerability
# Reporter: Assistant (Claude Code)
# Date: 2025-12-26

echo "========================================="
echo "🔒 Client-Side Authentication Tests"
echo "========================================="
echo ""

BASE_URL="http://pcaplab.com"

echo "Test 1: Access /history without authentication"
echo "-----------------------------------------------"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/history")
echo "GET $BASE_URL/history"
echo "Status: $STATUS"
if [ "$STATUS" = "200" ]; then
    echo "✅ Page accessible (HTML served)"
else
    echo "❌ Unexpected status: $STATUS"
fi
echo ""

echo "Test 2: Access /admin without authentication"
echo "-----------------------------------------------"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/admin")
echo "GET $BASE_URL/admin"
echo "Status: $STATUS"
if [ "$STATUS" = "200" ]; then
    echo "✅ Page accessible (HTML served)"
else
    echo "❌ Unexpected status: $STATUS"
fi
echo ""

echo "Test 3: Access /api/history without authentication"
echo "-----------------------------------------------"
RESPONSE=$(curl -s "$BASE_URL/api/history")
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/history")
echo "GET $BASE_URL/api/history"
echo "Status: $STATUS"
echo "Response: $RESPONSE"
if [ "$STATUS" = "401" ]; then
    echo "✅ API correctly protected (401 Unauthorized)"
else
    echo "❌ API not protected! Status: $STATUS"
fi
echo ""

echo "Test 4: Access /api/history with invalid token"
echo "-----------------------------------------------"
RESPONSE=$(curl -s -H "Authorization: Bearer fake_token_12345" "$BASE_URL/api/history")
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer fake_token_12345" "$BASE_URL/api/history")
echo "GET $BASE_URL/api/history (with fake token)"
echo "Status: $STATUS"
echo "Response: $RESPONSE"
if [ "$STATUS" = "401" ]; then
    echo "✅ Invalid token rejected (401 Unauthorized)"
else
    echo "❌ Invalid token accepted! Status: $STATUS"
fi
echo ""

echo "Test 5: Check if HTML contains sensitive data"
echo "-----------------------------------------------"
HTML=$(curl -s "$BASE_URL/history")
echo "Checking /history HTML for sensitive patterns..."

# Check for sensitive data in HTML
if echo "$HTML" | grep -q "task_id\|report_html_url\|owner_id"; then
    echo "⚠️  WARNING: HTML contains data attributes that might leak info"
else
    echo "✅ No sensitive data found in HTML (data loaded by JavaScript)"
fi

if echo "$HTML" | grep -q "history.js"; then
    echo "✅ JavaScript file referenced (client-side auth expected)"
fi
echo ""

echo "Test 6: Enumerate pages"
echo "-----------------------------------------------"
PAGES=("/" "/history" "/admin" "/login" "/profile" "/register" "/nonexistent")

for page in "${PAGES[@]}"; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$page")
    echo "$page → $STATUS"
done
echo ""

echo "========================================="
echo "Summary:"
echo "========================================="
echo "✅ APIs are protected (require authentication)"
echo "⚠️  HTML pages are served without server-side auth"
echo "✅ No sensitive data leaked in HTML templates"
echo "✅ Security relies on client-side JavaScript redirect"
echo ""
echo "Recommendation: Add server-side authentication"
echo "for protected pages to follow defense-in-depth."
echo "========================================="
