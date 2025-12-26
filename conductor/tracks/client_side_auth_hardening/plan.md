# Track: Hardening Client-Side Authentication (Defense in Depth)

**Goal:** Implement server-side access control for HTML frontend routes to prevent unauthenticated access to the application shell, implementing a "Defense in Depth" strategy.

**Status:** Proposed / Ready for Implementation

## Context
An investigation revealed that while API endpoints are secure and data is isolated, the HTML frontend pages (e.g., `/history`, `/admin`) are served with HTTP 200 status to anonymous users. Protection currently relies solely on client-side JavaScript redirects.

*   **Investigation Report:** [./BUG_REPORT_CLIENT_SIDE_AUTH.md](./BUG_REPORT_CLIENT_SIDE_AUTH.md)
*   **Test Script:** [./TEST_CLIENT_SIDE_AUTH.sh](./TEST_CLIENT_SIDE_AUTH.sh)

## Objectives
1.  Prevent anonymous users from loading the HTML shell for protected pages (`/history`, `/admin`, `/upload`).
2.  Return a `307 Temporary Redirect` to `/login` (or `401 Unauthorized`) for these pages when unauthenticated.
3.  Ensure "Defense in Depth" so that if JavaScript is disabled or fails, the user is still denied access.

## Implementation Plan (Option A)

### Phase 1: Authentication Mechanism Update (Completed) [checkpoint: 98ce433]
Since standard browser navigation does not send `Authorization` headers (which utilize the `localStorage` token), we must implement a Cookie-based approach or a Hybrid approach.

- [x] **Modify Login Endpoint**: Update `/api/token` to set an `access_token` cookie (HttpOnly, Secure, SameSite) in addition to returning the JWT in the body. (98ce433)
- [x] **Update Logout**: Ensure logout clears this cookie. (98ce433)

**Implementation Notes (Phase 1):**
- Updated `app/api/routes/auth.py` to set `access_token` cookie in `login`.
- Added `POST /api/logout` endpoint to clear the cookie.
- Fixed `tests/conftest.py` initialization errors related to dual-database and dynamic paths.
- Verified via `tests/security/test_cookie_auth.py`.

### Phase 2: Route Protection
- [ ] **Middleware / Dependency**: Create a dependency `get_current_user_optional` or similar that checks for the Cookie.
- [ ] **Protect Routes**: Update `app/main.py` (or where HTML routes are defined) to check for authentication before serving `templates.TemplateResponse`.
    - If cookie missing/invalid -> `RedirectResponse("/login")`.

### Phase 3: Verification
- [ ] **Run Test Script**: Execute `TEST_CLIENT_SIDE_AUTH.sh` to confirm HTML pages no longer return HTTP 200 for anonymous users.
- [ ] **E2E Testing**: Verify that the normal login flow still works and that the user is correctly redirected.

## Notes
- This change moves the application towards a more traditional session-based (via stateless JWT cookie) auth for the frontend, while keeping API auth token-based for potential CLI/External usage.
- Care must be taken to handle CSRF if we rely solely on cookies for API actions (though we are primarily using this for *GET* page loads). API actions likely still use the Header token, protecting them from CSRF, or we implement CSRF tokens.
