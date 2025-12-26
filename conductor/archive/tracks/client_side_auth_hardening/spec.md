# Specification: Hardening Client-Side Authentication

**Track ID:** `client_side_auth_hardening`
**Type:** Security Hardening / Refactor
**Target:** Frontend/Backend Authentication Flow

## Overview
This specification details the implementation of a "Defense in Depth" strategy for the PCAP Analyzer's frontend authentication. Currently, HTML pages (`/history`, `/admin`, etc.) are protected only by client-side JavaScript. While data is secure (API protected), the application shell is exposed to anonymous users. This track moves to a hybrid authentication model using Cookies for the browser shell and JWT Headers for API calls.

## Core Objectives
1.  **Server-Side Route Protection:** HTML pages must return a `307 Temporary Redirect` (or `303 See Other`) to `/login` if the user is unauthenticated.
2.  **Hybrid Authentication:** Support both `Cookie` (for browser navigation) and `Authorization: Bearer` (for API calls/CLI) authentication.
3.  **Secure Cookie Management:** Implement secure, HTTP-only, SameSite cookies for token storage.

## Technical Specifications

### 1. Authentication Updates (`app/api/routes/auth.py`)
The login endpoint must be updated to set a cookie alongside the JSON response.

*   **Login Endpoint (`POST /api/v1/auth/login`):**
    *   **Action:** In addition to returning the `access_token` in the JSON body, set a response cookie named `access_token`.
    *   **Cookie Attributes:**
        *   `key`: "access_token"
        *   `value`: `access_token` (JWT)
        *   `httponly`: `True` (Prevents XSS theft)
        *   `secure`: `True` (if HTTPS; configurable via env/context) or `False` (for localhost dev) - *Ideally determine dynamically based on request scheme.*
        *   `samesite`: "Lax" (Allows navigation from external sites, needed for OAuth flows if added later, and standard top-level navigation)
        *   `max_age`: Matches token expiry.
    *   **Logout Endpoint (`POST /api/v1/auth/logout`):**
        *   **Action:** Must explicitly delete the `access_token` cookie.

### 2. Dependency Update (`app/services/auth.py`)
We need a unified way to retrieve the current user that checks both sources.

*   **Refactor `oauth2_scheme`:**
    *   *Standard approach:* Keep `oauth2_scheme` for Swagger UI / API.
    *   *New helper:* `get_token_from_request(request: Request)`:
        1.  Check `Authorization` header.
        2.  Check `access_token` cookie.
        3.  Return token or `None`.
*   **Update `get_current_user`:**
    *   Should utilize `get_token_from_request`.
*   **New Dependency `get_current_user_optional`:**
    *   Does not raise `HTTPException` if user is missing. Returns `User | None`.
    *   Used for public pages or pages with custom redirect logic.

### 3. Frontend Route Protection (`app/api/routes/views.py`)
All HTML serving endpoints must be updated to enforce authentication.

*   **Protected Routes:** `/history`, `/admin`, `/upload`, `/profile`.
*   **Implementation Logic:**
    *   Inject `current_user: User = Depends(get_current_user_cookie_or_redirect)`.
    *   **`get_current_user_cookie_or_redirect`:**
        *   Checks for valid user via Cookie/Header.
        *   If invalid/missing -> Raises `HTTPException(status_code=307, headers={"Location": "/login?returnUrl=..."})` OR returns a `RedirectResponse` directly if used as a simple helper inside the route (cleaner for HTML endpoints).
    *   **Refined Approach:**
        ```python
        @router.get("/history", response_class=HTMLResponse)
        async def history(
            request: Request,
            user: User = Depends(get_current_user_from_cookie) # Raises Redirect if fails
        ):
            ...
        ```

### 4. Client-Side Adjustments
*   **Login Page:** No changes strictly required to logic (it receives the token), but the browser will now automatically handle the cookie.
*   **API Calls:** Existing JS logic uses `localStorage` + `Authorization` header. This **should remain** to ensure CSRF protection for state-changing actions (POST/PUT/DELETE), as Cookies are vulnerable to CSRF if used alone for APIs.
    *   *Note:* The API endpoints will continue to accept the Header token.
    *   *Cookie Usage:* Strictly for `GET` requests to load HTML pages and potentially read-only API calls (though keeping Header for API is safer/consistent).

## Verification Plan
1.  **Automated Script:** Use `TEST_CLIENT_SIDE_AUTH.sh` to verify `curl` requests to `/history` return 307/303 instead of 200.
2.  **Browser Test:**
    *   Clear LocalStorage AND Cookies.
    *   Navigate to `/history` -> Should redirect to `/login`.
    *   Login -> Should set Cookie AND LocalStorage.
    *   Reload `/history` -> Should load (Cookie auth).
    *   Delete LocalStorage (simulate JS fail) -> Reload `/history` -> Should still load (Cookie auth).
    *   Delete Cookie -> Reload `/history` -> Should redirect to `/login`.

## Security Considerations
*   **CSRF:** Using Cookies for API authentication introduces CSRF risks.
    *   **Mitigation:** We will **NOT** rely on Cookies for state-changing API operations (`POST`, `PUT`, `DELETE`). The API dependencies for these routes should strictly require the `Authorization` header (or we'd need to implement CSRF tokens).
    *   *Decision:* For this track, we primarily protect the *GET HTML* routes with cookies. API routes can technically accept cookies if we carefully verify `get_current_user` usage, but enforcing "Header Only" for sensitive API actions is a safer default unless we add CSRF middleware.
    *   *Refinement:* Let's configure `get_current_user` to accept *either*, but for this specific "HTML Hardening" task, the focus is the HTML routes.
