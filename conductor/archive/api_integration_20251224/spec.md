# Track Specification: API Route Integration Tests

## Overview
Implement comprehensive integration tests for the core FastAPI routes: `/api/upload` and `/api/auth`. These tests will validate API contracts, error handling, security controls (auth, input validation), and proper integration with the backend services, ensuring the project meets its 60% code coverage goal.

## Functional Requirements
- **Authentication Endpoints (`/api/auth`):**
    - Verify user registration flow (success, duplicate user handling).
    - Verify login flow (valid credentials, invalid credentials, unapproved account).
    - Verify token validity, expiration, and refresh behavior.
    - **Password Policies:** Validate zxcvbn strength checks, password history (reuse prevention), and temporary password flows.
- **Upload Endpoints (`/api/upload`):**
    - Verify successful PCAP file upload and task creation.
    - **Security:** Verify CSRF token validation is enforced.
    - Verify file validation:
        - Rejection of non-PCAP files (magic number check).
        - Rejection of oversized files.
        - Handling of malformed PCAP structures.
    - Verify proper error responses (400 Bad Request, 413 Payload Too Large).
- **Security Integration:**
    - Ensure protected routes correctly reject unauthenticated requests (401 Unauthorized).
    - Validate that uploaded files are correctly associated with the authenticated user (owner_id).
    - **Multi-tenant Isolation:** Verify that User A cannot access or manipulate User B's uploaded tasks.

## Non-Functional Requirements
- **Test Isolation:** Tests must use the `testcontainers-python` PostgreSQL fixture to ensure a clean database state.
- **Efficiency:** Use a specialized `auth_fixture` to inject valid JWT tokens for non-auth tests (like upload), avoiding repetitive login calls.
- **Realism:** Use real sample PCAP files (valid and invalid) from the test data directory to verify file validation logic.

## Acceptance Criteria
- [ ] Integration tests exist and pass for all `/api/auth` endpoints, including password policies and token refresh.
- [ ] Integration tests exist and pass for `/api/upload` endpoints using real PCAP samples, including CSRF checks.
- [ ] Tests verify multi-tenant isolation rules.
- [ ] Tests verify both success paths (200 OK, 201 Created) and failure paths (400, 401, 403, 413).
- [ ] Code coverage for `app/api/routes/auth.py` and `app/api/routes/upload.py` reaches 60%+.

## Out of Scope
- Tests for `/api/reports` and `/api/progress` (deferred to a future track).
- Frontend E2E testing (Playwright/Selenium).
- Performance load testing of the upload endpoint.
