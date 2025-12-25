# Track Specification: Admin Panel Refinement & E2E Testing

## Overview
Refine the existing Admin Panel UI to be production-ready by implementing server-side pagination and establishing a robust End-to-End (E2E) testing suite using Playwright. This track bridges the gap between the backend APIs (verified in previous tracks) and the frontend user experience, ensuring scalability and reliability.

## Functional Requirements
- **Server-Side Pagination:**
    - Extend `GET /api/users` to support `offset` (default: 0) and `limit` (default: 100) parameters.
    - **New Response Model:** Introduce `PaginatedUsersResponse` schema with metadata wrapper.
    - **Backward Compatibility:** Maintain compatibility so that clients calling `GET /api/users` without `offset` receive the legacy unwrapped `List[UserResponse]` format.
    - Update API response to wrap user list with pagination metadata: `{"users": [...], "total": 1234, "offset": 0, "limit": 100}` when pagination is requested.
- **Frontend Integration:**
    - Update Admin UI to consume the paginated API response.
    - Implement "Previous" and "Next" pagination controls.
    - Display current range and total count (e.g., "Showing 1-50 of 1234").
- **E2E Testing (Playwright):**
    - **Happy Path Scenarios:**
        - Admin login and dashboard access.
        - User approval workflow (Pending -> Approved).
        - User blocking/unblocking workflow.
        - Bulk actions (Approve, Block, Delete) with confirmation.
        - User creation with temporary password flow.
        - **Stats & Controls:** Verify stats cards (Total/Pending/Blocked) update correctly and search/filter controls work seamlessly with pagination.
    - **Edge Case Scenarios:**
        - CSRF token validation failures.
        - Handling of API errors (500/503).
        - Empty states (no users found).
        - Unauthorized access attempts by non-admin users.
        - **Concurrent Modification:** Display error feedback when user state changes between page load and action.
        - **Multi-tenant Isolation:** Verify admin sees only authorized users.
    - **Test Isolation:** Use testcontainers (PostgreSQL) like integration tests to ensure clean database state per test run.

## Non-Functional Requirements
- **Performance:** Pagination queries must be optimized (SQL `OFFSET/LIMIT`) to handle thousands of users without latency.
- **Testing Tool:** Use **Playwright** with Python bindings (`pytest-playwright`) for speed, reliability, and trace debugging.
- **Code Quality:** Maintain existing code style and ensure 100% type safety for new backend code.

## Acceptance Criteria
- [ ] `GET /api/users` supports `offset` and `limit` and returns total count metadata.
- [ ] Pagination query performance: <500ms response time for dataset of 10,000 users with proper database indexing on `created_at`.
- [ ] Admin UI correctly displays paginated data and navigation controls work.
- [ ] Stats cards and search/filter controls tested and working with pagination.
- [ ] Playwright E2E test suite created in `tests/e2e/`.
- [ ] E2E tests use testcontainers for database isolation.
- [ ] "Happy Path" tests pass: Login, Approve, Block, Bulk Actions, Create User.
- [ ] "Edge Case" tests pass: CSRF failure, Empty list, Unauthorized access.
- [ ] Manual verification confirms smooth UI transitions and error handling.

## Out of Scope
- Complete redesign of the Admin UI (focus is on functionality and pagination).
- Mobile responsiveness optimization (desktop-first for admin panel).
- Complex advanced filtering (e.g., complex multi-field search logic beyond basic status/role).
