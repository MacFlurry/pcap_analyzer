# Track Plan: Admin Panel Refinement & E2E Testing

## Phase 1: Backend Pagination & Integration [checkpoint: 84207]

- [x] Task: Update `GET /api/users` endpoint in `app/api/routes/auth.py` to support `offset` and `limit` parameters with backward compatibility. (84207)
- [x] Task: Implement `PaginatedUsersResponse` schema in `app/models/schemas.py`. (84207)
- [x] Task: Update `UserDatabaseService` to support efficient pagination queries (COUNT + LIMIT/OFFSET) with basic status/role filtering only. (84207)
- [x] Task: Optimize database indexes for `created_at` and `username` to ensure <500ms query performance. (84207)
- [x] Task: Verify backward compatibility: clients calling GET /api/users without offset receive unwrapped List[UserResponse]. (84207)
- [x] Task: Create `tests/integration/test_api_users_pagination.py` to verify pagination logic, metadata, and backward compatibility. (84207)
- [x] Task: (Optional) Add performance benchmark test to verify <500ms response time with 10k+ user dataset.
- [x] Task: Conductor - User Manual Verification 'Backend Pagination' (Protocol in workflow.md) (84207)

## Phase 2: Frontend Pagination Implementation

- [x] Task: Update Admin UI (`app/templates/admin.html`, `app/static/js/admin.js`) to consume paginated API response. (88521)
- [x] Task: Implement "Previous" and "Next" pagination controls and page size selector. (88521)
- [x] Task: Ensure Search and Filter controls reset/work seamlessly with pagination state. (88521)
- [x] Task: Verify Stats cards (Total/Pending/Blocked) update correctly independent of current page view. (88521)
- [x] Task: Conductor - User Manual Verification 'Frontend Pagination' (Protocol in workflow.md)

## Phase 3: E2E Testing Infrastructure (Playwright)

- [x] Task: Install Playwright and `pytest-playwright` dependencies. (89599)
- [x] Task: Create `tests/e2e/conftest.py` with Playwright fixtures and Testcontainers integration for isolated DB state. (93596)
- [x] Task: Create `tests/e2e/test_admin_happy_path.py`: (12526)
    - Admin login and dashboard access
    - User approval workflow (Pending -> Approved)
    - User blocking/unblocking workflow
    - Bulk actions (Approve, Block, Delete) with confirmation modals
    - User creation with temporary password display and copy
    - Pagination controls (Previous/Next, page range display)
- [x] Task: Create `tests/e2e/test_admin_edge_cases.py`: (12526)
    - CSRF token validation failures
    - API error handling (500/503 backend errors)
    - Empty user list state
    - Unauthorized access by non-admin users
    - Concurrent modification error feedback
    - Multi-tenant isolation (admin sees only authorized users)
- [x] Task: Verify E2E tests pass reliably and cover multi-tenant isolation scenarios. (12526)
- [x] Task: Conductor - User Manual Verification 'E2E Testing' (Protocol in workflow.md)

## Phase 4: Documentation & Track Closure

- [x] Task: Update `conductor/tech-stack.md` to include Playwright under Quality Assurance section.
- [x] Task: Update `conductor/product.md` to mention server-side pagination for admin panel scalability.
- [x] Task: Verify all acceptance criteria from spec are met.
- [x] Task: Conductor - Archive Track