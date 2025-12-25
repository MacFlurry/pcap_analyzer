# Track Plan: Admin Panel Refinement & E2E Testing

## Phase 1: Backend Pagination & Integration [checkpoint: 84207]

- [x] Task: Update `GET /api/users` endpoint in `app/api/routes/auth.py` to support `offset` and `limit` parameters with backward compatibility. (84207)
- [x] Task: Implement `PaginatedUsersResponse` schema in `app/models/schemas.py`. (84207)
- [x] Task: Update `UserDatabaseService` to support efficient pagination queries (COUNT + LIMIT/OFFSET) with basic status/role filtering only. (84207)
- [x] Task: Optimize database indexes for `created_at` and `username` to ensure <500ms query performance. (84207)
- [x] Task: Verify backward compatibility: clients calling GET /api/users without offset receive unwrapped List[UserResponse]. (84207)
- [x] Task: Create `tests/integration/test_api_users_pagination.py` to verify pagination logic, metadata, and backward compatibility. (84207)
- [ ] Task: (Optional) Add performance benchmark test to verify <500ms response time with 10k+ user dataset.
- [x] Task: Conductor - User Manual Verification 'Backend Pagination' (Protocol in workflow.md) (84207)

## Phase 2: Frontend Pagination Implementation

- [ ] Task: Update Admin UI (`app/templates/admin.html`, `app/static/js/admin.js`) to consume paginated API response.
- [ ] Task: Implement "Previous" and "Next" pagination controls and page size selector.
- [ ] Task: Ensure Search and Filter controls reset/work seamlessly with pagination state.
- [ ] Task: Verify Stats cards (Total/Pending/Blocked) update correctly independent of current page view.
- [ ] Task: Conductor - User Manual Verification 'Frontend Pagination' (Protocol in workflow.md)

## Phase 3: E2E Testing Infrastructure (Playwright)

- [ ] Task: Install Playwright and `pytest-playwright` dependencies.
- [ ] Task: Create `tests/e2e/conftest.py` with Playwright fixtures and Testcontainers integration for isolated DB state.
- [ ] Task: Create `tests/e2e/test_admin_happy_path.py`:
    - Admin login and dashboard access
    - User approval workflow (Pending -> Approved)
    - User blocking/unblocking workflow
    - Bulk actions (Approve, Block, Delete) with confirmation modals
    - User creation with temporary password display and copy
    - Pagination controls (Previous/Next, page range display)
- [ ] Task: Create `tests/e2e/test_admin_edge_cases.py`:
    - CSRF token validation failures
    - API error handling (500/503 backend errors)
    - Empty user list state
    - Unauthorized access by non-admin users
    - Concurrent modification error feedback
    - Multi-tenant isolation (admin sees only authorized users)
- [ ] Task: Verify E2E tests pass reliably and cover multi-tenant isolation scenarios.
- [ ] Task: Conductor - User Manual Verification 'E2E Testing' (Protocol in workflow.md)

## Phase 4: Documentation & Track Closure

- [ ] Task: Update `conductor/tech-stack.md` to include Playwright under Quality Assurance section.
- [ ] Task: Update `conductor/product.md` to mention server-side pagination for admin panel scalability.
- [ ] Task: Verify all acceptance criteria from spec are met.
- [ ] Task: Conductor - Archive Track
