# Track Plan: API Route Integration Tests

## Phase 1: Authentication API Tests [checkpoint: 24706]

- [x] Task: Create `tests/integration/test_api_auth.py` with TestClient and PostgreSQL container setup (24706)
- [x] Task: Implement tests for user registration flow (Success, Duplicate Username/Email) (Red Phase) (24706)
- [x] Task: Implement tests for login flow (Valid credentials, Invalid credentials, Unapproved account) (Red Phase) (24706)
- [x] Task: Implement tests for token validity, expiration, and refresh behavior (Red Phase) (24706)
- [x] Task: Implement tests for password policies: zxcvbn strength and history reuse prevention (Red Phase) (24706)
- [x] Task: Implement tests for temporary password flow (Red Phase) (24706)
- [x] Task: Conductor - User Manual Verification 'Authentication API Tests' (Protocol in workflow.md) (24706)

## Phase 2: File Upload API Tests [checkpoint: 28584]

- [x] Task: Create `tests/integration/test_api_upload.py` with auth fixtures (27501)
- [x] Task: Implement tests for successful PCAP upload and task creation (Red Phase) (27501)
- [x] Task: Implement security tests: Authentication enforcement (401) and CSRF validation (Red Phase) (27501)
- [x] Task: Implement file validation tests: non-PCAP (magic number), size limits, and malformed PCAP structures (Red Phase) (27501)
- [x] Task: Implement multi-tenant isolation tests: User A cannot see or delete User B's tasks (Red Phase) (27501)
- [x] Task: Measure coverage for `auth.py` and `upload.py` and identify remaining gaps (28584)
- [x] Task: Implement additional tests to reach 60%+ coverage target (Red Phase) (28584)
- [x] Task: Conductor - User Manual Verification 'File Upload API Tests' (Protocol in workflow.md) (28584)
