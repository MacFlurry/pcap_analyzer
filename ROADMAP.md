# PCAP Analyzer - Product Roadmap

## Current Version: v4.23.2 ✅

**Latest Release**: 2025-12-21
- Real-time progress callbacks for web UI
- Bug fixes: Jitter RTT regression, selection counter persistence

---

## Roadmap Overview

```
v4.23.2 (Current) → v4.24.0 (Security) → v4.25.0 (QA) → v5.0.0 (Admin) → v5.1.0 (Features)
```

---

## 🔴 Phase 1: v4.24.0 - Security Hardening (CRITICAL)
**Target**: 2025-12-31 | **Status**: 🟡 In Progress

### Critical Security Vulnerabilities

| Issue | Title | Severity | Agent | Status |
|-------|-------|----------|-------|--------|
| [#14](https://github.com/MacFlurry/pcap_analyzer/issues/14) | Path Traversal (CWE-22) | CVSS 9.1 | @agent:security | 🔴 Open |
| [#16](https://github.com/MacFlurry/pcap_analyzer/issues/16) | CSRF Vulnerability (CWE-352) | CVSS 8.1 | @agent:security | 🔴 Open |
| [#17](https://github.com/MacFlurry/pcap_analyzer/issues/17) | File Upload Validation (CWE-434) | CVSS 8.6 | @agent:security | 🔴 Open |

### Impact
- **Production Blocker**: YES
- **Exploitable**: YES (PoC available)
- **Data at Risk**: Configuration files, database, uploaded PCAPs

### Deliverables
- [ ] Path validation utility (`app/utils/path_validator.py`)
- [ ] CSRF protection middleware (fastapi-csrf-protect)
- [ ] Server-side file upload validation (magic number check)
- [ ] Security test suite integration
- [ ] Security audit report update

---

## 🟡 Phase 2: v4.25.0 - QA & Testing
**Target**: 2026-01-15 | **Status**: ⚪ Not Started

### Test Coverage Goals

| Issue | Title | Type | Agent | Priority |
|-------|-------|------|-------|----------|
| [#18](https://github.com/MacFlurry/pcap_analyzer/issues/18) | Web UI Security Test Suite | Security Tests | @agent:qa @agent:security | 🟠 High |
| [#25](https://github.com/MacFlurry/pcap_analyzer/issues/25) | PostgreSQL Integration Tests | Integration | @agent:qa | 🔴 Critical |
| [#26](https://github.com/MacFlurry/pcap_analyzer/issues/26) | Non-Regression Test Suite | Regression | @agent:qa | 🔴 Critical |

### Coverage Targets
- **Current**: ~40% (analyzers only)
- **Target v4.25.0**: 80%
  - Unit tests: 90%
  - Integration tests: 70%
  - Security tests: 100% (for known vulns)

### Deliverables
- [ ] pytest test suite for Web UI endpoints
- [ ] PostgreSQL integration tests (CRUD operations)
- [ ] Non-regression tests for core analysis features
- [ ] CI/CD integration (GitHub Actions)
- [ ] Test coverage reporting (codecov)

---

## 🟢 Phase 3: v5.0.0 - Admin Panel
**Target**: 2026-01-31 | **Status**: ⚪ Not Started

### User Management Features

| Issue | Title | Component | Agent | Priority |
|-------|-------|-----------|-------|----------|
| [#21](https://github.com/MacFlurry/pcap_analyzer/issues/21) | Admin Panel UI | Frontend | @agent:frontend | 🟠 High |
| [#22](https://github.com/MacFlurry/pcap_analyzer/issues/22) | Bulk User Actions API | Backend | @agent:backend | 🟠 High |
| [#23](https://github.com/MacFlurry/pcap_analyzer/issues/23) | Enhanced Password Policy | Backend | @agent:backend @agent:security | 🟡 Medium |

### Features
- **Admin Dashboard**: `/admin.html`
  - User list with filters (status, role, date)
  - Bulk selection and actions
  - Real-time updates (SSE/polling)
- **Bulk Actions API**:
  - Approve multiple users
  - Block multiple users
  - Delete with cascade (tasks + reports)
- **Password Policy**:
  - Minimum length: 12 characters
  - Complexity requirements
  - Password history (prevent reuse)
  - Expiration policy (90 days)

### Deliverables
- [ ] Admin UI page with Tailwind CSS
- [ ] Bulk actions API endpoints
- [ ] Password policy enforcement
- [ ] Audit logging for admin actions
- [ ] Admin user guide documentation

---

## 🔵 Phase 4: v5.1.0 - Documentation & Features
**Target**: 2026-02-28 | **Status**: ⚪ Not Started

### Documentation & Enhancements

| Issue | Title | Type | Agent | Priority |
|-------|-------|------|-------|----------|
| [#27](https://github.com/MacFlurry/pcap_analyzer/issues/27) | Security Audit v5.0 | Security | @agent:security | 🟠 High |
| [#28](https://github.com/MacFlurry/pcap_analyzer/issues/28) | Documentation Update v5.0 | Documentation | @agent:documentation | 🟡 Medium |
| [#29](https://github.com/MacFlurry/pcap_analyzer/issues/29) | Two-Factor Authentication (2FA) | Enhancement | @agent:security @agent:backend | 🟡 Medium |

### Deliverables
- [ ] Comprehensive security audit post-v5.0
- [ ] Updated user documentation
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Deployment guide (Docker/K8s)
- [ ] 2FA implementation (TOTP/WebAuthn)

---

## Agent Assignments

### 🔒 Security Agent (@agent:security)
**Responsible for**: Security vulnerabilities, audits, 2FA, password policies
- **Current Sprint**: v4.24.0 Security Hardening
- **Issues**: #14, #16, #17, #18, #23, #27, #29

### 🧪 QA Agent (@agent:qa)
**Responsible for**: Testing, quality assurance, CI/CD
- **Current Sprint**: Blocked until v4.24.0 complete
- **Issues**: #18, #25, #26

### ⚙️ Backend Agent (@agent:backend)
**Responsible for**: API development, database operations
- **Current Sprint**: Blocked until v4.25.0 complete
- **Issues**: #22, #23, #29

### 🎨 Frontend Agent (@agent:frontend)
**Responsible for**: UI/UX, client-side functionality
- **Current Sprint**: Blocked until v4.25.0 complete
- **Issues**: #21

### 📚 Documentation Agent (@agent:documentation)
**Responsible for**: User guides, API docs, deployment guides
- **Current Sprint**: Continuous (as features complete)
- **Issues**: #28

---

## Success Metrics

### v4.24.0 - Security Hardening
- ✅ All 3 critical vulnerabilities fixed
- ✅ Security test suite passing (100% coverage for known vulns)
- ✅ Penetration testing report (no critical findings)
- ✅ OWASP ASVS Level 2 compliance

### v4.25.0 - QA & Testing
- ✅ 80% code coverage
- ✅ All PostgreSQL operations tested
- ✅ Non-regression tests for v4.x features
- ✅ CI/CD pipeline green

### v5.0.0 - Admin Panel
- ✅ Admin can manage 1000+ users efficiently
- ✅ Bulk actions complete in <5s for 100 users
- ✅ Password policy enforced at registration
- ✅ Audit log captures all admin actions

### v5.1.0 - Documentation & Features
- ✅ 2FA adoption rate >50%
- ✅ Documentation covers 100% of features
- ✅ Zero critical security findings in audit
- ✅ Deployment guide validated on 3 platforms

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Security vulns exploited in production | Critical | Medium | Fast-track v4.24.0, security-first approach |
| Test suite delays v5.0 release | High | Low | Parallel development after security fixes |
| Admin panel complexity scope creep | Medium | Medium | Stick to MVP, defer advanced features to v5.2 |
| 2FA breaks existing auth workflow | Medium | Low | Gradual rollout, optional initially |

---

## Workflow

### Issue Lifecycle
1. **Triage**: Label with agent, priority, milestone
2. **Planning**: Agent reviews, breaks down into tasks
3. **Implementation**: Agent implements, commits with issue ref
4. **Review**: Code review (security audit for critical issues)
5. **Testing**: QA agent validates (unit + integration tests)
6. **Deployment**: Merge to main, tag release
7. **Documentation**: Update docs, changelog, release notes

### Branching Strategy
- `main`: Production-ready code
- `develop`: Integration branch (removed - we work directly on main with PRs)
- `feature/issue-XX-description`: Feature branches
- `hotfix/issue-XX-description`: Critical fixes

### Release Cadence
- **v4.24.0**: As soon as security fixes validated (target: 2025-12-31)
- **v4.25.0**: 2 weeks after v4.24.0 (QA sprint)
- **v5.0.0**: 2 weeks after v4.25.0 (Admin panel)
- **v5.1.0**: 4 weeks after v5.0.0 (Documentation + 2FA)

---

## Contact & Contributions

**Project Lead**: @MacFlurry
**AI Orchestrator**: Claude Sonnet 4.5

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
See [SECURITY.md](SECURITY.md) for security policy.

---

**Last Updated**: 2025-12-21
**Next Review**: After each milestone completion
