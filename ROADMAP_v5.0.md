# PCAP Analyzer v5.0 - PostgreSQL + Admin Approval Workflow

**Milestone**: Production-Ready Multi-Tenant Platform
**Target**: v5.0.0
**Status**: 🟡 Planning

---

## 🎯 Objectifs v5.0

### 1. **PostgreSQL Migration** (SQLite → PostgreSQL)
**Justification**: Production-ready, scalable, concurrent writes, better performance

- [ ] Migration schema SQLite → PostgreSQL
- [ ] Connection pooling (asyncpg)
- [ ] Database migrations (Alembic)
- [ ] Docker Compose avec PostgreSQL
- [ ] Environment-based config (dev: SQLite, prod: PostgreSQL)

**Priority**: 🔴 CRITICAL
**Agent**: Backend Agent

---

### 2. **Admin Approval Workflow**
**Justification**: Security requirement - prevent unauthorized access

- [ ] Add `is_approved` field to users table
- [ ] User registration creates PENDING account (is_approved=False)
- [ ] Email notification to admin on new registration (optional)
- [ ] Admin must approve before user can login
- [ ] Login returns 403 if account not approved

**Priority**: 🔴 CRITICAL
**Agent**: Backend Agent + Security Agent

---

### 3. **Admin Panel (Zone d'administration)**
**Justification**: Admin needs UI to manage users

**Features**:
- [ ] GET /api/admin/users (list all users with filters)
- [ ] PUT /api/admin/users/{id}/approve (approve pending user)
- [ ] PUT /api/admin/users/{id}/block (block/unblock user)
- [ ] DELETE /api/admin/users/{id} (delete user + cascade tasks)
- [ ] POST /api/admin/users/bulk (bulk actions: approve, block, delete)
- [ ] Admin dashboard UI (HTML + JavaScript)
  - User table with status (pending/approved/blocked)
  - Bulk selection checkboxes
  - Action buttons (Approve, Block, Delete)
  - Filters (status, role, date)

**Priority**: 🟠 HIGH
**Agent**: Frontend Agent + Backend Agent

---

### 4. **Enhanced Password Policy**
**Justification**: Robust password enforcement

**Current**: 12+ chars, common password check
**Target**: OWASP ASVS 2.1 + NIST SP 800-63B enhanced

- [ ] Password strength meter (zxcvbn library)
- [ ] Minimum entropy score (e.g., score ≥ 3/4)
- [ ] Password breach check (Have I Been Pwned API - optional)
- [ ] Password history (prevent reuse of last 5 passwords)
- [ ] Password expiration policy (optional, admin configurable)

**Priority**: 🟡 MEDIUM
**Agent**: Security Agent

---

### 5. **Testing & QA**
**Justification**: Ensure no regressions, production stability

- [ ] Update existing tests for PostgreSQL
- [ ] Add admin approval workflow tests
- [ ] Add admin panel API tests
- [ ] Integration tests with Docker Compose
- [ ] Non-regression test suite
- [ ] Security audit (OWASP Top 10)
- [ ] Performance benchmarks (PostgreSQL vs SQLite)

**Priority**: 🔴 CRITICAL
**Agent**: QA Agent + Security Agent

---

### 6. **Docker Compose Refactoring**
**Justification**: Local testing + production deployment

**Services**:
```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: pcap_analyzer
      POSTGRES_USER: pcap
      POSTGRES_PASSWORD: <secure>
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck: pg_isready

  pcap-analyzer:
    build: .
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://pcap:password@postgres/pcap_analyzer
      SECRET_KEY: <generated>
    volumes:
      - ./data:/data

  adminer:
    image: adminer
    ports:
      - "8080:8080"
```

**Tasks**:
- [ ] Add PostgreSQL service to docker-compose.yml
- [ ] Add Adminer (DB admin UI)
- [ ] Environment variable configuration
- [ ] Health checks
- [ ] Volume persistence
- [ ] Cleanup script for old images

**Priority**: 🟠 HIGH
**Agent**: DevOps Agent

---

### 7. **Documentation**
**Justification**: Onboarding, deployment guides

- [ ] PostgreSQL setup guide
- [ ] Admin approval workflow documentation
- [ ] Admin panel user guide
- [ ] API documentation update (Swagger)
- [ ] Deployment guide (Docker + K8s)
- [ ] Security best practices guide

**Priority**: 🟡 MEDIUM
**Agent**: Documentation Agent

---

## 📊 Architecture Decisions

### Database Schema Changes

```sql
-- Users table (PostgreSQL)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_approved BOOLEAN NOT NULL DEFAULT FALSE,  -- NEW
    approved_by UUID REFERENCES users(id),        -- NEW
    approved_at TIMESTAMP,                        -- NEW
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP,
    CONSTRAINT role_check CHECK (role IN ('admin', 'user'))
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_approved ON users(is_approved);  -- NEW

-- Tasks table (PostgreSQL)
CREATE TABLE tasks (
    task_id UUID PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    status VARCHAR(20) NOT NULL,
    uploaded_at TIMESTAMP NOT NULL DEFAULT NOW(),
    analyzed_at TIMESTAMP,
    file_size_bytes BIGINT NOT NULL,
    total_packets INTEGER,
    health_score DECIMAL(5, 2),
    report_html_path TEXT,
    report_json_path TEXT,
    error_message TEXT,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,  -- CASCADE
    CONSTRAINT status_check CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'expired'))
);

CREATE INDEX idx_tasks_owner_id ON tasks(owner_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_uploaded_at ON tasks(uploaded_at DESC);
```

### Admin Approval Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant DB
    participant Admin

    User->>API: POST /api/register
    API->>DB: INSERT user (is_approved=FALSE)
    API-->>User: 202 Account pending approval

    Admin->>API: GET /api/admin/users?status=pending
    API-->>Admin: List pending users

    Admin->>API: PUT /api/admin/users/{id}/approve
    API->>DB: UPDATE is_approved=TRUE, approved_by=admin.id
    API-->>Admin: 200 User approved

    User->>API: POST /api/token (login)
    API->>DB: Check is_approved
    alt is_approved=TRUE
        API-->>User: 200 JWT token
    else is_approved=FALSE
        API-->>User: 403 Account pending approval
    end
```

---

## 🚀 Implementation Phases

### **Phase 1: PostgreSQL Migration** (Week 1)
**Agent**: Backend Agent (specialized in DB migrations)

1. Setup Alembic migrations
2. Create PostgreSQL schema
3. Implement asyncpg connection pool
4. Add DATABASE_URL env var support
5. Backward compatibility (SQLite for dev)

**Deliverable**: PostgreSQL support with zero downtime migration

---

### **Phase 2: Admin Approval Workflow** (Week 1-2)
**Agent**: Backend Agent + Security Agent

1. Add is_approved fields to schema
2. Update registration endpoint (set is_approved=FALSE)
3. Update login endpoint (check is_approved)
4. Create admin approval endpoints
5. Add email notifications (optional)

**Deliverable**: Functional admin approval workflow

---

### **Phase 3: Admin Panel UI** (Week 2)
**Agent**: Frontend Agent (UI/UX specialist)

1. Design admin dashboard mockup
2. Create /admin.html page
3. Implement user management table
4. Add bulk selection + actions
5. Add filters (status, role, date)
6. Integrate with API endpoints

**Deliverable**: Professional admin panel UI

---

### **Phase 4: Enhanced Security** (Week 2-3)
**Agent**: Security Agent

1. Implement password strength meter
2. Add password breach check
3. Password history (last 5)
4. Security audit (OWASP Top 10)
5. Penetration testing

**Deliverable**: OWASP-compliant security posture

---

### **Phase 5: Testing & QA** (Week 3)
**Agent**: QA Agent

1. Update unit tests for PostgreSQL
2. Integration tests with Docker Compose
3. Non-regression test suite
4. Performance benchmarks
5. Load testing (100+ concurrent users)

**Deliverable**: 95%+ test coverage, zero regressions

---

### **Phase 6: Docker Compose & DevOps** (Week 3-4)
**Agent**: DevOps Agent

1. Refactor docker-compose.yml (PostgreSQL + Adminer)
2. Environment variable management
3. Health checks + graceful shutdown
4. Cleanup script for old images
5. CI/CD pipeline updates

**Deliverable**: Production-ready Docker Compose stack

---

### **Phase 7: Documentation & Release** (Week 4)
**Agent**: Documentation Agent

1. Update README.md
2. Write deployment guides
3. API documentation (Swagger)
4. Security best practices
5. Changelog for v5.0.0

**Deliverable**: Complete documentation suite

---

## 📋 GitHub Issues Tracking

**Milestone**: `v5.0.0 PostgreSQL + Admin Approval`

### Created Issues:
- [ ] #19: PostgreSQL migration with Alembic
- [ ] #20: Admin approval workflow (is_approved field)
- [ ] #21: Admin panel UI (user management)
- [ ] #22: Bulk user actions API
- [ ] #23: Enhanced password policy (strength meter)
- [ ] #24: PostgreSQL Docker Compose setup
- [ ] #25: Integration tests with PostgreSQL
- [ ] #26: Non-regression test suite
- [ ] #27: Security audit v5.0
- [ ] #28: Documentation update for v5.0

---

## ⚠️ Breaking Changes v5.0

1. **Database**: SQLite → PostgreSQL (migration script provided)
2. **Registration**: Users start as `is_approved=FALSE` (admin must approve)
3. **Login**: 403 if account not approved (vs 401 unauthorized)
4. **Environment**: Requires `DATABASE_URL` env var for PostgreSQL

---

## 🎯 Success Metrics

- [ ] PostgreSQL migration: zero data loss
- [ ] Admin approval: 100% functional
- [ ] Admin panel: professional UI/UX
- [ ] Test coverage: ≥ 95%
- [ ] Security score: ≥ 95% (OWASP)
- [ ] Performance: <500ms API response time
- [ ] Documentation: complete + up-to-date

---

## 🔄 Next Steps (Immediate)

1. **Create GitHub Issues** for all tasks (with labels: backend, frontend, security, devops, qa)
2. **Create Milestone** `v5.0.0 PostgreSQL + Admin Approval`
3. **Assign agents** to issues
4. **Start Phase 1**: PostgreSQL migration (Backend Agent)
5. **Parallel Phase 2**: Admin approval workflow (Backend + Security Agents)

---

**Status**: 🟡 Ready for orchestration
**ETA**: 4 weeks (with parallel agent work)
**Risk**: 🟢 Low (good test coverage, backward compatibility)
