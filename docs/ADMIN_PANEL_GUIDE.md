# Admin Panel User Guide

**Version**: 5.0
**Date**: 2025-12-21
**Audience**: Administrators
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Accessing the Admin Panel](#accessing-the-admin-panel)
3. [User Management](#user-management)
4. [Approval Workflow](#approval-workflow)
5. [Task Management](#task-management)
6. [Security Features](#security-features)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The Admin Panel provides a web interface for managing users, approving registrations, and monitoring tasks across all users in the PCAP Analyzer platform.

### Admin Capabilities

- ✅ **View all users** (approved and pending)
- ✅ **Approve user registrations**
- ✅ **Block/unblock users**
- ✅ **Delete user accounts**
- ✅ **View all tasks** (across all users)
- ✅ **Create users** with temporary passwords
- ✅ **Audit trail** of all admin actions

### Access Control

Only users with `role='admin'` can access admin endpoints and the admin panel.

---

## Accessing the Admin Panel

### Login

**URL**: `http://localhost:8000/login` (or your production URL)

**Default Admin Account**:
- **Username**: `admin`
- **Password**: Displayed in application logs on first boot (random 24-char password)

**Retrieve Admin Password**:
```bash
# Docker Compose
docker compose logs app | grep "ADMIN BRISE-GLACE"

# Kubernetes
kubectl logs -n pcap-analyzer deployment/pcap-analyzer | grep "ADMIN BRISE-GLACE"

# Example output:
# 🔒 ADMIN BRISE-GLACE ACCOUNT CREATED
# Username: admin
# Password: aB3dEf9Gh2JkLm5NpQrStUvWxYz
```

**⚠️ CRITICAL**: Change this password immediately after first login!

---

### Change Admin Password

**Via Web UI** (if available):
1. Click profile icon → **Change Password**
2. Enter current password
3. Enter new password (minimum 12 characters)
4. Confirm new password
5. Click **Save**

**Via API**:
```bash
# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<current_password>" \
  | jq -r '.access_token')

# Change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<current_password>",
    "new_password": "MyNewSecurePassword123!"
  }'
```

---

### Navigate to Admin Panel

**URL**: `http://localhost:8000/admin`

**Navigation**:
- From homepage: Click **Admin Panel** in top navigation (visible only to admins)
- Direct URL: `/admin` (redirects to login if not authenticated)

**Layout**:
```
┌─────────────────────────────────────────────┐
│ PCAP Analyzer - Admin Panel           [🔓]  │ ← Header
├─────────────────────────────────────────────┤
│ [Users] [Tasks] [Settings] [Logout]         │ ← Tabs
├─────────────────────────────────────────────┤
│                                              │
│  User Management                             │ ← Content Area
│  ─────────────────                           │
│  [Search: ______]  [Filter: All ▼]          │
│                                              │
│  ┌──────────────────────────────────────┐  │
│  │ Username  Email      Role   Status   │  │
│  │ alice     alice@...  user   Pending  │  │
│  │ bob       bob@...    user   Active   │  │
│  └──────────────────────────────────────┘  │
│                                              │
└─────────────────────────────────────────────┘
```

---

## User Management

### User List

**URL**: `/admin/users`

**View All Users**:

The user list displays all registered users with the following information:

| Column | Description | Values |
|--------|-------------|--------|
| **Username** | Unique username | String (3-50 chars) |
| **Email** | Email address | Valid email format |
| **Role** | User role | `admin` or `user` |
| **Status** | Account status | `Active` or `Blocked` |
| **Approval** | Approval status | `Approved` or `Pending` |
| **Created** | Registration date | ISO timestamp |
| **Actions** | Available actions | Approve, Block, Delete |

---

### Search and Filter

**Search Bar**:
- Search by username or email
- Real-time filtering
- Case-insensitive

**Filters**:
- **All Users** - Show all users
- **Pending Approval** - Show only users awaiting approval
- **Approved** - Show only approved users
- **Blocked** - Show only blocked users
- **Admins** - Show only admin users

**Example**:
```
Search: "alice"
Filter: "Pending Approval"
Result: Shows all pending users with "alice" in username/email
```

---

### User Details

**View User Details**:
Click on username to view detailed information:

```
User Details: alice
─────────────────────────

Basic Information:
  Username:    alice
  Email:       alice@example.com
  Role:        user
  Created:     2025-12-21 20:00:00

Status:
  Is Active:   ✅ Yes
  Is Approved: ❌ No (Pending approval)

Activity:
  Total Tasks: 0
  Last Login:  Never (not approved yet)

Actions:
  [Approve User]  [Block User]  [Delete User]
```

---

### User Actions

#### Approve User

**When to Use**: New user registered and needs approval before login

**Steps**:
1. Navigate to **Admin Panel** → **Users**
2. Filter by **Pending Approval**
3. Locate user to approve
4. Click **Approve** button (or checkbox + **Bulk Approve**)
5. Confirm approval

**Effect**:
- `is_approved` set to `true`
- `approved_by` set to your admin user ID
- `approved_at` set to current timestamp
- **Approval email sent** to the user (if email service is enabled)
- User can now login
- Audit log entry created

**Audit Log**:
```
🔓 AUDIT: Admin john.admin approved user alice (id: 550e8400-e29b-41d4-a716-446655440000)
```

**Via API**:
```bash
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
  -H "Authorization: Bearer <admin_token>"
```

---

#### Block User

**When to Use**: User account compromised or policy violation

**Steps**:
1. Navigate to **Admin Panel** → **Users**
2. Locate user to block
3. Click **Block** button
4. Enter reason (optional but recommended)
5. Confirm action

**Effect**:
- `is_active` set to `false`
- User **cannot login** (existing sessions remain valid until token expiry)
- User's tasks remain accessible (by admin)
- User data **not deleted**
- Audit log entry created

**⚠️ Note**: Blocking does **not** invalidate existing JWT tokens immediately (tokens expire after 30 minutes).

**Audit Log**:
```
🔒 AUDIT: Admin john.admin blocked user charlie (id: 660e8400-e29b-41d4-a716-446655440001)
```

**Via API**:
```bash
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/block \
  -H "Authorization: Bearer <admin_token>"
```

---

#### Unblock User

**When to Use**: Restore access for previously blocked user

**Steps**:
1. Navigate to **Admin Panel** → **Users**
2. Filter by **Blocked**
3. Locate user to unblock
4. Click **Unblock** button
5. Confirm action

**Effect**:
- `is_active` set to `true`
- User can login again
- Audit log entry created

**Audit Log**:
```
🔓 AUDIT: Admin john.admin unblocked user charlie (id: 660e8400-e29b-41d4-a716-446655440001)
```

**Via API**:
```bash
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/unblock \
  -H "Authorization: Bearer <admin_token>"
```

---

#### Delete User

**When to Use**: Permanent removal of user account (GDPR "Right to be Forgotten")

**⚠️ WARNING**: This action is **irreversible** and deletes all associated data!

**Steps**:
1. Navigate to **Admin Panel** → **Users**
2. Locate user to delete
3. Click **Delete** button
4. Type user's username to confirm
5. Click **Confirm Delete**

**Effect**:
- User account **permanently deleted** from database
- **All associated files deleted** from disk (PCAPs, HTML reports, JSON reports)
- User's tasks, progress snapshots, and password history removed (CASCADE)
- User **cannot** login (account no longer exists)
- Audit log entry created with count of files removed

**Audit Log**:
```
🗑️  AUDIT: Admin john.admin deleted user spam.account (id: 770e8400-e29b-41d4-a716-446655440002). Files removed: 12 uploads, 24 reports.
```

**Via API**:
```bash
curl -X DELETE http://localhost:8000/api/admin/users/<user_id> \
  -H "Authorization: Bearer <admin_token>"
```

---

### Create User

**When to Use**: Admin creates account for user who hasn't self-registered

**Steps**:
1. Navigate to **Admin Panel** → **Users**
2. Click **Create User** button
3. Fill form:
   - Username (3-50 chars)
   - Email (valid email format)
   - Temporary Password (minimum 12 chars)
   - Role (`user` or `admin`)
4. Click **Create**

**Effect**:
- User account created
- `is_approved` set to `true` (auto-approved)
- `password_must_change` set to `true` (user must change password on first login)
- Email sent to user with temporary password (if email configured)

**User First Login**:
```bash
# User logs in with temporary password
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=TempPassword123!"

# User MUST change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "TempPassword123!",
    "new_password": "MyNewSecurePassword456!"
  }'
```

**Via API**:
```bash
curl -X POST http://localhost:8000/api/admin/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "TempPassword123!",
    "role": "user"
  }'
```

---

## Approval Workflow

### Workflow Overview

```
┌─────────────────┐
│ User Registers  │ ← Self-service registration via /api/register
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Account Created │ ← is_approved=false, cannot login
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Admin Reviews   │ ← Admin views pending registrations
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Admin Approves  │ ← is_approved=true, approved_by, approved_at set
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ User Can Login  │ ← User authenticates via /api/token
└─────────────────┘
```

---

### Pending Approvals Badge

**Location**: Admin Panel header

**Display**:
```
Admin Panel [Users (3)] [Tasks] [Settings]
            ↑
         Badge shows count of pending approvals
```

**Notification**:
- Red badge if pending approvals > 0
- Updates in real-time (if WebSocket enabled)

---

### Bulk Actions

**Approve Multiple Users**:
1. Navigate to **Admin Panel** → **Users**
2. Filter by **Pending Approval**
3. Select users via checkboxes
4. Click **Bulk Approve** button
5. Confirm action

**Block Multiple Users**:
1. Select users via checkboxes
2. Click **Bulk Block** button
3. Enter reason (optional)
4. Confirm action

**⚠️ Note**: Bulk delete **not available** (safety measure)

---

## Task Management

### View All Tasks (Admin)

**URL**: `/admin/tasks`

**Features**:
- View **all tasks** across all users (admins only)
- Regular users see **only their own tasks**

**Task List Columns**:

| Column | Description | Values |
|--------|-------------|--------|
| **Task ID** | Unique identifier | UUID |
| **Filename** | PCAP filename | String |
| **Owner** | Username | String (or "Legacy" if NULL) |
| **Status** | Processing status | Pending, Processing, Completed, Failed |
| **Progress** | Completion percentage | 0-100% |
| **Uploaded** | Upload timestamp | ISO timestamp |
| **Actions** | Available actions | View Report, Delete |

---

### Filter by Owner

**Search Bar**:
- Search by owner username
- Search by filename
- Search by task ID

**Filters**:
- **All Tasks** - Show all tasks
- **Pending** - Show pending tasks
- **Processing** - Show currently processing tasks
- **Completed** - Show completed tasks
- **Failed** - Show failed tasks
- **Legacy** - Show tasks with NULL owner_id

---

### View Task Details

**Click on Task ID** to view details:

```
Task Details: abc-123-task-id
─────────────────────────────

File Information:
  Filename:    capture.pcap
  File Size:   125.4 MB
  Owner:       alice

Status:
  Status:      Completed
  Progress:    100%
  Uploaded:    2025-12-21 20:00:00
  Completed:   2025-12-21 20:15:30

Results:
  Packets:     1,234,567
  Duration:    600 seconds
  Latency:     12.3 ms avg
  Errors:      45 retransmissions

Actions:
  [View Report]  [Download JSON]  [Delete Task]
```

---

### Delete Task (Admin)

**⚠️ Admin Privilege**: Admins can delete any user's task

**Steps**:
1. Navigate to **Admin Panel** → **Tasks**
2. Locate task to delete
3. Click **Delete** button
4. Confirm deletion

**Effect**:
- Task record deleted from database
- PCAP file deleted from storage (if `DELETE_FILES=true`)
- Report files deleted (HTML + JSON)
- Cannot be undone

---

## Security Features

### Advanced Password Policy (zxcvbn)

PCAP Analyzer enforces a modern NIST-compliant password policy (v4.27+):

- **Minimum Length**: 12 characters.
- **Strength Validation**: Uses the `zxcvbn` library to estimate entropy.
- **Minimum Score**: Must be ≥ 3/4 (Strong or Very Strong).
- **Feedback**: Users receive real-time feedback and suggestions if their password is too weak.
- **Password History**: Prevents reuse of the last **5 passwords**.

**API Error Example**:
```json
{
  "detail": "Password is too weak (strength: 1/4, need ≥3). Warning: This is a common password. Suggestions: Add another word or two."
}
```

### Rate Limiting

**Failed Login Protection**:
- 1-4 failed attempts: No lockout
- 5 failed attempts: 1 second lockout
- 6 failed attempts: 2 seconds lockout
- 7+ failed attempts: 5 seconds lockout

**View Blocked IPs** (logs):
```bash
docker compose logs app | grep "Rate limit exceeded"
```

---

### CSRF Protection

**All State-Changing Actions** require CSRF token:
- Approve user
- Block user
- Delete user
- Create user
- Upload PCAP

**How it Works**:
1. Client requests CSRF token: `GET /api/csrf/token`
2. Server generates token signed with `CSRF_SECRET_KEY`
3. Client includes token in request: `X-CSRF-Token: <token>`
4. Server validates token signature

**Browser automatically handles CSRF tokens** in web UI (JavaScript fetch with credentials).

---

### Audit Logging

**All Admin Actions Logged**:
```
2025-12-21 20:00:00 WARNING  🔓 AUDIT: Admin john.admin approved user alice (id: 550e...)
2025-12-21 20:05:00 WARNING  🔒 AUDIT: Admin john.admin blocked user charlie (id: 660e...)
2025-12-21 20:10:00 WARNING  🗑️  AUDIT: Admin john.admin deleted user spam.bot (id: 770e...)
```

**View Audit Log**:
```bash
# Docker Compose
docker compose logs app | grep "AUDIT:"

# Kubernetes
kubectl logs -n pcap-analyzer deployment/pcap-analyzer | grep "AUDIT:"

# Save to file
docker compose logs app | grep "AUDIT:" > audit_log_$(date +%Y%m%d).txt
```

**Audit Log Retention**: Depends on log rotation policy (configure via logging system)

---

### Multi-Tenant Isolation

**Row-Level Isolation**:
- Regular users see **only their own tasks** (`WHERE owner_id = current_user.id`)
- Admins see **all tasks** (`role='admin'`)
- Database queries enforce isolation at application level

**Legacy Tasks** (NULL owner_id):
- Created before v5.0 (no multi-tenant support)
- Visible **only to admins**
- Regular users cannot access legacy tasks

---

## Best Practices

### Admin Account Management

1. **Change default admin password immediately** after first login
2. **Create individual admin accounts** (no shared accounts)
3. **Use strong passwords** (minimum 12 chars, mix of upper/lower/digits/symbols)
4. **Disable unused admin accounts** (block instead of delete for audit trail)
5. **Review admin accounts quarterly**

---

### User Approval

1. **Approve promptly** (within 24 hours)
2. **Verify email domain** (if corporate deployment)
3. **Check for duplicate accounts** (same email, similar usernames)
4. **Document rejection reasons** (in audit log or external system)
5. **Communicate with users** (email notification after approval)

---

### User Lifecycle

**Onboarding**:
1. User registers → Pending approval
2. Admin reviews → Approves
3. User receives notification (if email configured)
4. User logs in

**Offboarding**:
1. Admin blocks user (immediate access revocation)
2. Review user's tasks (archive if needed)
3. After retention period: Delete user account
4. Audit log entry preserved

---

### Security

1. **Enable HTTPS** (TLS/SSL) in production
2. **Use strong SECRET_KEY** (64 hex chars)
3. **Rotate SECRET_KEY quarterly** (invalidates all sessions)
4. **Monitor audit logs** for suspicious activity
5. **Review failed login attempts** (potential brute force)
6. **Use network-level MFA** (VPN, OAuth2 proxy)

---

## Troubleshooting

### Cannot Access Admin Panel

**Issue**: "Forbidden" error when accessing `/admin`

**Diagnosis**:
```bash
# Check current user role
curl -X GET http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <token>"

# Expected: {"role": "admin"}
```

**Solution**:
- Contact another admin to change your role to `admin`
- Or update database directly (not recommended):
  ```sql
  UPDATE users SET role='admin' WHERE username='your_username';
  ```

---

### User Cannot Login After Approval

**Issue**: User gets "Incorrect username or password" after approval

**Diagnosis**:
```bash
# Check user status
docker compose exec postgres psql -U pcap -d pcap_analyzer
SELECT username, is_approved, is_active FROM users WHERE username='alice';
\q
```

**Expected**:
- `is_approved = true`
- `is_active = true`

**Solution**:
- If `is_approved=false`: Re-approve user
- If `is_active=false`: Unblock user

---

### CSRF Token Failure

**Issue**: "Invalid CSRF token" error

**Diagnosis**:
- Check `CSRF_SECRET_KEY` is set
- Check `CSRF_SECRET_KEY` differs from `SECRET_KEY`
- Check token is included in request: `X-CSRF-Token` header

**Solution**:
```bash
# Generate new CSRF_SECRET_KEY
export CSRF_SECRET_KEY=$(openssl rand -hex 32)

# Restart application
docker compose restart app

# Get new token
curl -X GET http://localhost:8000/api/csrf/token \
  -H "Authorization: Bearer <token>"
```

---

### Pending Approvals Not Showing

**Issue**: No pending approvals in admin panel

**Diagnosis**:
```bash
# Check database directly
docker compose exec postgres psql -U pcap -d pcap_analyzer
SELECT username, is_approved FROM users WHERE is_approved=false;
\q
```

**Solution**:
- If users exist but not showing: Clear browser cache, hard refresh
- If no users in database: Users haven't registered yet

---

## Related Documentation

- [Admin Approval Workflow Guide](ADMIN_APPROVAL_WORKFLOW.md) - API-focused admin guide
- [Data Retention & Cleanup Policy](DATA_RETENTION_POLICY.md)
- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Audience**: Administrators
**Status**: Production Ready ✅
