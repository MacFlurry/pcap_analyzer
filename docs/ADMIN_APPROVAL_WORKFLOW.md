# Admin Approval Workflow Guide

**Version**: 5.0
**Date**: 2025-12-21
**Security**: OWASP ASVS V3.2 Compliant ✅

---

## Overview

The Admin Approval Workflow ensures that all new user registrations are reviewed and approved by an administrator before granting access to the PCAP Analyzer platform. This prevents unauthorized access and allows administrators to maintain control over who can use the system.

### Security Benefits

- **Prevents spam registrations** and bot accounts
- **Compliance**: OWASP ASVS V3.2 (Session Management)
- **Audit trail**: All admin actions are logged
- **Multi-tenant isolation**: Each user can only see their own data

---

## User Registration Flow

### Step 1: Self-Service Registration

Users register via the `/api/register` endpoint:

```bash
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "email": "john.doe@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "email": "john.doe@example.com",
  "role": "user",
  "is_active": true,
  "is_approved": false,
  "created_at": "2025-12-21T20:00:00Z"
}
```

**User State**: Account created but **cannot login** (is_approved=false)

---

### Step 2: Admin Reviews Registration

Admins view pending registrations:

```bash
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>"
```

**Response**:
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "john.doe",
    "email": "john.doe@example.com",
    "role": "user",
    "is_approved": false,  // ⚠️ Pending approval
    "created_at": "2025-12-21T20:00:00Z"
  }
]
```

---

### Step 3: Admin Approves User

Admin approves the registration:

```bash
curl -X PUT http://localhost:8000/api/admin/users/550e8400-e29b-41d4-a716-446655440000/approve \
  -H "Authorization: Bearer <admin_token>"
```

**Response**:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "john.doe",
  "is_approved": true,  // ✅ Approved
  "approved_by": "admin-user-id",
  "approved_at": "2025-12-21T20:05:00Z"
}
```

**Audit Log** (server-side):
```
🔓 AUDIT: Admin alice approved user john.doe (id: 550e8400-e29b-41d4-a716-446655440000)
```

---

### Step 4: User Can Login

User can now login:

```bash
curl -X POST http://localhost:8000/api/token \
  -d "username=john.doe&password=SecurePassword123!"
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

## Admin Actions

### List All Users

**Endpoint**: `GET /api/users`
**Auth**: Admin only

```bash
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>"
```

**Response**: Array of all users (approved and pending)

---

### Approve User

**Endpoint**: `PUT /api/admin/users/{user_id}/approve`
**Auth**: Admin only

**Effect**:
- Sets `is_approved = true`
- Records `approved_by` (admin user ID)
- Records `approved_at` (timestamp)
- Logs audit event

---

### Block User

**Endpoint**: `PUT /api/admin/users/{user_id}/block`
**Auth**: Admin only

**Effect**:
- Sets `is_active = false`
- User **cannot login** (existing sessions remain valid until token expiry)
- Does **not** delete user data
- Logs audit event

**Example**:
```bash
curl -X PUT http://localhost:8000/api/admin/users/550e8400.../block \
  -H "Authorization: Bearer <admin_token>"
```

---

### Unblock User

**Endpoint**: `PUT /api/admin/users/{user_id}/unblock`
**Auth**: Admin only

**Effect**:
- Sets `is_active = true`
- User can login again
- Logs audit event

---

### Delete User

**Endpoint**: `DELETE /api/admin/users/{user_id}`
**Auth**: Admin only

**Effect**:
- **Permanently deletes** user account
- **Does NOT delete** user's tasks (orphaned with owner_id = user_id)
- Admin **cannot delete their own account** (safety measure)
- Logs audit event

**⚠️ WARNING**: This action is **irreversible**. Consider blocking instead of deleting.

---

### Create User with Temporary Password

**Endpoint**: `POST /api/admin/users`
**Auth**: Admin only

**Use case**: Admin creates account for user who hasn't self-registered

**Request**:
```bash
curl -X POST http://localhost:8000/api/admin/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice.smith",
    "email": "alice@example.com",
    "password": "TempPassword123!",
    "role": "user"
  }'
```

**Response**:
```json
{
  "id": "...",
  "username": "alice.smith",
  "is_approved": true,  // ✅ Auto-approved
  "password_must_change": true  // ⚠️ User must change password on first login
}
```

**User must change password** via:
```bash
PUT /api/users/me
{
  "current_password": "TempPassword123!",
  "new_password": "MyNewSecurePassword456!"
}
```

---

## Admin Brise-Glace Account

### Initial Setup

On first boot, the application creates an **admin brise-glace** account:

```
🔒 ADMIN BRISE-GLACE ACCOUNT CREATED
================================================================================
Username: admin
Password: aB3dEf9Gh2JkLm5NpQrStUvWxYz  (random 24-char password)

📝 Password loaded from /var/run/secrets/admin_password (if file exists)
🔐 Random password generated (if no secrets file found)

⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!
   Use: PUT /api/users/me with new password
================================================================================
```

### Password Sources (Priority Order)

1. **Kubernetes Secret** (recommended): `/var/run/secrets/admin_password`
2. **Random generation**: If no secret file exists

### Changing Admin Password

**First login**:
```bash
# Login
curl -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<displayed_password>"

# Change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<displayed_password>",
    "new_password": "MyNewAdminPassword123!"
  }'
```

**Security note**: The admin password is displayed on **STDOUT only** (not in persistent logs), complying with CWE-532 (sensitive information in logs).

---

## Web UI Workflow

### Login Page

**URL**: `http://localhost:8000/login`

**Features**:
- Username/password form
- "Remember me" (extends token expiry)
- Link to registration page

---

### Registration Page

**URL**: `http://localhost:8000/register` (if exists in UI)

**Form fields**:
- Username (minimum 3 chars)
- Email (valid email format)
- Password (minimum 12 chars)

**After submission**:
- User sees: "Registration successful! Your account is pending admin approval."
- User **cannot login** until approved

---

### Admin Panel

**URL**: `http://localhost:8000/admin`
**Auth**: Admin only (redirects to login if not authenticated)

**Features**:
- **User list**: Shows all users (approved and pending)
- **Pending approvals badge**: Highlights users awaiting approval
- **Bulk actions**: Approve/block/delete multiple users
- **Search/filter**: By username, email, role, approval status

**User table columns**:
- Username
- Email
- Role (admin/user)
- Status (active/blocked)
- Approval (pending/approved)
- Created date
- Actions (approve/block/delete)

---

## Security Considerations

### Password Policy

**Enforced by application**:
- Minimum 12 characters
- No maximum (up to 128 chars accepted)
- bcrypt cost factor 12 (2025 recommended)
- Passwords **never logged** (CWE-532 compliance)

### Rate Limiting

**Brute force protection**:
- 4 failed attempts: No lockout
- 5 failed attempts: 1 second lockout
- 6 failed attempts: 2 seconds lockout
- 7+ failed attempts: 5 seconds lockout

**Implementation**: IP-based rate limiting with exponential backoff

### Session Security

**JWT tokens**:
- Algorithm: HS256
- Expiration: 30 minutes
- Refresh: Not implemented (user must re-login)
- SECRET_KEY: **Required in production** (fails hard if missing)

### Multi-Tenant Isolation

**CWE-639 compliance**:
- Each task has `owner_id` foreign key
- Users can **only see** their own tasks
- Admins can **see all** tasks
- Database queries enforce: `WHERE owner_id = current_user.id`

### Audit Logging

**All admin actions logged**:
```
🔓 AUDIT: Admin alice approved user bob.jones (id: 550e...)
🔒 AUDIT: Admin alice blocked user charlie.brown (id: 660e...)
🗑️  AUDIT: Admin alice deleted user spam.account (id: 770e...)
```

**Log location**: Application logs (not database)
**Format**: Structured JSON with timestamp, level, message

---

## Troubleshooting

### User Cannot Login After Approval

**Symptom**: User gets "Incorrect username or password" after admin approval

**Diagnosis**:
```bash
# Check user status
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>" | jq '.[] | select(.username=="john.doe")'
```

**Expected**:
```json
{
  "is_approved": true,
  "is_active": true
}
```

**Solution**: If `is_approved=false`, re-approve user. If `is_active=false`, unblock user.

---

### Admin Cannot Access Admin Panel

**Symptom**: HTTP 403 Forbidden on `/admin`

**Diagnosis**:
```bash
# Check current user role
curl -X GET http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <token>"
```

**Expected**:
```json
{
  "role": "admin"
}
```

**Solution**: Only users with `role='admin'` can access admin endpoints. Contact another admin to update your role.

---

### Admin Deleted Own Account by Mistake

**Symptom**: Admin deleted user but it was their own account

**Prevention**: Application **prevents** self-deletion:
```json
{
  "detail": "Cannot delete your own account"
}
```

**If bypassed** (e.g., direct database access):
1. Create new admin via database:
   ```sql
   INSERT INTO users (id, username, email, hashed_password, role, is_approved)
   VALUES (gen_random_uuid(), 'recovery_admin', 'admin@example.com', '<bcrypt_hash>', 'admin', true);
   ```
2. Use recovery admin to restore original admin (if user not deleted)

---

## API Reference

### Admin Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/users` | GET | Admin | List all users |
| `/api/admin/users` | POST | Admin | Create user with temp password |
| `/api/admin/users/{id}/approve` | PUT | Admin | Approve user registration |
| `/api/admin/users/{id}/block` | PUT | Admin | Block user account |
| `/api/admin/users/{id}/unblock` | PUT | Admin | Unblock user account |
| `/api/admin/users/{id}` | DELETE | Admin | Delete user account |

### User Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/register` | POST | No | Self-service registration |
| `/api/token` | POST | No | Login (OAuth2 password flow) |
| `/api/users/me` | GET | Yes | Get current user info |
| `/api/users/me` | PUT | Yes | Update password |

---

## Related Documentation

- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)
- [API Documentation](API_DOCUMENTATION.md)
- [Migration Guide v5.0](MIGRATION_GUIDE_v5.0.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Compliance**: OWASP ASVS V3.2 ✅
