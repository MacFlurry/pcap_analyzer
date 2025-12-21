# API Documentation

**Version**: 5.0
**Date**: 2025-12-21
**Base URL**: `http://localhost:8000` (development)
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Interactive Documentation](#interactive-documentation)
3. [Authentication](#authentication)
4. [Common Workflows](#common-workflows)
5. [Endpoint Reference](#endpoint-reference)
6. [Error Handling](#error-handling)
7. [Rate Limiting](#rate-limiting)
8. [Examples](#examples)

---

## Overview

PCAP Analyzer v5.0 provides a **RESTful API** built with **FastAPI**, featuring:

- ✅ **OpenAPI 3.0** specification (auto-generated)
- ✅ **JWT authentication** (HS256)
- ✅ **CSRF protection** on state-changing endpoints
- ✅ **Multi-tenant isolation** (users see only their own data)
- ✅ **Role-based access control** (admin vs user)
- ✅ **Real-time progress** via Server-Sent Events (SSE)

---

## Interactive Documentation

### Swagger UI

**URL**: `http://localhost:8000/docs`

**Features**:
- **Try it out** - Execute API calls directly from browser
- **Request/Response** examples
- **Schema explorer** - View data models
- **Authentication** - Test with JWT tokens

**Access**:
1. Open `http://localhost:8000/docs` in browser
2. Click **Authorize** button
3. Enter JWT token: `Bearer <your_token>`
4. Try endpoints with **Execute** button

---

### ReDoc

**URL**: `http://localhost:8000/redoc`

**Features**:
- **Clean documentation** - Easier to read than Swagger
- **Code samples** - Multiple languages (curl, Python, JavaScript)
- **Search** - Find endpoints quickly
- **Export** - Download OpenAPI spec

**Best For**: Reading documentation, sharing with team

---

### OpenAPI Spec (JSON)

**URL**: `http://localhost:8000/openapi.json`

**Usage**:
- Import into Postman, Insomnia, or other API clients
- Generate client SDKs (openapi-generator)
- Integrate with CI/CD documentation pipelines

**Example**:
```bash
# Download OpenAPI spec
curl http://localhost:8000/openapi.json > openapi.json

# Generate Python client
openapi-generator generate -i openapi.json -g python -o python-client
```

---

## Authentication

### Register New User

**Endpoint**: `POST /api/register`

**Auth Required**: ❌ No

**Request**:
```bash
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'
```

**Response** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "is_active": true,
  "is_approved": false,  ← User cannot login yet (pending admin approval)
  "created_at": "2025-12-21T20:00:00Z"
}
```

**⚠️ Note**: User must be approved by admin before login.

---

### Login (Get JWT Token)

**Endpoint**: `POST /api/token`

**Auth Required**: ❌ No

**Request** (OAuth2 password flow):
```bash
curl -X POST http://localhost:8000/api/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=SecurePassword123!"
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800  ← 30 minutes
}
```

**Usage**:
```bash
# Store token
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Use in subsequent requests
curl -X GET http://localhost:8000/api/users/me \
  -H "Authorization: Bearer $TOKEN"
```

---

### Get CSRF Token

**Endpoint**: `GET /api/csrf/token`

**Auth Required**: ✅ Yes

**Request**:
```bash
curl -X GET http://localhost:8000/api/csrf/token \
  -H "Authorization: Bearer $TOKEN"
```

**Response** (200 OK):
```json
{
  "csrf_token": "1234567890abcdef:1640123456.789:a1b2c3d4e5f6..."
}
```

**Usage**: Include in `X-CSRF-Token` header for POST/PUT/DELETE requests.

---

## Common Workflows

### Workflow 1: Upload and Analyze PCAP

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!" \
  | jq -r '.access_token')

# 2. Get CSRF token
CSRF_TOKEN=$(curl -s -X GET http://localhost:8000/api/csrf/token \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.csrf_token')

# 3. Upload PCAP file
UPLOAD_RESPONSE=$(curl -s -X POST http://localhost:8000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -F "file=@capture.pcap")

TASK_ID=$(echo $UPLOAD_RESPONSE | jq -r '.task_id')
echo "Task ID: $TASK_ID"

# 4. Monitor progress (SSE)
curl -N http://localhost:8000/api/progress/$TASK_ID \
  -H "Authorization: Bearer $TOKEN"

# Output (Server-Sent Events):
# data: {"progress": 25, "status": "processing"}
# data: {"progress": 50, "status": "processing"}
# data: {"progress": 100, "status": "completed"}

# 5. Get report
curl -X GET http://localhost:8000/api/reports/$TASK_ID/html \
  -H "Authorization: Bearer $TOKEN" \
  > report.html

open report.html
```

---

### Workflow 2: Admin Approves User

```bash
# 1. Admin login
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=admin&password=AdminPassword123!" \
  | jq -r '.access_token')

# 2. List all users (admin only)
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Response shows pending users:
# [
#   {"id": "550e...", "username": "alice", "is_approved": false},
#   {"id": "660e...", "username": "bob", "is_approved": true}
# ]

# 3. Approve user
curl -X PUT http://localhost:8000/api/admin/users/550e8400-e29b-41d4-a716-446655440000/approve \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Response:
# {
#   "id": "550e8400-e29b-41d4-a716-446655440000",
#   "username": "alice",
#   "is_approved": true,
#   "approved_by": "admin-user-id",
#   "approved_at": "2025-12-21T20:05:00Z"
# }

# 4. User can now login
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!"
```

---

## Endpoint Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth | CSRF |
|--------|----------|-------------|------|------|
| POST | `/api/register` | User registration | ❌ | ❌ |
| POST | `/api/token` | Login (OAuth2 password flow) | ❌ | ❌ |
| GET | `/api/users/me` | Get current user info | ✅ | ❌ |
| PUT | `/api/users/me` | Update password | ✅ | ✅ |
| GET | `/api/csrf/token` | Get CSRF token | ✅ | ❌ |

---

### Analysis Endpoints

| Method | Endpoint | Description | Auth | CSRF |
|--------|----------|-------------|------|------|
| POST | `/api/upload` | Upload PCAP file | ✅ | ✅ |
| GET | `/api/progress/{task_id}` | Real-time progress (SSE) | ✅ | ❌ |
| GET | `/api/status/{task_id}` | Task status | ✅ | ❌ |
| GET | `/api/history` | Analysis history (filtered by owner) | ✅ | ❌ |
| GET | `/api/reports/{task_id}/html` | HTML report | ✅ | ❌ |
| GET | `/api/reports/{task_id}/json` | JSON report | ✅ | ❌ |
| DELETE | `/api/reports/{task_id}` | Delete report | ✅ | ✅ |

---

### Admin Endpoints

| Method | Endpoint | Description | Admin Only | CSRF |
|--------|----------|-------------|------------|------|
| GET | `/api/users` | List all users | ✅ | ❌ |
| POST | `/api/admin/users` | Create user with temp password | ✅ | ✅ |
| PUT | `/api/admin/users/{id}/approve` | Approve user registration | ✅ | ✅ |
| PUT | `/api/admin/users/{id}/block` | Block user account | ✅ | ✅ |
| PUT | `/api/admin/users/{id}/unblock` | Unblock user account | ✅ | ✅ |
| DELETE | `/api/admin/users/{id}` | Delete user account | ✅ | ✅ |

---

### System Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/health` | Health check | ❌ |
| GET | `/` | Homepage | ❌ |
| GET | `/login` | Login page | ❌ |
| GET | `/admin` | Admin panel | ✅ (Admin) |

---

## Error Handling

### HTTP Status Codes

| Code | Name | Description | Example |
|------|------|-------------|---------|
| **200** | OK | Success | GET /api/users/me |
| **201** | Created | Resource created | POST /api/register |
| **204** | No Content | Success, no body | DELETE /api/reports/{id} |
| **400** | Bad Request | Invalid input | Missing required field |
| **401** | Unauthorized | Authentication required | Missing/invalid token |
| **403** | Forbidden | Insufficient permissions | Regular user accessing admin endpoint |
| **404** | Not Found | Resource not found | GET /api/reports/nonexistent |
| **409** | Conflict | Resource conflict | Username already exists |
| **413** | Payload Too Large | File too large | PCAP > MAX_UPLOAD_SIZE_MB |
| **422** | Unprocessable Entity | Validation error | Invalid email format |
| **429** | Too Many Requests | Rate limit exceeded | 7+ failed logins |
| **500** | Internal Server Error | Server error | Unhandled exception |

---

### Error Response Format

**Standard Error**:
```json
{
  "detail": "Incorrect username or password"
}
```

**Validation Error** (422):
```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

---

### Common Errors

#### 401 Unauthorized

**Cause**: Missing or invalid JWT token

**Solution**:
```bash
# Re-login to get new token
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!"
```

---

#### 403 Forbidden

**Cause 1**: CSRF token missing or invalid

**Solution**:
```bash
# Get new CSRF token
CSRF_TOKEN=$(curl -s -X GET http://localhost:8000/api/csrf/token \
  -H "Authorization: Bearer $TOKEN" \
  | jq -r '.csrf_token')

# Include in request
curl -X POST http://localhost:8000/api/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -F "file=@capture.pcap"
```

**Cause 2**: Insufficient permissions (not admin)

**Solution**: Contact admin to change your role.

---

#### 404 Not Found

**Cause**: Resource doesn't exist or user lacks access

**Example**:
```bash
# User A tries to access User B's task
curl -X GET http://localhost:8000/api/reports/user_b_task_id/html \
  -H "Authorization: Bearer $USER_A_TOKEN"

# Response: 404 Not Found (multi-tenant isolation)
```

---

## Rate Limiting

### Failed Login Protection

| Failed Attempts | Lockout Duration |
|-----------------|------------------|
| 1-4             | No lockout       |
| 5               | 1 second         |
| 6               | 2 seconds        |
| 7+              | 5 seconds        |

**Example**:
```bash
# 7 failed logins
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=WRONG_PASSWORD"

# Response (429 Too Many Requests):
{
  "detail": "Rate limit exceeded. Please wait 5 seconds."
}

# Wait 5 seconds, then retry with correct password
sleep 5
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!"
```

---

## Examples

### Example 1: Register, Login, Upload, Get Report

**Complete Python Script**:

```python
import requests
import time
import json

BASE_URL = "http://localhost:8000"

# 1. Register
register_data = {
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!"
}
response = requests.post(f"{BASE_URL}/api/register", json=register_data)
print(f"Register: {response.status_code} - {response.json()}")

# 2. Admin approves (manual step, skip for demo)
# curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
#   -H "Authorization: Bearer <admin_token>"

# 3. Login
login_data = {
    "username": "alice",
    "password": "SecurePassword123!"
}
response = requests.post(f"{BASE_URL}/api/token", data=login_data)
token = response.json()["access_token"]
print(f"Token: {token[:20]}...")

# 4. Get CSRF token
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(f"{BASE_URL}/api/csrf/token", headers=headers)
csrf_token = response.json()["csrf_token"]

# 5. Upload PCAP
headers["X-CSRF-Token"] = csrf_token
files = {"file": open("capture.pcap", "rb")}
response = requests.post(f"{BASE_URL}/api/upload", headers=headers, files=files)
task_id = response.json()["task_id"]
print(f"Task ID: {task_id}")

# 6. Poll status
while True:
    response = requests.get(f"{BASE_URL}/api/status/{task_id}", headers={"Authorization": f"Bearer {token}"})
    status = response.json()
    print(f"Status: {status['status']} - Progress: {status['progress']}%")

    if status["status"] in ["completed", "failed"]:
        break

    time.sleep(2)

# 7. Get HTML report
response = requests.get(f"{BASE_URL}/api/reports/{task_id}/html", headers={"Authorization": f"Bearer {token}"})
with open("report.html", "wb") as f:
    f.write(response.content)
print("Report saved to report.html")
```

---

### Example 2: Admin Workflow (JavaScript)

```javascript
const BASE_URL = 'http://localhost:8000';

// Helper function
async function fetchAPI(endpoint, options = {}) {
  const response = await fetch(`${BASE_URL}${endpoint}`, options);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  return response.json();
}

// 1. Admin login
const login = await fetchAPI('/api/token', {
  method: 'POST',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'username=admin&password=AdminPassword123!'
});

const token = login.access_token;
const authHeaders = {
  'Authorization': `Bearer ${token}`,
  'Content-Type': 'application/json'
};

// 2. List all users
const users = await fetchAPI('/api/users', {
  headers: authHeaders
});

console.log('All users:', users);

// 3. Find pending users
const pendingUsers = users.filter(u => !u.is_approved);
console.log('Pending approvals:', pendingUsers);

// 4. Approve first pending user
if (pendingUsers.length > 0) {
  const userId = pendingUsers[0].id;

  const approved = await fetchAPI(`/api/admin/users/${userId}/approve`, {
    method: 'PUT',
    headers: authHeaders
  });

  console.log('Approved user:', approved);
}

// 5. View all tasks (admin sees everyone's tasks)
const allTasks = await fetchAPI('/api/history', {
  headers: authHeaders
});

console.log('All tasks (admin view):', allTasks);
```

---

### Example 3: Monitor Progress with SSE

**JavaScript (Browser)**:

```javascript
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
const taskId = 'abc-123-task-id';

const eventSource = new EventSource(
  `http://localhost:8000/api/progress/${taskId}`,
  {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  }
);

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Progress: ${data.progress}% - Status: ${data.status}`);

  // Update UI
  document.getElementById('progress-bar').style.width = `${data.progress}%`;

  // Close connection when done
  if (data.status === 'completed' || data.status === 'failed') {
    eventSource.close();
    console.log('Processing finished');
  }
};

eventSource.onerror = (error) => {
  console.error('SSE error:', error);
  eventSource.close();
};
```

---

## Security Considerations

### Best Practices

1. **Always use HTTPS** in production
2. **Never log tokens** (sensitive data)
3. **Store tokens securely** (httpOnly cookies or secure storage)
4. **Include CSRF tokens** on all POST/PUT/DELETE requests
5. **Handle 401 errors** (re-login when token expires)
6. **Validate input** on client side (UX) and trust server validation
7. **Use environment variables** for API URL (don't hardcode)

---

### Token Expiration

**JWT tokens expire after 30 minutes**:

```javascript
// Good: Handle 401 and refresh token
async function fetchWithAuth(endpoint, options) {
  let response = await fetch(endpoint, options);

  if (response.status === 401) {
    // Token expired, re-login
    const token = await login();
    options.headers['Authorization'] = `Bearer ${token}`;
    response = await fetch(endpoint, options);
  }

  return response;
}
```

---

## Related Documentation

- [README.md](../README.md) - API endpoint table
- [Admin Approval Workflow Guide](ADMIN_APPROVAL_WORKFLOW.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Interactive Docs**: http://localhost:8000/docs
**Status**: Production Ready ✅
