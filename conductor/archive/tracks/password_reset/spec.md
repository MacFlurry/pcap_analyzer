# Track Specification: Password Reset Functionality

## Overview

Implémenter un système de réinitialisation de mot de passe sécurisé conforme aux standards OWASP pour PCAP Analyzer. Le système permettra aux utilisateurs de récupérer l'accès à leur compte de manière autonome, et aux administrateurs de réinitialiser les mots de passe en cas de besoin.

## Goals

1. **Self-Service Password Reset**: Permettre aux utilisateurs d'initier une réinitialisation de mot de passe par email avec un token sécurisé
2. **Admin-Initiated Reset**: Permettre aux admins de réinitialiser les mots de passe utilisateurs avec un mot de passe temporaire
3. **Security Compliance**: Respecter les standards OWASP ASVS v4.0 pour l'authentification
4. **User Experience**: Fournir un parcours fluide et intuitif avec feedback clair
5. **Auditability**: Logger tous les événements de sécurité pour audit trail complet

## Scope

### In Scope

**Database**:
- Nouvelle table `password_reset_tokens` avec colonnes: id, user_id, token_hash, created_at, expires_at, used_at, ip_address, user_agent
- Indexes pour performance (user_id, token_hash, expires_at)
- Foreign key CASCADE sur user_id
- Support PostgreSQL et SQLite

**Backend Services**:
- `PasswordResetService` pour génération/validation/consommation de tokens
- Token generation: 32 bytes (256 bits entropy) avec `secrets.token_urlsafe()`
- Token storage: hashed avec SHA-256 (jamais en clair)
- Token expiration: 1 heure (configurable)
- Token single-use: marqué comme utilisé après consommation

**API Endpoints**:
- `POST /api/auth/forgot-password`: Demande de réinitialisation (rate limited: 3/IP/15min)
- `POST /api/auth/reset-password`: Finalisation avec token
- `POST /api/auth/validate-reset-token`: Validation préalable (optionnel)
- `POST /api/admin/users/{user_id}/reset-password`: Admin-initiated reset

**Email Templates**:
- Password reset request (lien avec token)
- Password reset success (confirmation)
- Admin password reset (mot de passe temporaire)

**Frontend Pages**:
- `/forgot-password`: Formulaire de demande
- `/reset-password?token=...`: Formulaire de réinitialisation avec validation force
- Modification `/login`: Ajout lien "Mot de passe oublié?"
- Modification admin panel: Bouton "Reset Password" avec modal

**Security Features**:
- Anti-enumeration: réponses génériques identiques
- Rate limiting: 3 requests/IP/15min (forgot-password)
- Token security: 256 bits entropy, hashed SHA-256, single-use, 1h expiration
- Password validation: zxcvbn score ≥3, min 12 chars
- Password history: prevent reuse of last 5 passwords
- Admin protection: cannot reset other admin passwords
- 2FA preservation: 2FA settings maintained after password reset
- CSRF protection: all forms protected

**Testing**:
- Unit tests: PasswordResetService (95%+ coverage)
- Integration tests: API endpoints (100% coverage)
- E2E tests: Self-service flow, admin flow, edge cases
- Security tests: Rate limiting, token expiration, reuse prevention
- Coverage target: 85%+ pour le module password reset

### Out of Scope

- SMS-based password reset
- Security questions
- Account recovery via backup email
- Password reset via TOTP codes
- Biometric authentication
- Social login recovery
- Multi-factor authentication bypass
- Password reset link sent via SMS/WhatsApp
- Customizable expiration times par utilisateur
- Password reset history (different from password_history)

## Success Criteria

- [ ] **Functional**: User can successfully reset password via email link
- [ ] **Functional**: Admin can successfully reset user password with temp password
- [ ] **Security**: All OWASP ASVS V2.2 requirements met
- [ ] **Security**: Rate limiting prevents brute force attacks
- [ ] **Security**: Anti-enumeration prevents user discovery
- [ ] **Security**: Tokens are cryptographically secure (256 bits)
- [ ] **Security**: Tokens expire after 1 hour
- [ ] **Security**: Tokens are single-use only
- [ ] **Quality**: Code coverage ≥85% for password reset module
- [ ] **Quality**: All integration tests pass
- [ ] **Quality**: All E2E tests pass
- [ ] **Quality**: No regressions on existing tests
- [ ] **UX**: Password strength feedback in real-time
- [ ] **UX**: Clear error messages (no technical jargon)
- [ ] **UX**: Email delivery confirmation
- [ ] **Monitoring**: All security events logged (WARNING level)
- [ ] **Documentation**: User guide created
- [ ] **Documentation**: Admin guide created
- [ ] **Documentation**: API documentation updated

## Technical Requirements

### Database Schema

```sql
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_address TEXT,
    user_agent TEXT,
    CONSTRAINT token_not_expired CHECK (expires_at > created_at),
    CONSTRAINT token_hash_not_empty CHECK (length(token_hash) > 0)
);

CREATE INDEX idx_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_reset_tokens_expires_at ON password_reset_tokens(expires_at);
```

**SQLite Equivalent** (UUID as TEXT):
```sql
CREATE TABLE password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### API Specifications

#### POST /api/auth/forgot-password

**Request**:
```json
{
  "email": "user@example.com"
}
```

**Response** (always 200 OK):
```json
{
  "message": "If an account exists with this email, a password reset link has been sent."
}
```

**Rate Limit**: 3 requests per IP per 15 minutes
**Error Response** (429 Too Many Requests):
```json
{
  "detail": "Too many password reset requests. Please try again in 15 minutes."
}
```

#### POST /api/auth/reset-password

**Request**:
```json
{
  "token": "abc123xyz...",
  "new_password": "NewSecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "message": "Password reset successful. You can now login with your new password."
}
```

**Error Responses**:
- 400: `{"detail": "Invalid or expired token"}`
- 400: `{"detail": "Password too weak (strength: 2/4, need ≥3)"}`
- 400: `{"detail": "Password was used recently. Choose a different password"}`

#### POST /api/auth/validate-reset-token

**Request**:
```json
{
  "token": "abc123xyz..."
}
```

**Response** (200 OK):
```json
{
  "valid": true,
  "email": "u***@example.com"
}
```

**Error Response** (400):
```json
{
  "valid": false,
  "message": "Invalid or expired token"
}
```

#### POST /api/admin/users/{user_id}/reset-password

**Request**:
```json
{
  "send_email": true,
  "notify_user": true
}
```

**Response** (200 OK if send_email=false):
```json
{
  "user_id": "uuid...",
  "username": "john.doe",
  "temporary_password": "Xy9K-vBm2LpQ4nRt",
  "message": "Password reset successful. User will be prompted to change password on next login."
}
```

**Response** (200 OK if send_email=true):
```json
{
  "user_id": "uuid...",
  "username": "john.doe",
  "message": "Password reset email sent. User will be prompted to change password on next login."
}
```

**Error Responses**:
- 403: `{"detail": "Admin access required"}`
- 403: `{"detail": "Cannot reset another admin's password"}`
- 404: `{"detail": "User not found"}`

### Security Specifications

**Token Generation**:
```python
import secrets
import hashlib

# Generate 32 bytes (256 bits) of randomness
token_plaintext = secrets.token_urlsafe(32)  # Returns ~43 chars base64url

# Hash for storage (SHA-256)
token_hash = hashlib.sha256(token_plaintext.encode('utf-8')).hexdigest()

# Store token_hash in DB, send token_plaintext in email
```

**Token Validation**:
```python
# Hash received token
received_hash = hashlib.sha256(received_token.encode('utf-8')).hexdigest()

# Lookup in DB
token_record = db.query(PasswordResetToken).filter(
    PasswordResetToken.token_hash == received_hash,
    PasswordResetToken.expires_at > datetime.utcnow(),
    PasswordResetToken.used_at.is_(None)
).first()

if not token_record:
    raise HTTPException(400, "Invalid or expired token")
```

**Password Validation** (use existing zxcvbn):
```python
from zxcvbn import zxcvbn

result = zxcvbn(password)
if result['score'] < 3:  # 0-4 scale, need ≥3
    raise HTTPException(400, f"Password too weak (strength: {result['score']}/4, need ≥3)")
if len(password) < 12:
    raise HTTPException(400, "Password must be at least 12 characters")
```

**Rate Limiting** (extend existing RateLimiter):
```python
# In app/utils/rate_limiter.py
FORGOT_PASSWORD_LIMIT = {
    'max_attempts': 3,
    'window_seconds': 900,  # 15 minutes
    'lockout_seconds': 900
}
```

### Email Template Specifications

**Email 1: Password Reset Request**
- Subject: "Password Reset Request - PCAP Analyzer"
- Content:
  - Greeting with username
  - Explanation of request
  - Prominent reset button with link
  - Expiration notice (1 hour)
  - Single-use warning
  - IP address and timestamp for security
  - Contact support if user didn't request
- Link format: `https://pcaplab.com/reset-password?token={token}`

**Email 2: Password Reset Success**
- Subject: "Password Successfully Reset - PCAP Analyzer"
- Content:
  - Confirmation message
  - Login button
  - Security warning if user didn't make change
  - IP address and timestamp
  - Contact support

**Email 3: Admin Password Reset**
- Subject: "Administrator Password Reset - PCAP Analyzer"
- Content:
  - Notification of admin reset
  - Temporary password (monospace code block)
  - Warning about password_must_change
  - Login button
  - Administrator name and timestamp

### UI Specifications

**Forgot Password Page** (`/forgot-password`):
- Header: "Mot de passe oublié?"
- Email input field (validated)
- Submit button: "Envoyer le lien de réinitialisation"
- Success message (always shown after submit)
- Link back to login
- CSRF token

**Reset Password Page** (`/reset-password?token=...`):
- Token validation on load (AJAX)
- If invalid: Error message + link to request new reset
- If valid:
  - Display masked email (u***@example.com)
  - New password input (with show/hide toggle)
  - Confirm password input
  - Real-time strength indicator (zxcvbn)
  - Requirements list (12+ chars, score ≥3)
  - Submit button: "Réinitialiser le mot de passe"
- Redirect to login on success

**Admin Panel Modal**:
- Title: "Réinitialiser le mot de passe"
- Username display (read-only)
- Checkbox: "Envoyer par email"
- Checkbox: "Notifier l'utilisateur"
- Info: Explanation of temporary password
- Buttons: "Confirmer" / "Annuler"
- If send_email=false: Show temporary password with copy button

### Logging Specifications

All security events logged at WARNING level with consistent format:

```python
logger.warning(f"PASSWORD_RESET_REQUESTED: user_id={user_id}, email={email}, ip={ip_address}")
logger.warning(f"PASSWORD_RESET_TOKEN_CREATED: user_id={user_id}, expires_at={expires_at}")
logger.warning(f"PASSWORD_RESET_SUCCESS: user_id={user_id}, ip={ip_address}, token_age_minutes={age}")
logger.warning(f"PASSWORD_RESET_FAILED: reason={reason}, ip={ip_address}")
logger.warning(f"PASSWORD_RESET_RATE_LIMIT: ip={ip_address}, attempts={attempts}")
logger.warning(f"ADMIN_PASSWORD_RESET: admin_id={admin_id}, target_user_id={user_id}")
```

## Implementation Phases

See `plan.md` for detailed task breakdown.

**Phase 1** (Week 1): Database migration + PasswordResetService + unit tests
**Phase 2** (Week 2): Self-service API endpoints + integration tests
**Phase 3** (Week 2): Admin reset API + email templates + tests
**Phase 4** (Week 3-4): Frontend UI + E2E tests + documentation

## Dependencies

**Existing**:
- Python 3.10+
- FastAPI
- PostgreSQL / SQLite
- Alembic (migrations)
- bcrypt (password hashing)
- zxcvbn (password strength)
- fastapi-mail (email service)
- Playwright (E2E testing)

**New** (none required - use existing stack)

## Risks & Mitigations

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Email service down | Medium | High | Graceful degradation, log errors, generic success message |
| Token brute force | Low | High | Rate limiting, 256-bit entropy, 1h expiration |
| User enumeration | Medium | Medium | Generic responses, same timing for all requests |
| Admin account compromise | Low | Critical | Cannot reset other admins, audit logging |
| Token prediction | Very Low | Critical | Cryptographic RNG, SHA-256 hashing |
| Password reuse | Medium | Medium | Check password_history (already exists) |
| 2FA bypass | Low | High | Preserve 2FA settings, require 2FA code at login |

## Rollback Plan

1. **Code rollback**: Revert to previous version (no breaking changes)
2. **Database rollback**: Run Alembic downgrade migration
3. **Data loss**: None (tokens table can be dropped safely)
4. **User impact**: Minimal (feature removal only)

## Monitoring & Metrics

**Metrics to Track**:
- Password reset requests per hour
- Password reset success rate
- Token expiration rate (% expired before use)
- Email delivery failures
- Rate limit triggers
- Average time from request to reset completion

**Alerts**:
- Email failure rate > 5%
- Unusual spike in reset requests (>100/hour)
- High rate of expired tokens (>50%)
- Database errors during token operations

## Timeline

- **Phase 1**: 3-4 days
- **Phase 2**: 3-4 days
- **Phase 3**: 4-5 days
- **Phase 4**: 5-6 days
- **Total**: 15-19 days (~3-4 weeks)

## References

- OWASP ASVS v4.0 Section V2.2: https://github.com/OWASP/ASVS
- NIST SP 800-63B: https://pages.nist.gov/800-63-3/sp800-63b.html
- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
- Existing password_history implementation: `alembic/versions/2163cd9a7764_add_password_history_table.py`
- Existing email service: `app/services/email_service.py`
