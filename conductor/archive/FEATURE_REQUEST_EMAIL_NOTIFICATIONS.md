# Feature Request: Email Notifications for User Registration & Approval

**Status**: Pending Implementation
**Priority**: Medium
**Version**: Target v4.27.0
**Type**: Enhancement
**Reporter**: User Testing (Manual QA)
**Date**: 2025-12-25

---

## Executive Summary

The application currently lacks email notifications for user lifecycle events. Users have no confirmation when they register and no notification when their account is approved by an administrator. This creates a poor user experience and forces users to repeatedly check the login page.

**User Impact**: High - Affects all new users during registration and approval workflow.

---

## User Stories

### Story 1: Registration Confirmation Email
**As a** new user registering for an account
**I want to** receive an email confirmation immediately after registration
**So that** I know my registration was successful and understand that admin approval is required

**Acceptance Criteria**:
- Email sent immediately when user completes registration form
- Email contains: username, registration timestamp, pending approval status
- Email includes support/contact information
- Email is sent regardless of auto-approve setting
- Email sending does not block the registration response (async)
- Failed email sending does not prevent user creation (log error only)

### Story 2: Approval Notification Email
**As a** registered user waiting for approval
**I want to** receive an email when my account is approved
**So that** I can immediately login without repeatedly checking the site

**Acceptance Criteria**:
- Email sent when admin clicks "Approve" button
- Email contains: username, approval timestamp, login URL
- Email includes quick start guide or next steps
- Email is sent for both individual approval and bulk approval
- Email sending does not block the approval response (async)
- Failed email sending does not prevent approval (log error only)

---

## Current State Analysis

### Existing Email Infrastructure
**Finding**: No email infrastructure exists in the application.

**Evidence**:
```bash
# No email service files
$ find app -name "*email*" -o -name "*mail*"
# (no results)

# No SMTP configuration in .env.example
$ grep -i "smtp\|mail" .env.example
# (no results)

# User approval logs show no email activity
{"level": "INFO", "message": "User da73b171... approved by 7a286364..."}
{"level": "WARNING", "message": "🔓 AUDIT: Admin admin approved user obk"}
# No email-related logs
```

**User email is collected but unused**:
- Email stored in database: `app/services/user_database.py:59` (`email TEXT UNIQUE NOT NULL`)
- Email validated on registration: `app/models/user.py:46` (`email: EmailStr`)
- Email displayed in admin panel: `app/static/js/admin.js:219`
- **But**: No email service to send notifications

---

## Technical Requirements

### 1. Email Service Infrastructure

**Technology Choice**: `fastapi-mail` or `aiosmtplib`

**Recommendation**: `fastapi-mail`
- FastAPI-native integration
- Jinja2 template support for HTML emails
- Background task support (async)
- Well-documented and actively maintained

**Installation**:
```bash
pip install fastapi-mail jinja2
```

### 2. Environment Configuration

**New variables in `.env.example`**:
```bash
# ============================================
# Email Configuration (SMTP)
# ============================================
# SMTP server settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=noreply@yourcompany.com
SMTP_PASSWORD=your-app-specific-password

# Email sender details
MAIL_FROM=noreply@yourcompany.com
MAIL_FROM_NAME=PCAP Analyzer

# TLS/SSL settings
SMTP_TLS=true
SMTP_SSL=false

# Optional: Disable emails in dev mode
MAIL_ENABLED=true

# Optional: Support/contact email for user inquiries
SUPPORT_EMAIL=support@yourcompany.com

# Application URL for login links
APP_BASE_URL=http://pcap.local
```

### 3. Email Service Module

**File**: `app/services/email_service.py`

**Responsibilities**:
- SMTP connection management
- Template rendering (Jinja2)
- Email queue management (async with BackgroundTasks)
- Error handling and logging
- Email preview for development (save to file)

**Methods**:
```python
class EmailService:
    async def send_registration_email(user: User) -> None:
        """Send registration confirmation email"""

    async def send_approval_email(user: User) -> None:
        """Send account approval email"""

    async def send_rejection_email(user: User, reason: str) -> None:
        """Send account rejection email (future)"""
```

### 4. Email Templates

**Directory**: `app/templates/emails/`

**Templates needed**:

#### `registration_confirmation.html`
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Account Registration Confirmation</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px;">
        <h1 style="color: #2563eb;">Welcome to PCAP Analyzer!</h1>

        <p>Hello <strong>{{ username }}</strong>,</p>

        <p>Thank you for registering an account with PCAP Analyzer. Your registration was successful!</p>

        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
            <strong>⏳ Pending Administrator Approval</strong>
            <p>Your account is currently pending approval by an administrator. You will receive another email once your account has been approved and you can login.</p>
        </div>

        <h2>Registration Details</h2>
        <ul>
            <li><strong>Username:</strong> {{ username }}</li>
            <li><strong>Email:</strong> {{ email }}</li>
            <li><strong>Registration Date:</strong> {{ created_at }}</li>
        </ul>

        <p style="margin-top: 30px;">If you did not create this account, please contact us immediately at <a href="mailto:{{ support_email }}">{{ support_email }}</a>.</p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">

        <p style="color: #6c757d; font-size: 12px;">
            This is an automated email from PCAP Analyzer. Please do not reply to this email.
        </p>
    </div>
</body>
</html>
```

#### `account_approved.html`
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Account Approved</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 8px;">
        <h1 style="color: #10b981;">🎉 Your Account Has Been Approved!</h1>

        <p>Hello <strong>{{ username }}</strong>,</p>

        <p>Great news! Your PCAP Analyzer account has been approved by an administrator.</p>

        <div style="background: #d1fae5; border-left: 4px solid #10b981; padding: 15px; margin: 20px 0;">
            <strong>✅ You can now login and start analyzing network traffic!</strong>
        </div>

        <h2>Account Details</h2>
        <ul>
            <li><strong>Username:</strong> {{ username }}</li>
            <li><strong>Email:</strong> {{ email }}</li>
            <li><strong>Approved By:</strong> {{ approved_by }}</li>
            <li><strong>Approval Date:</strong> {{ approved_at }}</li>
        </ul>

        <div style="text-align: center; margin: 30px 0;">
            <a href="{{ login_url }}" style="background: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                Login Now
            </a>
        </div>

        <h2>Next Steps</h2>
        <ol>
            <li>Visit <a href="{{ login_url }}">{{ login_url }}</a></li>
            <li>Login with your username and password</li>
            <li>Upload a PCAP file to start analyzing network traffic</li>
        </ol>

        <p style="margin-top: 30px;">If you have any questions, please contact us at <a href="mailto:{{ support_email }}">{{ support_email }}</a>.</p>

        <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">

        <p style="color: #6c757d; font-size: 12px;">
            This is an automated email from PCAP Analyzer. Please do not reply to this email.
        </p>
    </div>
</body>
</html>
```

#### Plain-text versions (for email clients without HTML)
- `registration_confirmation.txt`
- `account_approved.txt`

### 5. Integration Points

#### Registration Endpoint (`app/api/routes/auth.py:191`)
```python
# BEFORE (current)
@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate, ...):
    new_user = await user_db.create_user(user_data=user, ...)
    return new_user

# AFTER (with email)
@router.post("/register", response_model=UserResponse)
async def register(
    user: UserCreate,
    background_tasks: BackgroundTasks,
    email_service: EmailService = Depends(get_email_service),
    ...
):
    new_user = await user_db.create_user(user_data=user, ...)

    # Send registration email asynchronously
    background_tasks.add_task(
        email_service.send_registration_email,
        new_user
    )

    return new_user
```

#### Approval Endpoint (`app/api/routes/auth.py:453`)
```python
# BEFORE (current)
@router.put("/admin/users/{user_id}/approve")
async def approve_user(user_id: str, ...):
    await user_db.approve_user(user_id, admin.id)
    updated_user = await user_db.get_user_by_id(user_id)
    return updated_user

# AFTER (with email)
@router.put("/admin/users/{user_id}/approve")
async def approve_user(
    user_id: str,
    background_tasks: BackgroundTasks,
    email_service: EmailService = Depends(get_email_service),
    ...
):
    await user_db.approve_user(user_id, admin.id)
    updated_user = await user_db.get_user_by_id(user_id)

    # Send approval email asynchronously
    background_tasks.add_task(
        email_service.send_approval_email,
        updated_user,
        admin.username
    )

    return updated_user
```

#### Bulk Approval Endpoint (`app/api/routes/auth.py:902`)
```python
# AFTER (with email for bulk operations)
@router.post("/admin/users/bulk-approve")
async def bulk_approve_users(
    request: BulkActionRequest,
    background_tasks: BackgroundTasks,
    email_service: EmailService = Depends(get_email_service),
    ...
):
    results = await user_db.bulk_approve_users(request.user_ids, admin.id)

    # Send approval emails for all successfully approved users
    for user_id in results["succeeded"]:
        user = await user_db.get_user_by_id(user_id)
        if user:
            background_tasks.add_task(
                email_service.send_approval_email,
                user,
                admin.username
            )

    return results
```

---

## Error Handling & Resilience

### Critical Design Principle
**Email failures MUST NOT prevent user registration or approval.**

### Error Handling Strategy

1. **Try-Catch in Email Service**:
```python
async def send_registration_email(self, user: User) -> None:
    try:
        # Attempt to send email
        await self._send_email(...)
        logger.info(f"Registration email sent to {user.email}")
    except SMTPException as e:
        logger.error(f"SMTP error sending registration email to {user.email}: {e}")
        # Do NOT raise - log only
    except Exception as e:
        logger.error(f"Unexpected error sending registration email to {user.email}: {e}")
        # Do NOT raise - log only
```

2. **Optional Email Service**:
```python
# If MAIL_ENABLED=false in .env
if os.getenv("MAIL_ENABLED", "true").lower() == "false":
    logger.info("Email service disabled (MAIL_ENABLED=false)")
    return  # Skip email sending
```

3. **SMTP Connection Pooling**:
- Use connection pooling to avoid timeout errors
- Graceful fallback if SMTP server unreachable

4. **Email Queue for High Volume** (Future Enhancement):
- Use Redis/Celery for production-scale email queues
- Current BackgroundTasks sufficient for MVP

---

## Testing Requirements

### Unit Tests (`tests/unit/test_email_service.py`)
1. Test email template rendering with mock data
2. Test SMTP connection handling
3. Test error handling (SMTP failures)
4. Test email sending with `MAIL_ENABLED=false`

### Integration Tests (`tests/integration/test_email_integration.py`)
1. Test registration endpoint sends email (mock SMTP)
2. Test approval endpoint sends email (mock SMTP)
3. Test bulk approval sends multiple emails
4. Test email failure does not block registration
5. Test email failure does not block approval

### E2E Tests (`tests/e2e/test_email_e2e.py`)
1. Use MailHog or similar SMTP testing tool
2. Register user and verify email received
3. Approve user and verify email received
4. Verify email content matches templates

### Manual QA Checklist
- [ ] Register new user → check registration email in inbox
- [ ] Verify email content (username, date, support email)
- [ ] Click links in email (if any)
- [ ] Approve user in admin panel → check approval email
- [ ] Verify approval email content (login URL, approved by, date)
- [ ] Test with invalid SMTP credentials → verify user still created
- [ ] Test with `MAIL_ENABLED=false` → verify no emails sent
- [ ] Test bulk approval → verify all users receive emails

---

## Security Considerations

### 1. Email Address Validation
- Already implemented: `EmailStr` in Pydantic models
- Prevents email injection attacks

### 2. SMTP Credentials Protection
- Store in environment variables only
- Never commit to version control
- Use app-specific passwords (Gmail, Outlook)
- Rotate credentials regularly

### 3. Rate Limiting
- Prevent email bombing attacks
- Limit registration emails per IP (use existing rate limiter)
- Admin approval emails exempt (trusted operation)

### 4. Email Content Sanitization
- Escape all user-provided content in templates
- Jinja2 auto-escaping enabled by default
- No user-controlled HTML in emails

### 5. SPF/DKIM/DMARC
- Configure DNS records for production domain
- Prevents emails being marked as spam
- Improves deliverability

---

## Deployment Considerations

### Development Environment
1. Use MailHog for local testing:
```yaml
# docker-compose.dev.yml
services:
  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP
      - "8025:8025"  # Web UI
```

2. Configure `.env` for MailHog:
```bash
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_TLS=false
MAIL_FROM=dev@pcap-analyzer.local
```

3. View emails at http://localhost:8025

### Kubernetes Production
1. Add SMTP secrets:
```bash
kubectl create secret generic smtp-credentials \
  --from-literal=host=smtp.gmail.com \
  --from-literal=port=587 \
  --from-literal=username=noreply@company.com \
  --from-literal=password='app-specific-password' \
  -n pcap-analyzer
```

2. Mount secrets in deployment:
```yaml
env:
  - name: SMTP_HOST
    valueFrom:
      secretKeyRef:
        name: smtp-credentials
        key: host
  - name: SMTP_USERNAME
    valueFrom:
      secretKeyRef:
        name: smtp-credentials
        key: username
  # ... etc
```

---

## Implementation Checklist

### Phase 1: Infrastructure (v4.27.0-alpha)
- [ ] Add `fastapi-mail` and `jinja2` to `requirements.txt`
- [ ] Create `app/services/email_service.py`
- [ ] Create email templates directory `app/templates/emails/`
- [ ] Add SMTP configuration to `.env.example`
- [ ] Create email templates (HTML + plain text)
- [ ] Write unit tests for email service

### Phase 2: Registration Email (v4.27.0-beta)
- [ ] Integrate email service with registration endpoint
- [ ] Add `BackgroundTasks` to registration handler
- [ ] Write integration tests for registration email
- [ ] Manual testing with MailHog
- [ ] Update API documentation

### Phase 3: Approval Email (v4.27.0-rc)
- [ ] Integrate email service with approval endpoint
- [ ] Integrate email service with bulk approval endpoint
- [ ] Add `BackgroundTasks` to approval handlers
- [ ] Write integration tests for approval emails
- [ ] Write E2E tests with email verification
- [ ] Manual testing with MailHog

### Phase 4: Production Deployment (v4.27.0)
- [ ] Configure production SMTP credentials (Gmail/SendGrid/AWS SES)
- [ ] Create Kubernetes secrets for SMTP
- [ ] Update Helm chart with email configuration
- [ ] Deploy to staging and verify
- [ ] Monitor email delivery rates
- [ ] Deploy to production
- [ ] Update user documentation

---

## Success Metrics

### Functional Metrics
- ✅ 100% of registrations trigger email within 5 seconds
- ✅ 100% of approvals trigger email within 5 seconds
- ✅ Email failure rate < 5%
- ✅ No registration/approval failures due to email errors

### User Experience Metrics
- ✅ User receives registration email immediately (< 30 seconds)
- ✅ User receives approval email immediately (< 30 seconds)
- ✅ Email deliverability > 95% (inbox, not spam)
- ✅ Email content renders correctly on mobile/desktop

### Technical Metrics
- ✅ Email service test coverage > 80%
- ✅ Integration test coverage > 90%
- ✅ Zero blocking email errors in production logs

---

## Future Enhancements (Post-v4.27.0)

### Account Rejection Email
- Send email when admin rejects/blocks user
- Include reason for rejection (optional)
- Provide appeal process information

### Password Reset Email
- "Forgot password" flow with reset link
- Time-limited token (1 hour expiry)
- Security notification on password change

### Digest Emails for Admins
- Daily/weekly summary of pending approvals
- New registrations report
- System health notifications

### Email Preferences
- User opt-in/opt-out for non-critical emails
- Email preference management in user profile
- Admin can disable emails per user

### Advanced Templates
- Multi-language support (i18n)
- Branded templates with logo
- Responsive email design (mobile-first)

---

## References

### Documentation
- [FastAPI-Mail Documentation](https://sabuhish.github.io/fastapi-mail/)
- [Jinja2 Template Documentation](https://jinja.palletsprojects.com/)
- [SMTP Email Standards (RFC 5321)](https://tools.ietf.org/html/rfc5321)

### Similar Implementations
- Django: `django.core.mail`
- Flask: `flask-mail`
- Express.js: `nodemailer`

### SMTP Providers for Production
- **Gmail**: Free (500/day), app passwords required
- **SendGrid**: Free tier (100/day), API-based
- **AWS SES**: Pay-per-use, high deliverability
- **Mailgun**: Free tier (5000/month), developer-friendly

---

## Questions for Stakeholders

1. **SMTP Provider**: Which email service provider will we use in production?
2. **Support Email**: What email should be displayed for user support inquiries?
3. **Email Branding**: Do we need company logo/branding in emails?
4. **Multi-language**: Do we need email templates in multiple languages?
5. **Email Retention**: Should we log sent emails for audit purposes?

---

**End of Feature Request**
