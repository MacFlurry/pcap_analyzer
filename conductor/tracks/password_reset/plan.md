# Track: Password Reset Functionality

**Goal**: Implémenter deux fonctionnalités de réinitialisation de mot de passe pour améliorer l'UX et la sécurité
**Status**: Proposed
**Coverage Target**: 85%+ pour le module password reset

---

## Context

L'application PCAP Analyzer dispose d'un système d'authentification robuste (OAuth2 + JWT, bcrypt, 2FA TOTP, zxcvbn validation, password history). **Manque actuel**: Aucun mécanisme de récupération de mot de passe. Les utilisateurs qui oublient leur mot de passe doivent contacter un administrateur manuellement.

Cette track implémente:
1. **Self-service password reset**: L'utilisateur demande un lien par email, reçoit un token sécurisé, et peut réinitialiser son mot de passe
2. **Admin-initiated reset**: L'admin peut forcer la réinitialisation d'un mot de passe utilisateur avec un mot de passe temporaire

---

## Prerequisites

- [x] Système d'authentification existant (OAuth2/JWT)
- [x] Service d'email configuré (FastAPI-mail)
- [x] Validation de mot de passe (zxcvbn)
- [x] Historique de mots de passe (table `password_history`)
- [x] Rate limiting infrastructure
- [x] Suite de tests E2E avec Playwright

---

## Implementation Plan

### Phase 1: Base de Données & Services Core

**Objectif**: Créer le schéma de base de données et la logique métier centrale

- [x] **Task 1.1**: Créer migration Alembic `password_reset_tokens` table (f209109)
  - Fichier: `alembic/versions/XXXX_add_password_reset_tokens.py`
  - Colonnes: id (UUID), user_id (FK CASCADE), token_hash (SHA-256), created_at, expires_at (1h), used_at, ip_address, user_agent
  - Indexes: user_id, token_hash, expires_at
  - Support PostgreSQL et SQLite (pattern: migration 2163cd9a7764)
  - Constraint: `expires_at > created_at`

- [ ] **Task 1.2**: Implémenter `PasswordResetService`
  - Fichier: `app/services/password_reset_service.py`
  - `generate_reset_token()` → (token_plaintext, token_hash) using `secrets.token_urlsafe(32)` + SHA-256
  - `create_reset_token(user_id, ip, user_agent)` → token_plaintext
  - `validate_token(token_hash)` → User or None (check: exists, !expired, !used, user active)
  - `consume_token(token_hash)` → bool (mark used_at)
  - `cleanup_expired_tokens()` → count deleted
  - `invalidate_user_tokens(user_id)` → count deleted

- [ ] **Task 1.3**: Tests unitaires `PasswordResetService`
  - Fichier: `tests/unit/services/test_password_reset_service.py`
  - Test génération tokens uniques
  - Test hachage déterministe
  - Test validation token valide
  - Test rejet token expiré
  - Test rejet token déjà utilisé
  - Test nettoyage tokens expirés
  - Coverage: 95%+

**Checkpoint Phase 1**: Migration appliquée, service fonctionnel, tests passent

---

### Phase 2: API Self-Service

**Objectif**: Implémenter les endpoints pour réinitialisation self-service

- [ ] **Task 2.1**: Endpoint `POST /api/auth/forgot-password`
  - Fichier: `app/api/routes/auth.py`
  - Input: `{"email": "user@example.com"}`
  - Réponse: Toujours 200 OK + message générique (anti-énumération)
  - Rate limiting: 3 requêtes/IP/15min
  - Logic: valider email → lookup user (case-insensitive) → si active+approved: créer token + email → log event → réponse générique
  - Intégrer avec `RateLimiter` existant

- [ ] **Task 2.2**: Endpoint `POST /api/auth/reset-password`
  - Input: `{"token": "...", "new_password": "..."}`
  - Réponse: 200 OK ou 400 Bad Request
  - Logic:
    1. Valider nouveau mot de passe (zxcvbn ≥3)
    2. Hacher token avec SHA-256
    3. Valider token (exists, !expired, !used, user active)
    4. Vérifier password_history (pas de réutilisation)
    5. Mettre à jour password (bcrypt)
    6. Marquer token utilisé
    7. Invalider autres tokens user
    8. Clear password_must_change
    9. Email de confirmation
    10. Log security event

- [ ] **Task 2.3**: Endpoint `POST /api/auth/validate-reset-token` (optionnel)
  - Input: `{"token": "..."}`
  - Réponse: `{"valid": true, "email": "u***@example.com"}`
  - Logic: valider token + retourner email masqué

- [ ] **Task 2.4**: Tests d'intégration API
  - Fichier: `tests/integration/test_password_reset_api.py`
  - Test forgot-password: user existant vs inexistant (même réponse)
  - Test reset-password: token valide, expiré, réutilisé
  - Test validation mot de passe: faible, dans historique
  - Test rate limiting
  - Coverage: 100% endpoints

**Checkpoint Phase 2**: Endpoints fonctionnels, tests passent, rate limiting actif

---

### Phase 3: Admin Reset & Email Templates

**Objectif**: Implémenter réinitialisation admin et templates d'emails

- [ ] **Task 3.1**: Endpoint `POST /api/admin/users/{user_id}/reset-password`
  - Fichier: `app/api/routes/auth.py`
  - Input: `{"send_email": bool, "notify_user": bool}`
  - Réponse: `{"user_id", "username", "temporary_password", "message"}`
  - Logic:
    1. Auth admin (get_current_admin_user)
    2. Vérifier user existe
    3. Bloquer reset admin→admin
    4. Générer temp password (16 chars, secrets.token_urlsafe)
    5. Hash bcrypt + update user
    6. Set password_must_change=True
    7. Si send_email: envoyer email, sinon retourner password
    8. Log AUDIT

- [ ] **Task 3.2**: Ajouter méthodes email `EmailService`
  - Fichier: `app/services/email_service.py`
  - `send_password_reset_request_email(user, reset_link, ip, timestamp)`
  - `send_password_reset_success_email(user, ip, timestamp)`
  - `send_admin_password_reset_email(user, temp_password, admin_username)`
  - Pattern: suivre `send_approval_email()` existant

- [ ] **Task 3.3**: Template email "Demande de réinitialisation"
  - Fichier: `app/templates/emails/password_reset_request.html`
  - Contenu: salutation, explication, bouton reset, expiration 1h, single-use warning, détails IP/timestamp, contact support
  - Style: suivre `account_approved.html`

- [ ] **Task 3.4**: Template email "Réinitialisation réussie"
  - Fichier: `app/templates/emails/password_reset_success.html`
  - Contenu: confirmation, lien login, warning sécurité, détails IP/timestamp

- [ ] **Task 3.5**: Template email "Admin reset"
  - Fichier: `app/templates/emails/admin_password_reset.html`
  - Contenu: notification reset admin, temp password (monospace), warning password_must_change, bouton login, détails admin/timestamp

- [ ] **Task 3.6**: Tests intégration admin reset
  - Fichier: `tests/integration/test_admin_password_reset.py`
  - Test admin reset user → succès
  - Test admin reset admin → erreur 403
  - Test user reset user → erreur 403
  - Test password_must_change flag
  - Test email envoyé vs password retourné

- [ ] **Task 3.7**: Tests unitaires emails
  - Fichier: `tests/unit/services/test_password_reset_emails.py`
  - Test rendering templates
  - Test variables substituées

**Checkpoint Phase 3**: Admin reset fonctionnel, emails envoyés, tests passent

---

### Phase 4: Frontend UI & Tests E2E

**Objectif**: Créer les pages UI et tests end-to-end complets

- [ ] **Task 4.1**: Modifier login - ajouter lien "Mot de passe oublié?"
  - Fichier: `app/templates/login.html`
  - Ajouter lien après bouton "Se connecter"
  - Style cohérent avec lien "S'inscrire"

- [ ] **Task 4.2**: Page "Mot de passe oublié"
  - Fichier: `app/templates/forgot-password.html`
  - Éléments: header, input email, bouton, message succès (toujours affiché), lien retour login, CSRF protection
  - Style: suivre login.html

- [ ] **Task 4.3**: Page "Réinitialiser mot de passe"
  - Fichier: `app/templates/reset-password.html`
  - Validation token au chargement (AJAX)
  - Si invalide: message erreur + lien forgot-password
  - Si valide: email masqué, inputs password (show/hide toggle), confirmation, indicateur force (zxcvbn), exigences, bouton
  - Redirect login après succès

- [ ] **Task 4.4**: Routes pour pages forgot/reset
  - Fichier: `app/api/routes/views.py`
  - `GET /forgot-password` → render forgot-password.html
  - `GET /reset-password` → render reset-password.html (token query param)
  - Pattern: suivre `/login`

- [ ] **Task 4.5**: Admin panel - bouton "Reset Password"
  - Fichier: `app/templates/admin.html`
  - Bouton dans menu actions utilisateur
  - Modal: checkbox "Envoyer par email", "Notifier", bouton confirmer
  - Si pas email: afficher temp password avec bouton copier

- [ ] **Task 4.6**: JavaScript admin reset
  - Fichier: `app/static/js/admin.js`
  - Méthode `resetUserPassword(userId, sendEmail, notifyUser)`
  - Modal confirmation
  - Call POST `/api/admin/users/{userId}/reset-password`
  - Afficher temp password si applicable
  - Reload liste

- [ ] **Task 4.7**: Tests E2E - Self-service flow
  - Fichier: `tests/e2e/test_password_reset_flow.py`
  - Test `test_complete_password_reset_flow`: login → forgot link → email → extract token DB → reset page → nouveau password → login success
  - Pattern: suivre `test_admin_full_workflow()`

- [ ] **Task 4.8**: Tests E2E - Admin reset flow
  - Test `test_admin_reset_user_password`: login admin → admin panel → reset user → copy temp password → logout → login user → verify password_must_change

- [ ] **Task 4.9**: Tests E2E - Edge cases
  - Token expiré, réutilisé, password faible, rate limiting, admin vs admin

**Checkpoint Phase 4**: UI complet, E2E tests passent, parcours fluide

---

## Configuration

Variables d'environnement à ajouter (`.env`):

```bash
PASSWORD_RESET_TOKEN_EXPIRY_MINUTES=60        # Défaut: 1 heure
PASSWORD_RESET_MAX_TOKENS_PER_USER=5          # Max tokens actifs par user
PASSWORD_RESET_CLEANUP_INTERVAL_HOURS=24      # Nettoyage auto
RATE_LIMIT_FORGOT_PASSWORD_MAX=3              # Max demandes/IP
RATE_LIMIT_FORGOT_PASSWORD_WINDOW=15          # Fenêtre en minutes
```

---

## Testing Strategy

**Coverage Targets**:
- Global module password reset: 85%+
- Endpoints API: 100%
- Service layer: 95%+
- Email sending: 80%+ (mocké)

**Test Types**:
1. **Unit** (pytest): token generation/validation, PasswordResetService, email rendering
2. **Integration** (pytest + TestClient): API endpoints, rate limiting, password validation
3. **E2E** (Playwright): parcours complets user + admin, edge cases

**Commands**:
```bash
pytest tests/unit/services/test_password_reset_service.py -v
pytest tests/integration/test_password_reset_api.py -v
pytest tests/integration/test_admin_password_reset.py -v
pytest tests/e2e/test_password_reset_flow.py -v --headed
pytest --cov=app.services.password_reset_service --cov=app.api.routes.auth --cov-report=term-missing
```

---

## Security (OWASP ASVS)

- [x] V2.1.1: Password policy (12+ chars, zxcvbn ≥3) - existant
- [x] V2.1.7: Prevent password reuse (last 5) - existant
- [x] V2.2.1: Rate limiting sur endpoints reset
- [x] V2.2.2: Anti-énumération (réponses génériques)
- [x] V2.2.3: Account lockout - existant
- [x] V2.2.4: Token entropy (256 bits)
- [x] V2.2.5: Token expiration (1h)
- [x] V2.2.6: Single-use tokens
- [x] V3.5.1: Cryptographic token generation (secrets)
- [x] V3.5.2: Token storage security (hashed SHA-256)
- [x] V9.1.1: HTTPS pour liens reset (prod)
- [x] V9.1.2: Sensitive data pas dans URLs

---

## Edge Cases

| Scénario | Comportement |
|----------|--------------|
| User bloqué | Pas d'email, réponse générique |
| User non approuvé | Pas d'email, réponse générique |
| User admin | Reset autorisé (self-service + admin si différent) |
| User 2FA actif | Reset autorisé, 2FA préservé |
| Tokens multiples | Tous invalidés après reset réussi |
| Token réutilisé | Rejet "Invalid or expired token" |
| Token expiré | Rejet "Invalid or expired token" |
| Mot de passe réutilisé | Rejet avec message password_history |
| Email service down | Log error, pas de crash, user voit succès |
| Admin reset autre admin | Erreur 403 Forbidden |

---

## Documentation

- [ ] `docs/password-reset.md` - Guide utilisateur et admin
- [ ] Mettre à jour `README.md` - Section sécurité
- [ ] Mettre à jour `conductor/tech-stack.md` si nouvelles dépendances
- [ ] Changelog entry pour v5.1.0

---

## Definition of Done

- [ ] Migration DB appliquée (PostgreSQL + SQLite)
- [ ] Service PasswordResetService fonctionnel
- [ ] 4 endpoints API créés et testés
- [ ] 3 templates email créés
- [ ] 2 pages UI (forgot, reset) fonctionnelles
- [ ] Admin panel étendu avec reset password
- [ ] Rate limiting actif
- [ ] Coverage ≥85% module password reset
- [ ] Tests E2E passent (self-service + admin)
- [ ] OWASP checklist validée
- [ ] Documentation complète
- [ ] Aucune régression sur tests existants

---

## Notes d'Implémentation

1. **TDD**: Écrire les tests AVANT l'implémentation (workflow Conductor)
2. **Commits**: Un commit par tâche avec SHA tracké dans plan.md
3. **Security**: Priorité absolue - valider chaque endpoint
4. **UX**: Messages clairs, pas de jargon technique
5. **Monitoring**: Logger tous les événements de sécurité (WARNING level)
6. **Email fallback**: Graceful degradation si email service down
7. **2FA**: Préserver les settings 2FA après reset password
8. **Admin protection**: Empêcher reset mutuel entre admins
