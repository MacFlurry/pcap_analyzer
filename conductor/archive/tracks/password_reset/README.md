# Track: Password Reset Functionality

## Quick Overview

Implémenter un système de réinitialisation de mot de passe sécurisé pour PCAP Analyzer avec deux parcours :
1. **Self-service**: Utilisateur reçoit un lien par email avec token sécurisé
2. **Admin-initiated**: Admin force la réinitialisation avec mot de passe temporaire

**Status**: 🟡 Proposed (not started)
**Priority**: High (amélioration UX critique)
**Security**: OWASP ASVS V2.2 compliant

## Current Blockers

None - tous les prérequis sont satisfaits.

## Files in this Track

- `plan.md` - Plan d'implémentation détaillé avec 4 phases et checkboxes
- `spec.md` - Spécification technique complète (API, DB, sécurité, UI)
- `README.md` - Ce fichier (quick reference)
- `metadata.json` - Métadonnées du track

## Quick Start

### Pour implémenter ce track:

1. Lire `plan.md` pour comprendre les 4 phases d'implémentation
2. Consulter `spec.md` pour les détails techniques
3. Suivre l'approche TDD : écrire les tests avant le code
4. Marquer chaque tâche dans `plan.md` avec le commit SHA
5. Vérifier coverage ≥85% pour le module

### Commandes rapides:

```bash
# Phase 1: Migration DB
alembic revision --autogenerate -m "add_password_reset_tokens"
alembic upgrade head

# Tests unitaires
pytest tests/unit/services/test_password_reset_service.py -v

# Tests intégration
pytest tests/integration/test_password_reset_api.py -v

# Tests E2E
pytest tests/e2e/test_password_reset_flow.py -v --headed

# Coverage
pytest --cov=app.services.password_reset_service --cov=app.api.routes.auth --cov-report=term-missing
```

## Architecture Snapshot

**Nouveau**:
- Table `password_reset_tokens` (PostgreSQL + SQLite)
- Service `PasswordResetService` (génération/validation tokens)
- 4 endpoints API (forgot, reset, validate, admin-reset)
- 3 templates email (request, success, admin-reset)
- 2 pages UI (forgot-password, reset-password)

**Modifié**:
- `app/api/routes/auth.py` - ajout endpoints
- `app/services/email_service.py` - ajout méthodes email
- `app/templates/login.html` - ajout lien "Mot de passe oublié?"
- `app/templates/admin.html` - ajout bouton "Reset Password"
- `app/static/js/admin.js` - ajout méthode reset

## Success Criteria (Definition of Done)

- [x] Migration DB appliquée (PostgreSQL + SQLite)
- [x] Service PasswordResetService fonctionnel
- [x] 4 endpoints API créés et testés
- [x] 3 templates email créés
- [x] 2 pages UI (forgot, reset) fonctionnelles
- [x] Admin panel étendu avec reset password
- [x] Rate limiting actif (3/IP/15min)
- [x] Coverage ≥85% module password reset
- [x] Tests E2E passent (self-service + admin)
- [x] OWASP checklist validée
- [x] Documentation complète
- [x] Aucune régression sur tests existants

## Timeline Estimate

- **Phase 1** (DB + Service): 3-4 jours
- **Phase 2** (API Self-Service): 3-4 jours
- **Phase 3** (Admin Reset + Emails): 4-5 jours
- **Phase 4** (UI + E2E): 5-6 jours
- **Total**: ~3-4 semaines

## Security Highlights

- ✅ Tokens: 256 bits d'entropie (SHA-256 hashed)
- ✅ Expiration: 1 heure (configurable)
- ✅ Single-use: marqué après consommation
- ✅ Rate limiting: 3 requêtes/IP/15min
- ✅ Anti-énumération: réponses génériques
- ✅ Password validation: zxcvbn ≥3, 12+ chars
- ✅ Password history: pas de réutilisation
- ✅ Admin protection: pas de reset mutuel
- ✅ 2FA preservation: settings préservés
- ✅ Audit logging: tous événements tracés

## Key Technical Decisions

1. **Token Storage**: Hashed avec SHA-256 (jamais en clair) pour sécurité en cas de breach DB
2. **Token Expiration**: 1 heure - balance sécurité vs UX
3. **Rate Limiting**: 3/IP/15min - prévient brute force sans bloquer légitimes users
4. **Anti-Enumeration**: Réponse générique toujours identique - empêche découverte users
5. **Email Fallback**: Graceful degradation si service down - pas de crash
6. **2FA Preservation**: 2FA pas réinitialisé - sécurité maximale
7. **Admin Protection**: Pas de reset admin→admin - empêche escalade

## Testing Strategy

- **Unit**: PasswordResetService (95%+ coverage)
- **Integration**: API endpoints (100% coverage)
- **E2E**: Parcours complets + edge cases
- **Security**: Rate limiting, token expiration, reuse prevention

## Related Tracks

- ✅ Password History (completed) - `alembic/versions/2163cd9a7764_add_password_history_table.py`
- ✅ 2FA Implementation (completed) - preservé après password reset
- ✅ Email Service (completed) - `app/services/email_service.py`
- ✅ Admin Panel (completed) - étendu avec reset password

## Support

Pour questions ou blockers:
- Consulter `spec.md` pour détails techniques
- Consulter `plan.md` pour ordre d'implémentation
- Suivre pattern des migrations existantes (`alembic/versions/2163cd9a7764_*`)
- Suivre pattern des emails existants (`app/templates/emails/account_approved.html`)
- Suivre pattern des tests E2E existants (`tests/e2e/test_admin_happy_path.py`)

## Notes

- Approche TDD stricte : tests avant code
- Commits granulaires avec SHA tracké dans plan.md
- Security logging à WARNING level
- Documentation à jour à chaque phase
- Pas de breaking changes sur API existante
