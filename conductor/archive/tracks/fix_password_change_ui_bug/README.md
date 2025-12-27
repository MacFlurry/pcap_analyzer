# Track: Fix Password Change UI Bug

## 🎯 Objectif

Corriger le bug où le menu utilisateur (profil + logout) n'apparaît pas après un changement de mot de passe forcé suite à un reset admin.

## 🐛 Symptôme

### ⚠️ Scope Important : Seul le Flux Admin Reset Est Affecté

**Ce bug affecte UNIQUEMENT**:
- ✅ **Admin-initiated password reset** (admin reset user password → user login avec mot de passe temporaire)

**Ce bug N'affecte PAS**:
- ❌ **Self-service password reset** (user clique "Mot de passe oublié" → reçoit lien email)

**Pourquoi cette différence ?**
- **Self-service**: Après reset, redirection vers `/login` → Re-login complet → `current_user` stocké automatiquement
- **Admin reset**: Après changement, redirection vers `/` (user déjà logged in) → `current_user` PAS stocké → BUG

---

**User Story (Admin Reset Flow)**:
> En tant qu'utilisateur ayant reçu un mot de passe temporaire de l'admin,
> Après avoir changé mon mot de passe avec succès,
> Je suis redirigé vers la page d'accueil MAIS le menu utilisateur n'apparaît pas,
> Et je ne peux pas me déconnecter (sauf en allant manuellement sur `/logout`).

**Impact**:
- Sévérité: **Haute** (UX bloquante)
- Fréquence: **100%** des cas de password reset admin
- Flux self-service: **Non affecté** (fonctionne correctement)
- Workaround: Aller sur `/logout` manuellement ou refresh page (F5)

## 🔍 Cause Racine

Le menu utilisateur ne s'affiche que si `localStorage` contient **à la fois**:
1. ✅ `access_token` (présent après login)
2. ❌ `current_user` (**ABSENT** car redirection immédiate lors de `password_must_change=true`)

**Fichier concerné**: `app/templates/change-password.html`
**Ligne**: 213-219 (redirection sans fetch user data)

## ✅ Solution

Après changement de mot de passe réussi:
1. Fetch les données utilisateur à jour via `GET /api/users/me`
2. Stocker dans `localStorage.setItem('current_user', JSON.stringify(user))`
3. Initialiser CSRF protection
4. Rediriger vers `/` (comme avant)

**Pattern**: Identique au flux de login normal (login.html:205-241)

## 📁 Fichiers Modifiés

| Fichier | Type | Description |
|---------|------|-------------|
| `app/templates/change-password.html` | Modification | Fetch user data avant redirection |
| `tests/e2e/test_password_reset_flow.py` | Augmentation | Vérifier menu visible + logout fonctionnel |
| `CHANGELOG.md` | Ajout | Bug fix entry |
| `docs/password-reset.md` | Ajout | Note utilisateur |

## 🚀 Quick Start

### Pour Conductor

```bash
# 1. Lire le plan complet
cat conductor/tracks/fix_password_change_ui_bug/plan.md

# 2. Lire les spécifications techniques
cat conductor/tracks/fix_password_change_ui_bug/spec.md

# 3. Implémenter le fix
# Modifier: app/templates/change-password.html (lignes 213-219)
# Augmenter: tests/e2e/test_password_reset_flow.py

# 4. Tester localement
pytest tests/e2e/test_password_reset_flow.py::test_admin_reset_user_password -v --headed

# 5. Mettre à jour documentation
# CHANGELOG.md + docs/password-reset.md

# 6. Commit
git add .
git commit -m "fix(ui): user menu now visible after forced password change

- Fetch user data from /api/users/me after password update
- Store current_user in localStorage before redirect
- Initialize CSRF protection (consistent with login flow)
- Add E2E tests to verify menu visibility and logout functionality

Fixes: User menu not appearing after admin password reset flow
Impact: High severity UX bug (100% repro rate)
Pattern: Matches login.html flow (lines 205-241)
"
```

### Test Manuel

```bash
# 1. Créer utilisateur test
# Admin panel → Create User → testuser@example.com

# 2. Reset password
# Admin panel → Reset Password (testuser) → Copy temporary password

# 3. Logout admin et login comme testuser
# Username: testuser
# Password: <temporary_password>

# 4. Changement de mot de passe
# Entrer nouveau mot de passe sécurisé → Submit

# 5. VALIDATION
# ✅ Redirection vers / après 2 secondes
# ✅ Menu utilisateur VISIBLE (initiales en haut à droite)
# ✅ Clic sur menu → Dropdown s'ouvre
# ✅ Bouton "Se déconnecter" visible
# ✅ Clic logout → Redirection vers /login
```

## 📊 Métriques de Succès

- [ ] **Code modifié**: `change-password.html` ligne 213-219 → 213-252 (+39 lignes)
- [ ] **Tests E2E passent**: `test_admin_reset_user_password` avec menu assertions
- [ ] **Test manuel validé**: Menu visible + logout fonctionnel
- [ ] **localStorage cohérent**: `access_token`, `token_type`, `current_user` tous présents
- [ ] **Aucune régression**: Tests existants passent (`pytest` + `playwright`)
- [ ] **Documentation à jour**: CHANGELOG.md + password-reset.md modifiés

## 🔒 Sécurité

- ✅ Pas de changement de logique d'authentification
- ✅ CSRF protection initialisée (comme login flow)
- ✅ Token JWT inchangé (pas de re-login forcé)
- ✅ Données utilisateur fetchées depuis BDD (toujours à jour)
- ✅ Graceful error handling (si fetch échoue, redirection continue)

## ⚡ Performance

**Avant**: 1 requête (`PUT /api/users/me`) → ~50ms
**Après**: 2 requêtes (`PUT` + `GET /api/users/me`) → ~80ms
**Impact**: +30ms (négligeable, utilisateur attend déjà 2 sec avant redirection)

## 🎓 Références

- **Plan détaillé**: [plan.md](./plan.md)
- **Spécifications techniques**: [spec.md](./spec.md)
- **Code source**:
  - `app/templates/change-password.html` (lignes 213-219)
  - `app/static/js/common.js` (lignes 455-518 - `initializeUserMenu()`)
  - `app/templates/login.html` (lignes 205-241 - flux de référence)

## 💡 Notes d'Implémentation

1. **Pattern Consistency**: Le fix utilise exactement le même pattern que le login normal (login.html)
2. **Error Handling**: Si `GET /api/users/me` échoue, la redirection continue (graceful degradation)
3. **CSRF Protection**: Initialisée comme dans le flux de login (cohérence)
4. **Backward Compatibility**: Aucun changement backend requis, pas de migration DB
5. **Rollback Plan**: Simple git revert si problème (workaround: refresh page F5)

## 📝 Changelog Entry

```markdown
## [5.1.1] - YYYY-MM-DD

### Bug Fixes
- **UI**: Fixed user menu not appearing after forced password change (admin reset flow)
  - After changing temporary password, user menu and logout button are now properly visible
  - `current_user` data is now stored in localStorage after password change
  - Pattern matches login flow for consistency
```

## 👤 Ownership

**Created**: 2025-12-27
**Assignee**: Conductor (Gemini)
**Reviewer**: Claude Code
**Priority**: Haute (UX Critical)
**Type**: Bug Fix
**Complexity**: Faible (1 fichier core, logique claire)
**Risk**: Très faible (pas de changement backend)

---

**Status**: ⏳ Ready for Implementation
