# Plan: Fix User Menu Not Showing After Password Change

**Objectif**: Corriger le bug où le menu utilisateur (profil + logout) n'apparaît pas après un changement de mot de passe forcé

**Type**: Bug Fix (UX Critical)
**Priorité**: Haute (blocage utilisateur)
**Statut**: Proposition initiale

---

## Scope et Périmètre

### ⚠️ IMPORTANT : Ce Bug N'Affecte QUE le Flux Admin Reset

**Flux affecté** (🐛 BUGUÉ):
- **Admin-initiated password reset** → User login avec mot de passe temporaire → `/change-password` → Menu caché

**Flux NON affecté** (✅ FONCTIONNE):
- **Self-service password reset** → User clique lien email → `/reset-password?token=xxx` → Redirection `/login` → Re-login → Menu visible

**Raison de la différence**:

| Aspect | Self-Service | Admin Reset |
|--------|-------------|-------------|
| Page | `/reset-password?token=xxx` | `/change-password` |
| User logged in ? | ❌ Non | ✅ Oui (token présent) |
| Après succès | Redirect `/login` | Redirect `/` |
| Re-login requis ? | ✅ Oui | ❌ Non |
| `current_user` stocké ? | ✅ Lors du login | ❌ Non (BUG) |

**Conclusion**: Le self-service fonctionne car il force un re-login qui stocke automatiquement `current_user`. L'admin reset ne force pas de re-login (meilleure UX) mais oublie de stocker `current_user`.

---

## Contexte

### Problème Reporté

Lorsqu'un administrateur réinitialise le mot de passe d'un utilisateur:

1. ✅ L'utilisateur reçoit un mot de passe temporaire
2. ✅ Il se connecte et est redirigé vers `/change-password`
3. ✅ Il change son mot de passe avec succès
4. ✅ Il est redirigé vers la page d'accueil `/`
5. ❌ **BUG**: Le menu utilisateur n'apparaît pas (pas d'icône, pas de logout visible)
6. ❌ L'utilisateur doit aller manuellement sur `/logout` pour se déconnecter

### Cause Racine

Le menu utilisateur (défini dans `base.html` ligne 92) ne s'affiche que si **DEUX** conditions sont remplies (common.js:467):

```javascript
const token = localStorage.getItem('access_token');
const currentUserData = localStorage.getItem('current_user');

if (token && currentUserData) {  // Les DEUX sont requis!
    // Afficher le menu...
}
```

**Flux actuel (BUGUÉ)** :

1. **Login avec `password_must_change=true`** (login.html:190-201):
   - Token stocké: ✅ `localStorage.setItem('access_token', ...)`
   - `current_user` stocké: ❌ **NON** (redirection immédiate ligne 199)

2. **Changement de mot de passe** (change-password.html:199-219):
   - Appel `PUT /api/users/me` avec token existant
   - BDD mise à jour: `password_must_change = false`
   - Redirection vers `/`
   - `current_user` stocké: ❌ **NON**

3. **Page d'accueil** :
   - `token`: ✅ Présent
   - `current_user`: ❌ **ABSENT**
   - Menu utilisateur: ❌ **CACHÉ** (classe `hidden`)

### Impact

- **Sévérité**: Haute (UX bloquante)
- **Fréquence**: 100% des cas de password reset admin
- **Workaround**: Aller sur `/logout` manuellement (non intuitif)
- **Utilisateurs affectés**: Tous les utilisateurs avec mot de passe temporaire

---

## Solution Proposée

### Option Retenue: Fetch et Store User Data After Password Change

Après un changement de mot de passe réussi dans `change-password.html`, avant la redirection:

1. Fetch les données utilisateur à jour via `GET /api/users/me`
2. Stocker dans `localStorage.setItem('current_user', JSON.stringify(user))`
3. Initialiser CSRF protection (comme dans login.html)
4. Ensuite rediriger vers `/`

**Avantages**:
- ✅ Minimal changes (un seul fichier modifié)
- ✅ Pas de régression sur flux existants
- ✅ Cohérent avec le flux de login normal
- ✅ Données utilisateur à jour (avec `password_must_change=false`)

**Alternatives considérées**:
- ❌ **Forcer re-login complet**: UX dégradée (utilisateur doit re-taper mot de passe)
- ❌ **Stocker current_user même si password_must_change=true**: Données obsolètes après changement
- ❌ **Modifier endpoint PUT /api/users/me**: Changement backend inutile

---

## Phase 1: Correction du Bug

- [x] **Task 1.1**: Modifier change-password.html `b54cfb3`

**Fichier**: `app/templates/change-password.html`
**Lignes**: 213-219 (section après `response.ok`)

**Changement**:

```javascript
if (response.ok) {
    window.toast.success('✅ Mot de passe changé avec succès! Redirection...');

    // 🐛 FIX: Fetch updated user data and store in localStorage
    // This ensures the user menu appears on the home page
    const token = localStorage.getItem('access_token');
    try {
        const userResponse = await fetch('/api/users/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (userResponse.ok) {
            const user = await userResponse.json();
            localStorage.setItem('current_user', JSON.stringify(user));
            console.log('Password changed - User data updated:', user.username);

            // Initialize CSRF protection (like in login flow)
            if (window.csrfManager) {
                await window.csrfManager.init();
                console.log('Password changed - CSRF protection initialized');
            }
        } else {
            console.error('Failed to fetch updated user data:', userResponse.status);
            // Continue anyway - user can refresh page
        }
    } catch (error) {
        console.error('Error fetching user data:', error);
        // Continue anyway - user can refresh page
    }

    // Wait 2 seconds then redirect to home
    setTimeout(() => {
        window.location.href = '/';
    }, 2000);
}
```

**Explication**:
- Fetch `/api/users/me` après changement de mot de passe
- Store `current_user` dans localStorage (comme login.html:213)
- Initialiser CSRF protection (comme login.html:220-226)
- Graceful fallback si fetch échoue (user peut refresh)
- Même délai de 2 secondes avant redirection

**SHA Commit**: `[ ]` (à remplir après commit)

---

## Phase 2: Tests de Validation

### Tâche 2.1: Test E2E - Admin Reset Flow Complet
[x] `b54cfb3`

### Tâche 2.2: Test E2E - Self-Service Flow Non-Régression
[x] `b54cfb3`

---

### Tâche 2.3: Test Manuel - Scénario Admin Reset (BUGUÉ)

**Objectif**: Valider que le bug est corrigé pour le flux admin reset

**Checklist de validation manuelle**:

- [ ] **Prérequis**: Admin créé, user normal créé
- [ ] Admin reset user password (send by email = false)
- [ ] Copier mot de passe temporaire affiché
- [ ] Logout admin
- [ ] Login user avec mot de passe temporaire
- [ ] Vérifier redirection vers `/change-password`
- [ ] Entrer nouveau mot de passe sécurisé
- [ ] Soumettre formulaire
- [ ] **VALIDATION**: Vérifier toast "Mot de passe changé avec succès"
- [ ] **VALIDATION**: Attendre 2 secondes
- [ ] **VALIDATION**: Redirection vers `/` (page d'accueil)
- [ ] **VALIDATION**: Menu utilisateur **VISIBLE** (initiales en haut à droite) ✅
- [ ] **VALIDATION**: Cliquer sur menu → Dropdown s'ouvre ✅
- [ ] **VALIDATION**: Username et role affichés ✅
- [ ] **VALIDATION**: Bouton "Se déconnecter" visible ✅
- [ ] Cliquer "Se déconnecter"
- [ ] **VALIDATION**: Redirection vers `/login` ✅

**Résultat attendu**: Toutes les validations ✅ (menu visible, logout fonctionne)

---

### Tâche 2.4: Test Manuel - Scénario Self-Service (Non-Régression)

**Objectif**: Vérifier que le flux self-service n'est PAS régressé

**Checklist de validation manuelle**:

- [ ] **Prérequis**: User normal créé et approuvé
- [ ] Aller sur `/login`
- [ ] Cliquer "Mot de passe oublié ?"
- [ ] Entrer email de l'utilisateur
- [ ] Soumettre → Vérifier message générique de succès
- [ ] Aller dans la base de données pour récupérer le token de reset
  ```bash
  # Si PostgreSQL
  kubectl exec -n pcap-analyzer pcap-analyzer-postgresql-0 -- psql -U pcap -d pcap_analyzer -c \
    "SELECT token_hash, expires_at FROM password_reset_tokens WHERE used_at IS NULL ORDER BY created_at DESC LIMIT 1;"
  ```
- [ ] Construire URL: `/reset-password?token=<plaintext_token>`
  - **Note**: Le token en DB est haché, il faut le plaintext token (normalement dans email)
  - **Workaround test**: Regarder les logs backend pour voir le token plaintext
- [ ] Aller sur `/reset-password?token=xxx`
- [ ] Vérifier que l'email masqué s'affiche
- [ ] Entrer nouveau mot de passe sécurisé (force ≥ 3)
- [ ] Soumettre formulaire
- [ ] **VALIDATION**: Toast "Mot de passe réinitialisé !" ✅
- [ ] **VALIDATION**: Redirection vers `/login` (PAS `/`) ✅
- [ ] Login avec username + nouveau mot de passe
- [ ] **VALIDATION**: Login réussi ✅
- [ ] **VALIDATION**: Redirection vers `/` ✅
- [ ] **VALIDATION**: Menu utilisateur **VISIBLE** ✅
- [ ] **VALIDATION**: Logout fonctionnel ✅

**Résultat attendu**: Toutes les validations ✅ (self-service fonctionne comme avant)

---

## Phase 3: Documentation et Changelog

### Tâche 3.1: Mettre à jour CHANGELOG.md
[x] `40e2b1d`

### Tâche 3.2: Mettre à jour password-reset.md
[x] `40e2b1d`

---

## Critères de Succès

### Flux Admin Reset (Corrigé)

- [ ] **Code modifié**: `change-password.html` mis à jour avec fetch user data
- [ ] **Test E2E admin reset**: `test_admin_reset_user_password` passe avec assertions menu visible
- [ ] **Test manuel admin reset**: Menu utilisateur visible après password change forcé
- [ ] **Logout fonctionnel**: Bouton visible et redirection vers `/login` OK
- [ ] **localStorage cohérent**: `access_token`, `token_type`, et `current_user` tous présents

### Flux Self-Service (Non-Régression)

- [ ] **Test E2E self-service**: `test_complete_password_reset_flow` passe (pas de régression)
- [ ] **Test manuel self-service**: Menu visible après reset via email + re-login
- [ ] **Redirection correcte**: Toujours vers `/login` après reset (pas vers `/`)

### Général

- [ ] **Documentation à jour**: CHANGELOG.md et password-reset.md modifiés
- [ ] **Aucune régression**: Tests existants passent (pytest + playwright)
- [ ] **Les DEUX flux fonctionnent**: Admin reset ET self-service ✅

---

## Résumé des Changements

| Fichier | Type | Lignes | Description |
|---------|------|--------|-------------|
| `app/templates/change-password.html` | Modification | 213-219 | Fetch user data et store dans localStorage après password change |
| `tests/e2e/test_password_reset_flow.py` | Augmentation | +20 | Vérifier menu utilisateur visible et logout fonctionnel |
| `CHANGELOG.md` | Ajout | +4 | Bug fix entry |
| `docs/password-reset.md` | Ajout | +2 | Note sur menu utilisateur après changement |

**Total**: 1 fichier core modifié, tests augmentés, documentation mise à jour

---

## Notes d'Implémentation

1. **Backward Compatibility**: ✅ Aucun breaking change
2. **CSRF Protection**: ✅ Initialisé comme dans login flow
3. **Error Handling**: ✅ Graceful fallback si fetch échoue
4. **Performance**: ✅ Un seul fetch supplémentaire (négligeable)
5. **Security**: ✅ Pas de changement de logique d'auth
6. **UX**: ✅ Amélioration significative (menu visible)

---

## Rollback Plan

Si le fix cause des problèmes:

1. **Revert commit** de `change-password.html`
2. **Workaround utilisateur**: Refresh page (F5) après changement de mot de passe
3. **Alternative**: Forcer re-login complet (rediriger vers `/login` après password change)

---

## Track Metadata

**Track ID**: `fix_password_change_ui_bug`
**Created**: 2025-12-27
**Estimated Duration**: 1 heure (fix simple)
**Complexity**: Faible (1 fichier, logique claire)
**Risk**: Très faible (pas de changement backend)

---

**Prêt pour implémentation** ✓
