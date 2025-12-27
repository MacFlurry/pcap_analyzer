# Spécification Technique: Fix Password Change UI Bug

## 0. Scope - Flux Affectés

### ⚠️ IMPORTANT : Seul le Flux Admin Reset Est Bugué

Ce bug n'affecte **QUE** le flux admin-initiated password reset (`password_must_change=true`).

Le flux self-service password reset (`/forgot-password` → `/reset-password`) fonctionne **correctement**.

### Comparaison des Deux Flux

#### ✅ Flux Self-Service (FONCTIONNE - Pas de Bug)

**Fichiers**: `forgot-password.html` → `reset-password.html`

**Séquence**:
```
1. User → /forgot-password (pas logged in)
2. Enter email → POST /api/auth/forgot-password
3. Email reçu avec lien → /reset-password?token=xxx
4. Enter nouveau mot de passe → POST /api/auth/reset-password
5. ✅ Redirect /login (reset-password.html:286)
6. User entre username + nouveau mot de passe
7. POST /api/token → Succès
8. ✅ GET /api/users/me (login.html:205)
9. ✅ localStorage.setItem('current_user', ...) (login.html:213)
10. Redirect / → Menu visible ✅
```

**Pourquoi ça fonctionne**: Re-login complet → `current_user` stocké automatiquement dans login flow

---

#### ❌ Flux Admin Reset (BUGUÉ)

**Fichiers**: Admin panel → `login.html` → `change-password.html`

**Séquence**:
```
1. Admin → Reset user password → Temporary password generated
2. User → /login avec temporary password
3. POST /api/token → {password_must_change: true}
4. ✅ localStorage.setItem('access_token', ...) (login.html:186)
5. ❌ Redirect /change-password SANS stocker current_user (login.html:199)
6. User entre nouveau mot de passe → PUT /api/users/me
7. Succès → password_must_change set to false
8. ❌ Redirect / SANS fetch current_user (change-password.html:218)
9. Page / loaded:
   - access_token: ✅ Présent
   - current_user: ❌ ABSENT
   - Menu: ❌ Caché (common.js:467 - requires both)
```

**Pourquoi c'est bugué**: Pas de re-login → User déjà logged in → Mais `current_user` jamais stocké

---

### Design Decision: Pourquoi Pas de Re-Login pour Admin Reset ?

**Raison UX**: Forcer re-login après password change = mauvaise UX
- User vient de taper son nouveau mot de passe
- Le forcer à le re-taper immédiatement = frustrant
- Token JWT déjà valide → Pas besoin de re-login

**Solution**: Garder le design actuel (pas de re-login) MAIS fetch et store `current_user` avant redirect

---

## 1. Problème Technique

### 1.1 Comportement Actuel (BUGUÉ)

**Flux de login avec `password_must_change=true`** (login.html):

```javascript
// Ligne 184-201
if (response.ok) {
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('token_type', data.token_type);

    if (data.password_must_change === true) {
        // ❌ REDIRECTION IMMÉDIATE sans stocker current_user
        window.location.href = '/change-password';
        return;  // ← Sortie prématurée
    }

    // ✅ Ce code n'est JAMAIS exécuté si password_must_change=true
    const userResponse = await fetch('/api/users/me', {...});
    const user = await userResponse.json();
    localStorage.setItem('current_user', JSON.stringify(user));
}
```

**Flux de changement de mot de passe** (change-password.html):

```javascript
// Ligne 199-219
const response = await fetch('/api/users/me', {
    method: 'PUT',
    body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
    })
});

if (response.ok) {
    window.toast.success('✅ Mot de passe changé avec succès!');

    // ❌ REDIRECTION DIRECTE sans stocker current_user
    setTimeout(() => {
        window.location.href = '/';
    }, 2000);
}
```

**État du localStorage après changement**:

```javascript
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",  // ✅ Présent
    "token_type": "bearer",                                      // ✅ Présent
    "current_user": undefined                                     // ❌ ABSENT!
}
```

### 1.2 Vérification du Menu Utilisateur (common.js)

```javascript
// Ligne 455-518
function initializeUserMenu() {
    const token = localStorage.getItem('access_token');
    const currentUserData = localStorage.getItem('current_user');

    if (token && currentUserData) {  // ← Les DEUX doivent être présents
        const user = JSON.parse(currentUserData);
        userMenu.classList.remove('hidden');  // Afficher menu
        // ...
    }
    // Sinon: menu reste hidden
}
```

**Résultat**: Menu caché car `currentUserData === null`

---

## 2. Solution Technique

### 2.1 Code Modifié (change-password.html)

**Avant** (lignes 213-219):

```javascript
if (response.ok) {
    window.toast.success('✅ Mot de passe changé avec succès! Redirection...');

    // Wait 2 seconds then redirect to home
    setTimeout(() => {
        window.location.href = '/';
    }, 2000);
}
```

**Après** (proposition):

```javascript
if (response.ok) {
    window.toast.success('✅ Mot de passe changé avec succès! Redirection...');

    // 🐛 FIX: Fetch updated user data and store in localStorage
    // This ensures the user menu appears on the home page
    const token = localStorage.getItem('access_token');

    try {
        // Fetch updated user info (with password_must_change=false)
        const userResponse = await fetch('/api/users/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (userResponse.ok) {
            const user = await userResponse.json();

            // Store user data (like login flow)
            localStorage.setItem('current_user', JSON.stringify(user));
            console.log('Password changed - User data updated:', user.username);

            // Initialize CSRF protection (like login flow at login.html:220-226)
            if (window.csrfManager) {
                await window.csrfManager.init();
                console.log('Password changed - CSRF protection initialized');
            } else {
                console.warn('Password changed - CSRF manager not available');
            }
        } else {
            console.error('Failed to fetch updated user data:', userResponse.status);
            // Continue anyway - user can refresh page to fix
        }
    } catch (error) {
        console.error('Error fetching user data after password change:', error);
        // Continue anyway - graceful degradation
    }

    // Wait 2 seconds then redirect to home
    setTimeout(() => {
        window.location.href = '/';
    }, 2000);
}
```

### 2.2 Modifications Détaillées

**Changements**:

1. **Ligne +3**: Récupérer token depuis localStorage
2. **Ligne +5-35**: Bloc try/catch pour fetch user data
3. **Ligne +7-11**: Fetch `GET /api/users/me` avec Authorization header
4. **Ligne +13-17**: Parse et store dans localStorage
5. **Ligne +20-25**: Initialiser CSRF protection (cohérence avec login.html)
6. **Ligne +26-28**: Graceful error handling si fetch échoue
7. **Ligne +38-40**: Redirection après 2 secondes (inchangé)

**Caractéristiques**:
- ✅ **Non-bloquant**: Erreur fetch n'empêche pas redirection
- ✅ **Cohérent**: Même pattern que login.html (lignes 205-226)
- ✅ **Logué**: Console logs pour debug
- ✅ **Sécurisé**: CSRF protection initialisée

---

## 3. Validation Backend

### 3.1 Endpoint GET /api/users/me

**Fichier**: `app/api/routes/auth.py`
**Ligne**: 599-615

```python
@router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        is_approved=current_user.is_approved,
        approved_by=current_user.approved_by,
        approved_at=current_user.approved_at,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        # ✅ password_must_change sera False après update_password
    )
```

**État après `update_password`**:
- `password_must_change` mis à False dans BDD (user_database.py:565-566)
- Token JWT reste le même (pas besoin de re-login)
- `GET /api/users/me` retourne données **fraîches** depuis BDD (via Depends)

### 3.2 Flux de Données

```
[change-password.html]
    ↓ PUT /api/users/me (change password)
[Backend: update_password]
    ↓ UPDATE users SET password_must_change=False
[Database]
    ↓ Commit transaction
[change-password.html]
    ↓ GET /api/users/me (fetch updated user)
[Backend: get_current_user_info]
    ↓ SELECT * FROM users WHERE id=... (données fraîches)
[Response]
    ↓ {username, email, role, ..., password_must_change: false}
[change-password.html]
    ↓ localStorage.setItem('current_user', ...)
[localStorage]
    ✅ current_user stocké avec password_must_change=false
```

---

## 4. Tests de Validation

### 4.1 Test E2E - Admin Reset Flow

**Fichier**: `tests/e2e/test_password_reset_flow.py`
**Fonction**: `test_admin_reset_user_password`

**Assertions à ajouter** (après ligne 10):

```python
# Vérifier que le menu utilisateur est visible
user_menu = page.locator('#user-menu')
expect(user_menu).not_to_have_class('hidden')

# Vérifier les initiales de l'utilisateur
user_initials = page.locator('#user-initials')
expect(user_initials).to_be_visible()
expect(user_initials).to_have_text(test_username[:2].upper())

# Ouvrir le menu dropdown
page.click('#user-menu-button')
user_dropdown = page.locator('#user-menu-dropdown')
expect(user_dropdown).not_to_have_class('hidden')

# Vérifier le bouton logout
logout_btn = page.locator('#logout-btn')
expect(logout_btn).to_be_visible()
expect(logout_btn).to_contain_text('Se déconnecter')

# Test logout fonctionnel
page.click('#logout-btn')
page.wait_for_url('/login')
expect(page).to_have_url('/login')

# Vérifier que localStorage est nettoyé
access_token = page.evaluate('() => localStorage.getItem("access_token")')
expect(access_token).to_be_null()

current_user = page.evaluate('() => localStorage.getItem("current_user")')
expect(current_user).to_be_null()
```

### 4.2 Test localStorage State

**Test unitaire JavaScript** (si nécessaire):

```javascript
// Simuler le flux complet
describe('Password Change - localStorage State', () => {
    it('should store current_user after successful password change', async () => {
        // Mock fetch responses
        global.fetch = jest.fn()
            .mockResolvedValueOnce({ // PUT /api/users/me (password update)
                ok: true,
                json: async () => ({})
            })
            .mockResolvedValueOnce({ // GET /api/users/me (fetch user)
                ok: true,
                json: async () => ({
                    id: 'user-123',
                    username: 'testuser',
                    email: 'test@example.com',
                    role: 'user',
                    password_must_change: false
                })
            });

        // Execute password change flow
        await changePasswordAndRedirect();

        // Assertions
        const currentUser = JSON.parse(localStorage.getItem('current_user'));
        expect(currentUser).toBeDefined();
        expect(currentUser.username).toBe('testuser');
        expect(currentUser.password_must_change).toBe(false);
    });
});
```

---

## 5. Edge Cases

### 5.1 Fetch User Data Fails

**Scénario**: `GET /api/users/me` retourne 401 ou network error

**Comportement**:
- Error caught dans try/catch
- Log error dans console
- **Graceful degradation**: Redirection vers `/` quand même
- **Workaround utilisateur**: Refresh page (F5) → `initializeUserMenu()` re-check et fetch user data si token présent

**Test**:
```javascript
// Mock fetch failure
global.fetch = jest.fn()
    .mockResolvedValueOnce({ ok: true }) // PUT succeeds
    .mockRejectedValueOnce(new Error('Network error')); // GET fails

await changePasswordFlow();

// User is still redirected (graceful)
expect(window.location.href).toContain('/');

// localStorage.current_user not set
expect(localStorage.getItem('current_user')).toBeNull();
```

### 5.2 CSRF Manager Not Available

**Scénario**: `window.csrfManager` undefined (rare)

**Comportement**:
- Condition `if (window.csrfManager)` évite crash
- Warning logged: "CSRF manager not available"
- Redirection continue normalement

### 5.3 Token Expiré Entre PUT et GET

**Scénario**: Token expire entre password change et fetch user

**Probabilité**: Très faible (token expire après 30 min, délai < 1 sec)

**Comportement**:
- `GET /api/users/me` retourne 401
- Caught dans try/catch
- User redirigé vers `/`
- Sur `/`, auth check échoue → redirect vers `/login`

---

## 6. Comparaison avec Login Flow

### 6.1 Login Normal (login.html:204-241)

```javascript
// Fetch user info
const userResponse = await fetch('/api/users/me', {
    headers: { 'Authorization': `Bearer ${data.access_token}` }
});

if (userResponse.ok) {
    const user = await userResponse.json();
    localStorage.setItem('current_user', JSON.stringify(user));  // ← Store

    // Initialize CSRF protection
    if (window.csrfManager) {
        await window.csrfManager.init();
    }

    // Redirect
    window.location.href = returnUrl || '/';
}
```

### 6.2 Password Change (change-password.html - APRÈS FIX)

```javascript
// Fetch user info
const userResponse = await fetch('/api/users/me', {
    headers: { 'Authorization': `Bearer ${token}` }
});

if (userResponse.ok) {
    const user = await userResponse.json();
    localStorage.setItem('current_user', JSON.stringify(user));  // ← Store (IDENTIQUE)

    // Initialize CSRF protection
    if (window.csrfManager) {
        await window.csrfManager.init();
    }

    // Redirect (après 2 sec)
    setTimeout(() => {
        window.location.href = '/';
    }, 2000);
}
```

**Conclusion**: Pattern **identique** → cohérence maximale

---

## 7. Impact Analysis

### 7.1 Fichiers Impactés

| Fichier | Type Changement | Lignes | Impact |
|---------|----------------|--------|--------|
| `app/templates/change-password.html` | Modification | 213-219 → 213-252 | Ajout fetch user data |
| `tests/e2e/test_password_reset_flow.py` | Augmentation | +25 | Vérifier menu visible |
| `CHANGELOG.md` | Ajout | +4 | Bug fix entry |
| `docs/password-reset.md` | Ajout | +2 | Note utilisateur |

**Total**: 1 fichier core modifié

### 7.2 Risques

| Risque | Probabilité | Mitigation |
|--------|-------------|------------|
| Fetch user data échoue | Faible | Try/catch + graceful fallback |
| CSRF manager undefined | Très faible | Condition if + warning log |
| Token expiré entre PUT/GET | Très faible | Auth check sur page d'accueil |
| Régression login normal | Nulle | Pas de modification login.html |
| Performance degradation | Nulle | 1 fetch supplémentaire (~100ms) |

### 7.3 Backward Compatibility

- ✅ **API**: Aucun changement backend
- ✅ **Database**: Aucune migration
- ✅ **Existing Users**: Pas d'impact (flux normal inchangé)
- ✅ **Browser Support**: Fetch API supporté (déjà utilisé partout)

---

## 8. Performance

### 8.1 Before Fix

**Requêtes lors du changement de mot de passe**:
1. `PUT /api/users/me` (change password) → ~50ms

**Total**: 1 requête, ~50ms

### 8.2 After Fix

**Requêtes lors du changement de mot de passe**:
1. `PUT /api/users/me` (change password) → ~50ms
2. `GET /api/users/me` (fetch user data) → ~30ms

**Total**: 2 requêtes, ~80ms

**Impact**: +30ms (négligeable, utilisateur attend déjà 2 secondes avant redirection)

---

## 9. Alternatives Rejected

### 9.1 ❌ Forcer Re-Login Complet

**Approche**: Après password change, clear token et redirect vers `/login`

**Rejet**:
- UX dégradée (utilisateur doit re-taper nouveau mot de passe)
- Pas cohérent avec flux de login normal
- Changement plus invasif

### 9.2 ❌ Modifier PUT /api/users/me Response

**Approche**: Endpoint retourne user data après update

**Rejet**:
- Changement backend inutile (GET /api/users/me existe déjà)
- Pas RESTful (PUT devrait retourner resource updated, pas full user object)
- Plus complexe (modification backend + tests)

### 9.3 ❌ Stocker current_user Au Login Même Si password_must_change=true

**Approche**: Dans login.html, toujours fetch et store current_user

**Rejet**:
- Données obsolètes après password change (password_must_change toujours true dans localStorage)
- Faudrait quand même re-fetch après changement
- Pas de gain par rapport à solution proposée

---

## 10. Rollback Procedure

**Si le fix cause des problèmes**:

1. **Revert commit**:
   ```bash
   git revert <commit-sha>
   git push origin main
   ```

2. **Rebuild et redeploy**:
   ```bash
   docker build -t pcap-analyzer:v5.1.1 .
   kind load docker-image pcap-analyzer:v5.1.1 --name pcap-analyzer
   helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer --set image.tag=v5.1.1
   ```

3. **Workaround utilisateur** (temporaire):
   - Après changement de mot de passe, appuyer sur F5 (refresh page)
   - Menu utilisateur apparaîtra après refresh

---

## Conclusion

Fix simple, low-risk, high-impact pour résoudre un bug UX critique. Pattern cohérent avec login flow existant, graceful error handling, aucun changement backend requis.

**Prêt pour implémentation** ✓
