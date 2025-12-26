# 🔒 Bug Report: Client-Side Only Authentication for Protected Pages

**Severity:** 🟡 Medium
**Security Impact:** Moderate
**Reporter:** Assistant (Claude Code)
**Date:** 2025-12-26
**Versions affected:** v4.28.3 and earlier

---

## Summary

Les pages protégées (`/history`, `/admin`, `/upload`) n'ont **aucune protection d'authentification côté serveur**. L'authentification se fait uniquement via JavaScript côté client, ce qui présente plusieurs vulnérabilités potentielles.

---

## Pages affectées

### 1. `/history` - Page d'historique
- **Route serveur:** `app/api/routes/views.py:39-44`
- **Protection serveur:** ❌ Aucune
- **Protection client:** ✅ JavaScript (`app/static/js/history.js:22-58`)

### 2. `/admin` - Panel d'administration
- **Route serveur:** `app/api/routes/views.py:63-69`
- **Protection serveur:** ❌ Aucune
- **Protection client:** ✅ JavaScript (`app/static/js/admin.js:34-39`)

### 3. `/` (upload) - Page d'upload
- **Route serveur:** `app/api/routes/views.py:23-28`
- **Protection serveur:** ❌ Aucune
- **Protection client:** ✅ JavaScript (`app/static/js/upload.js:24-32`)

### 4. `/profile` - Page de profil utilisateur
- **Route serveur:** `app/api/routes/views.py:89-94`
- **Protection serveur:** ❌ Aucune
- **Protection client:** ❓ À vérifier

---

## Code actuel

### Exemple: Route `/history` (NON PROTÉGÉE)

```python
# app/api/routes/views.py:39-44
@router.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    """
    Page d'historique des analyses
    """
    return templates.TemplateResponse("history.html", {"request": request, "version": __version__})
```

**Problème:** Aucune dépendance `Depends(get_current_user)` → La page HTML est servie à n'importe qui.

### Protection JavaScript (app/static/js/history.js)

```javascript
async checkAuthentication() {
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
        return false;
    }

    // Verify token is still valid
    try {
        const response = await fetch('/api/users/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (!response.ok) {
            localStorage.removeItem('access_token');
            localStorage.removeItem('token_type');
            localStorage.removeItem('current_user');
            window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            return false;
        }

        return true;
    } catch (error) {
        console.error('Auth check error:', error);
        window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
        return false;
    }
}
```

**Protection actuelle:** Redirection côté client si pas de token valide.

---

## Vulnérabilités identifiées

### 1. 🔴 Bypass JavaScript désactivé

**Scénario:**
```bash
# Un attaquant désactive JavaScript dans son navigateur
curl -H "User-Agent: Mozilla/5.0" http://pcaplab.com/history
```

**Résultat:**
- ✅ La page HTML `/history` est servie (template Jinja2)
- ❌ Le JavaScript ne s'exécute pas
- ⚠️ L'attaquant voit la structure de la page (même si vide de données)

**Impact:** Faible (la page est vide sans données), mais révèle la structure de l'interface.

### 2. 🟡 Énumération de l'existence des pages

**Scénario:**
```bash
# Test d'existence de pages protégées
curl -s -o /dev/null -w "%{http_code}" http://pcaplab.com/history  # → 200 OK
curl -s -o /dev/null -w "%{http_code}" http://pcaplab.com/admin   # → 200 OK
curl -s -o /dev/null -w "%{http_code}" http://pcaplab.com/secret  # → 404 Not Found
```

**Impact:** Un attaquant peut découvrir quelles pages existent sans authentification.

### 3. 🟢 Données protégées par l'API (Pas de fuite)

**Bon point:** Les APIs sont bien protégées.

```python
# app/api/routes/progress.py:236-267
@router.get("/history")
async def get_task_history(limit: int = 20, current_user: User = Depends(get_current_user)):
    """
    ✅ Authentification requise
    ✅ Multi-tenant filtering (owner_id)
    """
    if current_user.role == UserRole.ADMIN:
        tasks = await db_service.get_recent_tasks(limit=limit)
    else:
        tasks = await db_service.get_recent_tasks(limit=limit, owner_id=current_user.id)

    return {"tasks": tasks, "count": len(tasks)}
```

**Résultat:**
- ❌ Sans token valide → `401 Unauthorized`
- ✅ Avec token user → Voir seulement ses propres tâches
- ✅ Avec token admin → Voir toutes les tâches

**Impact:** Les données sensibles sont BIEN protégées. Un utilisateur anonyme ne peut PAS voir l'historique d'un autre utilisateur.

### 4. 🟡 Session leakage entre utilisateurs ?

**Question initiale de l'utilisateur:**
> "est-ce que si quelqu'un se log, et une autre personne anonyme clique sur l'historique verra son historique ?"

**Réponse:** ❌ **NON, pas de fuite de session.**

**Explication:**
1. L'authentification utilise **JWT tokens stockés dans localStorage**
2. Le localStorage est **isolé par origine** (same-origin policy)
3. Un utilisateur anonyme dans un autre navigateur/onglet n'a PAS accès au token de l'utilisateur connecté

**Test scenario:**
```
Navigateur A (User connecté):
  - localStorage contient: access_token = "eyJhbGc..."
  - GET /api/history → Renvoie l'historique de User

Navigateur B (Anonyme):
  - localStorage est vide (pas de token)
  - GET /history → Redirigé vers /login par JavaScript
  - GET /api/history → 401 Unauthorized (pas de token)
```

**Conclusion:** ✅ Pas de fuite de données entre utilisateurs.

---

## Scénarios de test

### Test 1: Accès anonyme à /history

```bash
# Terminal
curl -H "Host: pcaplab.com" http://localhost/history
```

**Résultat attendu:**
- ✅ HTTP 200 OK
- ✅ HTML de la page history.html servie
- ⚠️ Contenu vide (JavaScript ne charge pas les données)

**Résultat actuel:** ✅ **CONFORME** - Testé le 2025-12-26
```
HTTP 200
HTML de la page servie, pas de données sensibles dans le template
```

### Test 2: Accès API sans authentification

```bash
curl -H "Host: pcaplab.com" http://localhost/api/history
```

**Résultat attendu:**
- ✅ HTTP 401 Unauthorized
- ✅ {"detail": "Not authenticated"}

**Résultat actuel:** ✅ **CONFORME** - Testé le 2025-12-26
```json
{"detail":"Not authenticated"}
```
L'API est bien protégée et refuse l'accès sans token.

### Test 3: Accès avec token invalide

```bash
curl -H "Host: pcaplab.com" -H "Authorization: Bearer fake_token_123" http://localhost/api/history
```

**Résultat attendu:**
- ✅ HTTP 401 Unauthorized

**Résultat actuel:** ✅ **CONFORME** - Testé le 2025-12-26
```json
{"detail":"Could not validate credentials"}
```
Les faux tokens sont bien rejetés par l'API.

### Test 4: Isolation entre utilisateurs

**Scénario:**
1. User A se connecte dans Chrome → voit ses 5 analyses
2. User B ouvre Firefox (anonyme) → va sur /history
3. User B est redirigé vers /login
4. User B ne voit PAS l'historique de User A

**Résultat:** ✅ Les données sont isolées (localStorage par origine)

---

## Impact réel

### 🟢 Données protégées
- ✅ Les APIs sont bien protégées avec `Depends(get_current_user)`
- ✅ Multi-tenant filtering fonctionnel
- ✅ Pas de fuite de données entre utilisateurs
- ✅ Tokens JWT sécurisés dans localStorage

### 🟡 Pages HTML accessibles
- ⚠️ Les templates HTML sont servis sans authentification
- ⚠️ Un attaquant peut voir la structure de la page (mais pas les données)
- ⚠️ Révèle l'existence de certaines pages (/admin, /history, etc.)

### 🔴 Risques théoriques
- JavaScript désactivé → Pas de redirection vers /login
- Énumération de pages (mais pas de secret révélé)
- Potentiel pour de futurs bugs si des données sensibles sont rendues côté serveur

---

## Recommandations

### Option A: Protection légère côté serveur (Recommandé pour SPA)

Ajouter une vérification minimale côté serveur pour les pages sensibles :

```python
# app/api/routes/views.py
from fastapi import Depends, HTTPException, status
from app.services.auth import get_current_user_optional

@router.get("/history", response_class=HTMLResponse)
async def history(request: Request, user = Depends(get_current_user_optional)):
    """
    Page d'historique des analyses
    Redirection vers /login si pas authentifié
    """
    # Si pas de cookie/session valide, rediriger
    token = request.cookies.get("access_token") or request.headers.get("Authorization")
    if not token:
        return RedirectResponse(url="/login?returnUrl=/history", status_code=303)

    return templates.TemplateResponse("history.html", {"request": request, "version": __version__})
```

**Avantages:**
- ✅ Protection côté serveur
- ✅ Redirection HTTP 303 (pas de JavaScript requis)
- ✅ Maintient l'architecture SPA actuelle

**Inconvénients:**
- ⚠️ Nécessite de stocker le token dans un cookie (actuellement localStorage)
- ⚠️ Changement d'architecture

### Option B: Middleware d'authentification global

Créer un middleware qui vérifie l'authentification pour certaines routes :

```python
# app/middleware/auth.py
PROTECTED_PATHS = ["/history", "/admin", "/profile"]

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if request.url.path in PROTECTED_PATHS:
        # Vérifier Authorization header ou cookie
        token = request.headers.get("Authorization") or request.cookies.get("access_token")
        if not token:
            return RedirectResponse(url=f"/login?returnUrl={request.url.path}")

    return await call_next(request)
```

### Option C: Garder l'architecture actuelle (Status Quo)

**Arguments pour:**
- ✅ Les données sensibles sont déjà bien protégées au niveau API
- ✅ Architecture SPA moderne (protection côté client)
- ✅ Pas de fuite de données réelle
- ✅ Complexité moindre

**Arguments contre:**
- ⚠️ Défense en profondeur manquante
- ⚠️ Révélation de la structure de l'interface
- ⚠️ Pas de protection si JavaScript désactivé

---

## Conclusion

### Risque actuel: 🟡 MOYEN

**Points positifs:**
- ✅ Les APIs sont correctement protégées
- ✅ Pas de fuite de données entre utilisateurs
- ✅ Multi-tenant filtering fonctionnel

**Points à améliorer:**
- ⚠️ Pages HTML servies sans authentification serveur
- ⚠️ Dépendance totale sur JavaScript pour la sécurité
- ⚠️ Manque de défense en profondeur

### Recommandation finale

**Pour une application de production:** Implémenter **Option A** (Protection légère côté serveur) pour :
1. Respecter le principe de défense en profondeur
2. Éviter la révélation de la structure de l'interface
3. Maintenir la compatibilité même si JavaScript est désactivé

**Pour un environnement contrôlé:** **Option C** (Status quo) est acceptable si :
1. L'application est déployée dans un environnement de confiance
2. Les utilisateurs sont authentifiés
3. L'accent est mis sur la protection des données (déjà bien fait)

---

## Références

- OWASP Top 10 - A01:2021 Broken Access Control
- OWASP ASVS v4.0.3 - Section V4.1 (General Access Control Design)
- CWE-306: Missing Authentication for Critical Function

---

**Action requise:** Décision de Conductor sur l'option à implémenter (A, B, ou C).
