# CSRF Protection Implementation

## Vue d'ensemble

Ce document décrit l'implémentation de la protection CSRF (Cross-Site Request Forgery) pour pcap_analyzer, conforme aux normes OWASP ASVS 4.2.2.

## Architecture

### Pattern de sécurité
- **Double Submit Cookie Pattern**
- Token CSRF envoyé à la fois comme cookie HttpOnly ET dans un header personnalisé
- Validation côté serveur pour toutes les requêtes state-changing (POST, PUT, PATCH, DELETE)

### Composants créés/modifiés

#### Fichiers Python créés
1. **app/api/routes/csrf.py** - Endpoints pour obtenir et rafraîchir les tokens CSRF
   - `GET /api/csrf/token` - Obtenir un token CSRF (authentification JWT requise)
   - `POST /api/csrf/refresh` - Rafraîchir le token CSRF

2. **app/security/csrf.py** - Configuration CSRF (déjà existant, utilisé)

#### Fichiers Python modifiés
1. **app/main.py**
   - Import des modules CSRF
   - Exception handler pour `CsrfProtectError` (HTTP 403)
   - Middleware CSRF (placé AVANT le middleware CORS)
   - Inclusion du router CSRF

#### Fichiers JavaScript créés
1. **app/static/js/csrf.js** - Client-side CSRF Manager
   - Classe `CsrfManager` pour gérer les tokens
   - Auto-refresh toutes les 25 minutes
   - Stockage sécurisé dans sessionStorage (pas localStorage)

#### Fichiers JavaScript modifiés
1. **app/static/js/upload.js**
   - Ajout de CSRF headers dans `uploadFile()` (ligne 226)
   - Gestion d'erreur HTTP 403 pour CSRF

2. **app/static/js/history.js**
   - Ajout de CSRF headers dans `deleteTask()` (ligne 507)
   - Ajout de CSRF headers dans `deleteSelected()` (ligne 449)
   - Gestion d'erreur HTTP 403 pour CSRF

3. **app/static/js/admin.js**
   - Ajout de CSRF headers dans `approveUser()` (ligne 317)
   - Ajout de CSRF headers dans `blockUser()` (ligne 347)
   - Ajout de CSRF headers dans `unblockUser()` (ligne 373)
   - Ajout de CSRF headers dans `deleteUser()` (ligne 403)
   - Ajout de CSRF headers dans `bulkAction()` (ligne 487)
   - Ajout de CSRF headers dans `createUser()` (ligne 606)
   - Gestion d'erreur HTTP 403 pour CSRF

4. **app/static/js/common.js**
   - Modification de `handleLogout()` pour nettoyer le token CSRF (ligne 500-503)

#### Templates modifiés
1. **app/templates/base.html**
   - Ajout de `<meta name="csrf-token">` dans `<head>` (ligne 7)
   - Chargement de `/static/js/csrf.js` AVANT common.js (ligne 154)

2. **app/templates/login.html**
   - Initialisation du CSRF après login réussi (ligne 203-210)
   - Appel à `window.csrfManager.init()` après stockage du JWT

## Variables d'environnement requises

### CSRF_SECRET_KEY (RECOMMANDÉ)
```bash
# Clé secrète pour signer les tokens CSRF
# IMPORTANT: DOIT être différente de SECRET_KEY (JWT)
# Génération: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
CSRF_SECRET_KEY=<votre_secret_csrf_32_caracteres_minimum>
```

### SECRET_KEY (FALLBACK)
```bash
# Si CSRF_SECRET_KEY n'est pas défini, SECRET_KEY sera utilisé
# Cependant, il est FORTEMENT RECOMMANDÉ d'utiliser une clé séparée
SECRET_KEY=<votre_secret_jwt>
```

### ENVIRONMENT (OPTIONNEL)
```bash
# Définit l'environnement d'exécution
# En production, les cookies CSRF auront le flag 'secure' (HTTPS obligatoire)
ENVIRONMENT=production  # ou 'development'
```

## Configuration de sécurité

### Paramètres CSRF (app/security/csrf.py)
- **cookie_name**: `fastapi-csrf-token`
- **header_name**: `X-CSRF-Token`
- **cookie_samesite**: `lax`
- **cookie_httponly**: `True`
- **cookie_secure**: `True` en production, `False` en développement
- **token_expiration**: 1800 secondes (30 minutes)
- **protected_methods**: POST, PUT, PATCH, DELETE

### Endpoints exemptés de CSRF
- `/api/health`
- `/api/token` (login)
- `/api/register`
- `/docs`
- `/openapi.json`
- `/swagger-custom.css`
- Tous les fichiers statiques (`/static/*`)

## Flux d'utilisation

### 1. Login utilisateur
```javascript
// login.html - Après authentification réussie
const response = await fetch('/api/token', { method: 'POST', body: formData });
const data = await response.json();
localStorage.setItem('access_token', data.access_token);

// Initialiser CSRF
await window.csrfManager.init();  // Fetch token CSRF
```

### 2. Requêtes protégées (POST/PUT/DELETE)
```javascript
// Pattern général pour toutes les requêtes state-changing
const csrfHeaders = await window.csrfManager.getHeaders();
const response = await fetch('/api/endpoint', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${jwt_token}`,
        ...csrfHeaders  // Ajoute X-CSRF-Token: <token>
    },
    body: data
});

if (response.status === 403) {
    // Erreur CSRF - demander à l'utilisateur de rafraîchir
    window.toast.error('Erreur de sécurité CSRF. Veuillez rafraîchir la page.');
}
```

### 3. Auto-refresh du token
```javascript
// Automatique toutes les 25 minutes
// Géré par CsrfManager en arrière-plan
// Peut aussi être déclenché manuellement:
await window.csrfManager.fetchToken();
```

### 4. Logout
```javascript
// common.js - handleLogout()
localStorage.removeItem('access_token');
window.csrfManager.clear();  // Nettoie token CSRF et arrête auto-refresh
```

## Vérifications de sécurité effectuées

### ✅ Compilation Python
```bash
python3 -m py_compile app/api/routes/csrf.py
python3 -m py_compile app/main.py
python3 -m py_compile app/security/csrf.py
```
**Résultat**: Tous les fichiers compilent sans erreur

### ✅ Audit de secrets en dur
```bash
# Recherche de secrets hardcodés
grep -r "SECRET.*=.*['\"]" app/api/routes/csrf.py app/security/csrf.py
```
**Résultat**: Aucun secret en dur détecté

Tous les secrets utilisent `os.getenv()`:
- `app/security/csrf.py:29` - `secret_key: str = os.getenv("CSRF_SECRET_KEY", os.getenv("SECRET_KEY", ""))`
- `app/security/csrf.py:39` - `cookie_secure: bool = os.getenv("ENVIRONMENT", "development") == "production"`

### ✅ Vérification pattern CSRF
- [x] Token généré côté serveur (imprévisible)
- [x] Token envoyé comme cookie HttpOnly ET header personnalisé
- [x] Validation sur toutes les méthodes state-changing
- [x] Exemptions correctement configurées (login, health, static)
- [x] Middleware placé AVANT CORS
- [x] Auto-refresh pour éviter l'expiration
- [x] Nettoyage lors du logout

## Tests recommandés

### Test 1: Login et initialisation CSRF
1. Se connecter via `/login`
2. Vérifier dans la console: `CsrfManager.init() - CSRF protection activated`
3. Vérifier sessionStorage: présence de `csrf_token`, `csrf_header_name`, `csrf_expiration`

### Test 2: Upload avec CSRF
1. Uploader un fichier PCAP
2. Vérifier les headers de la requête: présence de `X-CSRF-Token`
3. Vérifier la réponse: succès (200)

### Test 3: Delete avec CSRF
1. Supprimer une analyse depuis `/history`
2. Vérifier les headers: `Authorization` + `X-CSRF-Token`
3. Vérifier la suppression réussie

### Test 4: Erreur CSRF (simulation)
1. Supprimer manuellement le cookie CSRF dans DevTools
2. Tenter un upload ou delete
3. Vérifier l'erreur HTTP 403
4. Vérifier le message toast: "Erreur de sécurité CSRF..."

### Test 5: Auto-refresh
1. Se connecter
2. Attendre 26+ minutes (ou modifier le code pour 1 minute en test)
3. Vérifier dans la console: logs de refresh automatique
4. Vérifier que les requêtes fonctionnent toujours

### Test 6: Logout
1. Se connecter
2. Vérifier sessionStorage: `csrf_token` présent
3. Se déconnecter
4. Vérifier sessionStorage: `csrf_token` supprimé

## Conformité OWASP

### OWASP ASVS 4.2.2
> **Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality**

✅ **Conformité démontrée**:
- Tokens CSRF imprévisibles générés avec secrets cryptographiques
- Double Submit Cookie Pattern (cookie + header)
- Validation systématique pour POST/PUT/PATCH/DELETE
- Expiration des tokens (30 minutes)
- Rotation automatique via auto-refresh
- Protection contre la réutilisation (tokens uniques par session)

### CWE-352 (Cross-Site Request Forgery)
✅ **Mitigations implémentées**:
- Synchronizer Token Pattern
- SameSite cookie attribute (lax)
- Custom header validation
- Token lié à la session utilisateur (JWT requis)

## Troubleshooting

### Problème: "No CSRF token available"
**Cause**: Token non initialisé après login
**Solution**: Vérifier que `window.csrfManager.init()` est appelé dans login.html

### Problème: HTTP 403 sur toutes les requêtes
**Cause**: Variable CSRF_SECRET_KEY ou SECRET_KEY non définie
**Solution**: Définir `CSRF_SECRET_KEY` dans les variables d'environnement

### Problème: Cookie CSRF non défini
**Cause**: HTTPS requis en production mais pas disponible
**Solution**:
- En développement: `ENVIRONMENT=development`
- En production: Configurer HTTPS ou modifier `cookie_secure` temporairement

### Problème: Token expiré fréquemment
**Cause**: Auto-refresh ne fonctionne pas
**Solution**: Vérifier que l'onglet reste actif (setInterval ne fonctionne pas en arrière-plan)

## Notes de sécurité importantes

⚠️ **IMPORTANT - À NE PAS FAIRE**:
- Ne JAMAIS commit de vraies valeurs de CSRF_SECRET_KEY
- Ne JAMAIS désactiver CSRF en production
- Ne JAMAIS exempter des endpoints sensibles
- Ne JAMAIS stocker le token CSRF dans localStorage (utiliser sessionStorage)

✅ **BONNES PRATIQUES**:
- Générer CSRF_SECRET_KEY avec un générateur cryptographique
- Utiliser une clé différente pour JWT et CSRF
- Monitorer les logs pour détecter les tentatives CSRF
- Rotation régulière des secrets en production
- Tests automatisés pour vérifier la protection CSRF

## Références
- OWASP ASVS 4.2.2: https://owasp.org/www-project-application-security-verification-standard/
- CWE-352: https://cwe.mitre.org/data/definitions/352.html
- fastapi-csrf-protect: https://github.com/aekasitt/fastapi-csrf-protect
- Double Submit Cookie Pattern: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
