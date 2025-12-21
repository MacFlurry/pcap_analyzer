# CSRF Protection - Deployment Checklist

## Pré-déploiement

### 1. Variables d'environnement

**OBLIGATOIRE** - Créer ou mettre à jour le fichier `.env`:

```bash
# Copier le fichier d'exemple
cp .env.example .env

# Générer les secrets CSRF et JWT
python3 -c "import secrets; print('CSRF_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env

# Définir l'environnement
echo "ENVIRONMENT=production" >> .env

# Sécuriser le fichier
chmod 600 .env
```

**IMPORTANT**:
- ✅ CSRF_SECRET_KEY et SECRET_KEY doivent être DIFFÉRENTS
- ✅ Minimum 32 caractères pour chaque secret
- ❌ NE JAMAIS commit .env dans Git

### 2. Vérification des fichiers

Vérifier que tous les fichiers sont présents:

```bash
# Fichiers créés (nouveaux)
ls -l app/api/routes/csrf.py
ls -l app/static/js/csrf.js
ls -l CSRF_IMPLEMENTATION.md

# Fichiers modifiés
ls -l app/main.py
ls -l app/templates/base.html
ls -l app/templates/login.html
ls -l app/static/js/upload.js
ls -l app/static/js/history.js
ls -l app/static/js/admin.js
ls -l app/static/js/common.js
```

### 3. Test de compilation

```bash
# Vérifier que le code Python compile
python3 -m py_compile app/api/routes/csrf.py
python3 -m py_compile app/main.py
python3 -m py_compile app/security/csrf.py

# Aucune erreur = OK
echo $?  # Doit retourner 0
```

### 4. Vérification des dépendances

```bash
# Vérifier que fastapi-csrf-protect est installé
grep "fastapi-csrf-protect" requirements-web.txt

# Si absent, l'ajouter:
echo "fastapi-csrf-protect==0.3.5" >> requirements-web.txt
```

## Déploiement

### Option 1: Docker (Recommandé)

```bash
# 1. Rebuild des images
docker-compose build

# 2. Redémarrer les services
docker-compose down
docker-compose up -d

# 3. Vérifier les logs
docker-compose logs -f pcap-analyzer | grep -i csrf

# Rechercher:
# - "CSRF protection activated" (après login)
# - "CSRF token generated" (logs serveur)
```

### Option 2: Installation locale

```bash
# 1. Installer/mettre à jour les dépendances
pip install -r requirements-web.txt

# 2. Vérifier les variables d'environnement
source .env
echo $CSRF_SECRET_KEY  # Doit afficher le secret

# 3. Redémarrer l'application
# (méthode dépend de votre setup: systemd, supervisor, etc.)
```

## Tests post-déploiement

### Test 1: Endpoint CSRF accessible

```bash
# Doit retourner HTTP 401 (pas authentifié)
curl -X GET http://localhost:8000/api/csrf/token

# Output attendu: {"detail":"Not authenticated"}
```

### Test 2: Login et CSRF initialization

1. Ouvrir navigateur: `http://localhost:8000/login`
2. Ouvrir DevTools (F12) > Console
3. Se connecter avec un utilisateur valide
4. Vérifier logs console:
   ```
   Login - Token stored: ...
   Login - Initializing CSRF protection...
   CsrfManager.init() - Fetching CSRF token...
   CsrfManager.init() - CSRF protection activated
   ```
5. Vérifier sessionStorage (DevTools > Application > Session Storage):
   - `csrf_token` présent
   - `csrf_header_name` = "X-CSRF-Token"
   - `csrf_expiration` timestamp

### Test 3: Upload avec CSRF

1. Aller sur `/` (upload page)
2. Uploader un fichier PCAP
3. Ouvrir DevTools > Network
4. Vérifier la requête POST `/api/upload`:
   - Request Headers contient: `X-CSRF-Token: <token>`
   - Response status: 200 OK

### Test 4: Delete avec CSRF

1. Aller sur `/history`
2. Supprimer une analyse
3. Vérifier Network tab:
   - Request DELETE `/api/reports/<id>` contient `X-CSRF-Token`
   - Response status: 200 OK

### Test 5: Erreur CSRF (simulation)

1. Se connecter normalement
2. Ouvrir DevTools > Application > Cookies
3. Supprimer le cookie `fastapi-csrf-token`
4. Tenter un upload ou delete
5. Vérifier:
   - Response status: 403 Forbidden
   - Toast message: "Erreur de sécurité CSRF..."

### Test 6: Auto-refresh (optionnel)

**Note**: Ce test prend 26+ minutes

1. Se connecter
2. Laisser l'onglet ouvert pendant 26 minutes
3. Vérifier console logs:
   ```
   CsrfManager - Auto-refreshing CSRF token...
   CsrfManager.fetchToken() - Token fetched successfully
   ```
4. Tenter un upload/delete - doit fonctionner normalement

## Monitoring post-déploiement

### Logs à surveiller

```bash
# Logs serveur - tentatives CSRF
docker-compose logs pcap-analyzer | grep "CSRF validation failed"

# Logs serveur - génération tokens
docker-compose logs pcap-analyzer | grep "CSRF token generated"

# Logs client - DevTools Console
# Rechercher: "CSRF" dans la console du navigateur
```

### Métriques importantes

1. **Taux d'erreur 403 CSRF**
   - Taux normal: <0.1% des requêtes
   - Si >1%: Investiguer (tokens expirés, problème auto-refresh)

2. **Durée de session**
   - Les utilisateurs ne devraient PAS voir d'erreurs CSRF si actifs
   - Auto-refresh fonctionne toutes les 25 minutes

3. **Performance**
   - Overhead CSRF minimal (<1ms par requête)
   - Pas d'impact sur temps de chargement pages

## Rollback en cas de problème

### Option 1: Désactiver temporairement CSRF

**⚠️ DANGER - UTILISER SEULEMENT EN URGENCE**

```python
# Dans app/main.py - commenter le middleware CSRF
# @app.middleware("http")
# async def csrf_middleware(request: Request, call_next):
#     ...

# Redémarrer l'application
```

### Option 2: Revert Git (si commit séparé)

```bash
# Trouver le commit avant CSRF
git log --oneline | head -5

# Revenir en arrière (exemple)
git revert <commit_hash>
git push
```

### Option 3: Restaurer backup

```bash
# Si vous avez un backup avant déploiement
docker-compose down
# Restaurer les fichiers depuis backup
docker-compose up -d
```

## Troubleshooting commun

### Problème: "CSRF_SECRET_KEY not set"

**Cause**: Variable d'environnement manquante

**Solution**:
```bash
# Vérifier .env
cat .env | grep CSRF_SECRET_KEY

# Si absent, générer et ajouter
python3 -c "import secrets; print('CSRF_SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env

# Redémarrer
docker-compose restart pcap-analyzer
```

### Problème: Tous les POST/DELETE retournent 403

**Cause**: Cookie CSRF non défini (HTTPS requis mais non disponible)

**Solution pour développement**:
```bash
# Dans .env
ENVIRONMENT=development

# Redémarrer
docker-compose restart pcap-analyzer
```

**Solution pour production**:
- Configurer reverse proxy HTTPS (nginx, traefik)
- Ou modifier temporairement `cookie_secure = False` dans csrf.py

### Problème: CSRF fonctionne mais logout ne nettoie pas

**Cause**: Code logout non mis à jour

**Solution**: Vérifier que `common.js` contient:
```javascript
function handleLogout() {
    localStorage.removeItem('access_token');
    if (window.csrfManager) {
        window.csrfManager.clear();
    }
    // ...
}
```

### Problème: "csrfManager is not defined"

**Cause**: Script csrf.js non chargé ou erreur JavaScript

**Solution**:
1. Vérifier DevTools > Console pour erreurs
2. Vérifier que `base.html` charge `/static/js/csrf.js`
3. Vérifier que csrf.js est accessible: `curl http://localhost:8000/static/js/csrf.js`

## Checklist finale

- [ ] Variables d'environnement configurées (CSRF_SECRET_KEY, SECRET_KEY, ENVIRONMENT)
- [ ] Fichier .env sécurisé (chmod 600)
- [ ] Code Python compile sans erreur
- [ ] Dépendances installées (fastapi-csrf-protect)
- [ ] Application redémarrée
- [ ] Test login + CSRF initialization réussi
- [ ] Test upload avec CSRF réussi
- [ ] Test delete avec CSRF réussi
- [ ] Test erreur 403 (simulation) réussi
- [ ] Logs serveur vérifiés (pas d'erreurs CSRF massives)
- [ ] Documentation lue (CSRF_IMPLEMENTATION.md)

## Support

En cas de problème:

1. Consulter `CSRF_IMPLEMENTATION.md` (documentation complète)
2. Vérifier logs serveur: `docker-compose logs pcap-analyzer`
3. Vérifier console navigateur (DevTools)
4. Vérifier variables d'environnement: `docker-compose exec pcap-analyzer env | grep CSRF`

## Sécurité

**À FAIRE régulièrement**:
- Rotation des secrets (CSRF_SECRET_KEY, SECRET_KEY) tous les 90 jours
- Audit des logs CSRF pour détecter tentatives d'attaque
- Mise à jour de fastapi-csrf-protect

**À NE JAMAIS FAIRE**:
- Commit .env dans Git
- Désactiver CSRF en production
- Utiliser le même secret pour JWT et CSRF
- Exempter des endpoints sensibles de CSRF
