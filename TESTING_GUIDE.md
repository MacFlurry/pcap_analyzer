# Test Scripts - Admin Approval Workflow

Scripts de test pour valider le workflow d'approbation admin (Issue #20).

## Configuration

Les scripts utilisent des **variables d'environnement** pour les credentials (sécurité : pas de mots de passe en dur).

### Variables requises

```bash
export ADMIN_PASSWORD="your_admin_password_here"
export USER_PASSWORD="your_user_password_here"
```

### Variables optionnelles

```bash
export USER_USERNAME="testuser"  # Défaut: "testuser"
export USER_EMAIL="test@example.com"  # Défaut: "testuser@example.com"
```

## Scripts disponibles

### 1. `test_approval_workflow.py`
Test complet du workflow d'approbation.

**Teste** :
- Inscription utilisateur avec `is_approved=False`
- Login bloqué pour utilisateur non approuvé (403)
- Approbation par admin
- Login réussi après approbation
- Blocage utilisateur par admin
- Login bloqué pour utilisateur désactivé (403)

**Usage** :
```bash
export ADMIN_PASSWORD="your_admin_password"
python3 test_approval_workflow.py
```

### 2. `test_user_obk.py`
Test du workflow avec un utilisateur spécifique.

**Teste** :
- Inscription/recherche utilisateur
- Workflow complet : inscription → approbation → login → accès profil

**Usage** :
```bash
export ADMIN_PASSWORD="your_admin_password"
export USER_USERNAME="myuser"
export USER_EMAIL="myuser@example.com"
export USER_PASSWORD="mypassword"
python3 test_user_obk.py
```

### 3. `test_multitenant.py`
Test de l'isolation multi-tenant.

**Teste** :
- Admin voit toutes les tâches
- Utilisateur voit uniquement ses tâches
- Utilisateur ne peut pas accéder aux rapports d'autres utilisateurs (403)

**Usage** :
```bash
export ADMIN_PASSWORD="your_admin_password"
export USER_USERNAME="testuser"
export USER_PASSWORD="testpassword"
python3 test_multitenant.py
```

## Exemple complet

```bash
# 1. Obtenir le mot de passe admin breakglass
docker logs pcap-analyzer 2>&1 | grep -A 10 "ADMIN BRISE-GLACE"

# 2. Configurer les variables d'environnement
export ADMIN_PASSWORD="your_admin_password_here"
export USER_USERNAME="testuser"
export USER_EMAIL="testuser@example.com"
export USER_PASSWORD="SecurePassword123!"

# 3. Lancer les tests
python3 test_approval_workflow.py
python3 test_user_obk.py
python3 test_multitenant.py
```

## Résultats attendus

Tous les tests doivent afficher :
```
✅ ALL TESTS PASSED - [TEST NAME] WORKING CORRECTLY
```

## Sécurité

⚠️ **IMPORTANT** :
- Ne jamais commiter de mots de passe dans Git
- Utiliser toujours des variables d'environnement
- Ne pas logger les mots de passe en clair
- Changer le mot de passe admin breakglass après le premier déploiement

## Dépendances

```bash
pip install httpx
```

## Logs et debugging

Pour voir les logs du serveur pendant les tests :
```bash
docker logs -f pcap-analyzer
```

Pour débugger un test spécifique :
```bash
# Activer le mode verbose (ajouter print statements)
python3 test_approval_workflow.py
```

## Troubleshooting

### Erreur "Missing required environment variables"
→ Les variables d'environnement ne sont pas définies. Vérifier avec `echo $ADMIN_PASSWORD`.

### Erreur "Admin login failed: 401"
→ Mot de passe admin incorrect. Récupérer le mot de passe breakglass dans les logs Docker.

### Erreur "Connection refused"
→ Le serveur n'est pas démarré. Vérifier avec `docker ps` et `curl http://localhost:8000/api/health`.

### Test échoue à l'étape d'approbation
→ Vérifier que l'utilisateur n'est pas déjà approuvé. Vérifier les logs : `docker logs pcap-analyzer | grep -i approve`.
