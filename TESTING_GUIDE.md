# Guide de Test - PCAP Analyzer

Ce guide décrit les procédures de test pour le PCAP Analyzer, incluant les tests unitaires, d'intégration et les tests de sécurité.

## 1. Tests Unitaires & Mocking

Les tests unitaires utilisent `pytest` et `unittest.mock` pour isoler les composants.

### Mocking de Tshark & Système
Pour tester l'analyse PCAP sans dépendre de binaires externes (`tshark`, `tcpdump`) :
- Utiliser la stratégie de mocking définie dans `tests/unit/services/test_analyzer_mocking.py`.
- Les analyseurs complexes et le parser `FastPacketParser` doivent être patchés pour retourner des données simulées.

**Usage :**
```bash
pytest tests/unit/services/test_analyzer_mocking.py
```

### Sanitization PII (GDPR)
Vérifier que les informations sensibles (IPs, mots de passe, chemins) sont correctement masquées dans les logs et rapports.

**Usage :**
```bash
pytest tests/unit/utils/test_pii_sanitization.py
```

## 2. Tests d'Intégration (API & Worker)

Les tests d'intégration utilisent **Testcontainers** pour lancer une base de données PostgreSQL réelle dans Docker.

### Configuration Requise
- Docker doit être installé et démarré.
- L'utilisateur doit avoir les permissions pour lancer des conteneurs.

### Cycle de Vie Upload
Teste le workflow complet : Upload -> Validation -> Création de tâche.
- Fichiers valides (202 Accepted)
- Fichiers non-PCAP (400 Bad Request)
- Fichiers trop volumineux (413 Payload Too Large)

**Usage :**
```bash
pytest tests/integration/test_upload_lifecycle.py
```

### Analysis Worker
Teste le traitement en arrière-plan et les transitions de statut (PENDING -> PROCESSING -> COMPLETED/FAILED).

**Usage :**
```bash
pytest tests/integration/test_analysis_worker.py
```

### Isolation Multi-Tenant
Vérifie que les utilisateurs ne peuvent accéder qu'à leurs propres rapports.

**Usage :**
```bash
pytest tests/integration/test_reports_access.py
```

## 3. Couverture de Code

Pour générer un rapport de couverture détaillé :

```bash
pytest --cov=app --cov=src --cov-report=html
```
Le rapport sera disponible dans le répertoire `htmlcov/`.

## 4. Troubleshooting

### Erreur "Too many open files" (OSError 24)
Cette erreur survient lors de l'exécution de la suite complète de tests (700+ tests) à cause de l'accumulation de descripteurs de fichiers non fermés.
**Solution :**
- Augmenter la limite système : `ulimit -n 4096`.
- Lancer les tests par modules plutôt que la suite complète.

### Erreur "Runner.run() cannot be called from a running event loop"
Survient souvent avec `pytest-asyncio` lors de l'utilisation de fixtures asynchrones mal configurées.
**Solution :**
- S'assurer qu'une seule boucle d'événements est utilisée par session.
- Vérifier la fixture `event_loop` dans `tests/conftest.py`.

### Échec de connexion PostgreSQL dans Testcontainers
**Solution :**
- Vérifier que Docker est démarré.
- Augmenter le timeout `ensure_postgres_ready` dans `conftest.py` si nécessaire.