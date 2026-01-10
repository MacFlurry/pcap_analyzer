# Tests - PCAP Analyzer

Suite de tests complète pour l'application PCAP Analyzer Web.

## Structure

```
tests/
├── conftest.py              # Fixtures pytest communes
├── unit/                    # Tests unitaires
│   ├── test_database.py     # Tests service database
│   ├── test_worker.py       # Tests worker background
│   ├── test_routes_*.py     # Tests routes API
│   └── test_routes_health.py
├── integration/             # Tests d'intégration
│   └── test_end_to_end.py   # Tests workflow complet
└── security/                # Tests de sécurité
    └── test_upload_validation.py
```

## Exécution

### Tous les tests
```bash
pytest tests/ -v
```

### Par catégorie
```bash
# Tests unitaires
pytest tests/unit/ -v -m unit

# Tests d'intégration
pytest tests/integration/ -v -m integration

# Tests de sécurité
pytest tests/security/ -v -m security
```

### Avec coverage
```bash
pytest tests/ -v --cov=app --cov=src --cov-report=html
# Ouvrir htmlcov/index.html pour voir le rapport
```

### Tests rapides (skip slow)
```bash
pytest tests/ -v -m "not slow"
```

## Markers

- `@pytest.mark.unit` - Tests unitaires
- `@pytest.mark.integration` - Tests d'intégration
- `@pytest.mark.security` - Tests de sécurité
- `@pytest.mark.slow` - Tests lents (>5s)
- `@pytest.mark.smoke` - Tests rapides essentiels

## Fixtures disponibles

- `test_db` - Base de données SQLite en mémoire
- `test_worker` - Worker background initialisé
- `client` - TestClient FastAPI (sync)
- `async_client` - AsyncClient (async)
- `sample_pcap_file` - Fichier PCAP valide minimal
- `invalid_pcap_file` - Fichier PCAP invalide
- `large_file` - Fichier >500MB (pour tests limites)
- `test_data_dir` - Répertoire temporaire pour tests

## Objectif de coverage

**Target**: >80% de couverture de code  
**Actuel**: 26.77% de couverture

### Statistiques (v5.4.5)

- **102 fichiers** de tests
- **877 tests** collectés par pytest
- **Répartition**:
  - Unit: ~170 tests (19 fichiers)
  - Integration: ~400 tests (26 fichiers)
  - Security: ~150 tests (13 fichiers)
  - Root/E2E: ~157 tests (38 fichiers)

### Catégories principales

- ✅ **Tests unitaires** (`tests/unit/`): Services, routes, analyzers
- ✅ **Tests d'intégration** (`tests/integration/`): Workflows complets, base de données
- ✅ **Tests de sécurité** (`tests/security/`): Validation upload, XSS, CSRF, injection
- ✅ **Tests E2E** (`tests/e2e/`): Flux utilisateur complets
- ✅ **Tests de régression**: Bugs corrigés (duration, flow_key, timing)

### Tests nettoyés (v5.4.5)

- ❌ `test_v415_security_poc.py` - POC obsolète v4.15.0 (supprimé)
- ❌ `test_security_poc_exploits.py` - POC d'exploits non-pytest (supprimé)
- ✅ Tests de régression consolidés dans `tests/regression/`
- ✅ Bug corrigé dans `test_routes_health.py` (version hardcodée → dynamique)

### Tests de régression (utiles pour éviter les régressions)

- ✅ `test_duration_calculation_regression.py` - Bug corrigé v5.4.4
- ✅ `test_timeline_flow_key_fix.py` - Bug corrigé v4.15.0
- ✅ `test_backward_compatibility.py` - Compatibilité SQLite/PostgreSQL
