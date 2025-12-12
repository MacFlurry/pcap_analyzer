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

Actuellement testé:
- ✅ Service database (10 tests)
- ✅ Service worker (6 tests)
- ✅ Routes upload (6 tests)
- ✅ Routes progress/status (4 tests)
- ✅ Routes reports (4 tests)
- ✅ Route health (1 test)
- ✅ Validation sécurité upload (6 tests)
- ✅ Tests intégration end-to-end (7 tests)

**Total**: ~44 tests
