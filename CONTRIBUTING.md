# Guide de contribution

Merci de votre intérêt pour contribuer à PCAP Analyzer ! 🎉

## Comment contribuer

### Signaler un bug

1. Vérifiez que le bug n'a pas déjà été signalé dans les [issues](https://github.com/MacFlurry/pcap_analyzer/issues)
2. Créez une nouvelle issue avec :
   - Un titre descriptif
   - Les étapes pour reproduire le problème
   - Le comportement attendu vs le comportement observé
   - Votre environnement (OS, version Python, version de l'outil)
   - Les logs pertinents

### Proposer une fonctionnalité

1. Ouvrez une issue pour discuter de la fonctionnalité
2. Décrivez :
   - Le cas d'usage
   - Le comportement souhaité
   - Des exemples d'utilisation

### Soumettre une pull request

1. **Forkez** le repository
2. **Créez une branche** pour votre fonctionnalité :
   ```bash
   git checkout -b feature/ma-super-fonctionnalite
   ```

3. **Installez les outils de développement** :
   ```bash
   # Créez un environnement virtuel
   python3 -m venv venv
   source venv/bin/activate  # Sur Windows: venv\Scripts\activate

   # Installez en mode développement avec toutes les dépendances
   pip install -e ".[dev]"

   # Installez pre-commit pour les hooks automatiques
   pre-commit install
   ```

   Note: Toutes les dépendances (CLI, web, dev) sont maintenant dans `pyproject.toml`

4. **Faites vos modifications** :
   - Suivez le style de code existant (Black + isort)
   - Ajoutez des tests (unitaires + property-based avec Hypothesis)
   - Mettez à jour la documentation
   - Les hooks pre-commit vérifient automatiquement le formatage

5. **Testez** vos modifications :
   ```bash
   # Lancez les tests
   pytest

   # Avec couverture
   pytest --cov=src --cov-report=html

   # Lancez les tests property-based
   pytest tests/test_property_based.py

   # Vérifiez le formatage manuellement
   pre-commit run --all-files

   # Testez l'analyse CLI
   pcap_analyzer analyze test.pcap

   # Testez l'interface web
   docker-compose up -d
   curl http://localhost:8000/api/health
   docker-compose down
   ```

6. **Committez** vos changements :
   ```bash
   git commit -m "feat: ajout de ma super fonctionnalité

   Description détaillée de ce qui a été fait.

   Fixes #123"
   ```
   Note: Les hooks pre-commit formatent automatiquement votre code lors du commit.

7. **Poussez** sur votre fork :
   ```bash
   git push origin feature/ma-super-fonctionnalite
   ```

8. **Créez une Pull Request** sur GitHub

## Standards de code

### Style Python

- Suivez [PEP 8](https://pep8.org/)
- **Formatage automatique** avec Black (line-length=120)
- **Tri des imports** avec isort (profile=black)
- **Type hints requis** pour toutes les nouvelles fonctions publiques
- **Docstrings** obligatoires pour classes et fonctions publiques
- Maximum 120 caractères par ligne (configuré dans pyproject.toml)
- Les hooks **pre-commit** vérifient automatiquement le style

Exemple :

```python
def analyze_packet(packet: Packet, threshold: float = 1.0) -> Dict[str, Any]:
    """
    Analyse un paquet réseau

    Args:
        packet: Paquet Scapy à analyser
        threshold: Seuil de détection en secondes

    Returns:
        Dictionnaire contenant les résultats d'analyse
    """
    # Votre code ici
    pass
```

### Convention de nommage

- **Fichiers** : `snake_case.py`
- **Classes** : `PascalCase`
- **Fonctions/variables** : `snake_case`
- **Constantes** : `UPPER_SNAKE_CASE`

### Messages de commit

Format recommandé :

```
type(scope): description courte

Description détaillée si nécessaire.

Fixes #123
```

Types :
- `feat`: Nouvelle fonctionnalité
- `fix`: Correction de bug
- `docs`: Documentation uniquement
- `style`: Formatage, pas de changement de code
- `refactor`: Refactoring sans changement de comportement
- `test`: Ajout ou modification de tests
- `chore`: Maintenance (dépendances, etc.)

Exemples :
```
feat(dns): ajout support DNS over HTTPS
fix(ssh): correction expansion tilde dans chemins
docs(readme): mise à jour exemples d'utilisation
```

## Structure du projet

```
pcap_analyzer/
├── app/                    # Interface web FastAPI
│   ├── api/routes/        # Endpoints REST
│   ├── services/          # Worker, DB, Analyzer
│   ├── templates/         # UI (upload, progress, history)
│   └── static/            # CSS/JS
├── src/                   # CLI + analyseurs
│   ├── analyzers/         # 17 analyseurs TCP/DNS/etc
│   ├── parsers/           # dpkt + Scapy parsers
│   ├── exporters/         # Générateurs de rapports
│   ├── utils/             # Utilitaires
│   └── cli.py             # Interface ligne de commande
├── helm-chart/            # Déploiement Kubernetes
│   └── pcap-analyzer/    # Helm chart avec Ingress
├── tests/                 # Tests pytest
│   ├── unit/             # Tests unitaires
│   ├── integration/      # Tests d'intégration
│   └── conftest.py       # Fixtures communes
├── scripts/               # Scripts utilitaires
├── docker-compose.yml     # Dev environment
├── Dockerfile             # Multi-stage build (485 MB)
├── pyproject.toml         # Configuration moderne (PEP 517/518)
└── pytest.ini             # Configuration pytest
```

## Architecture

PCAP Analyzer offre deux modes d'utilisation:

### Mode CLI
- Analyse directe de fichiers PCAP locaux
- Rapports HTML/JSON générés immédiatement
- Idéal pour analyse ponctuelle ou scripts

### Mode Web (FastAPI)
- Interface moderne avec upload drag & drop
- Progression temps réel via Server-Sent Events (SSE)
- Historique des analyses (rétention 24h)
- API REST complète
- Déploiement Docker/Kubernetes avec Ingress

### Technologies
- **Parsing**: Architecture hybride dpkt + Scapy (1.7x plus rapide)
- **Web**: FastAPI + Uvicorn + aiosqlite
- **Frontend**: HTML/CSS/JS vanilla (pas de framework)
- **Déploiement**: Docker multi-stage + Helm chart
- **Tests**: pytest + pytest-asyncio + Hypothesis

## Ajouter un nouvel analyseur

Pour ajouter un nouvel analyseur de latence :

1. **Créez le fichier** `src/analyzers/mon_analyzer.py` :

```python
from scapy.all import Packet
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class MonResultat:
    """Résultat de l'analyse"""
    field1: str
    field2: float

class MonAnalyzer:
    """Analyseur pour détecter [votre cas d'usage]"""

    def __init__(self, threshold: float = 1.0):
        self.threshold = threshold
        self.results: List[MonResultat] = []

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les paquets

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats
        """
        # Votre logique d'analyse
        pass

    def get_summary(self) -> str:
        """Retourne un résumé textuel"""
        return f"Mon analyse: {len(self.results)} résultats"
```

2. **Ajoutez dans** `src/analyzers/__init__.py` :

```python
from .mon_analyzer import MonAnalyzer

__all__ = [
    # ... existants
    'MonAnalyzer',
]
```

3. **Intégrez dans** `src/cli.py` :

```python
from .analyzers import MonAnalyzer

# Dans la fonction analyze_pcap()
mon_analyzer = MonAnalyzer(threshold=config.get('thresholds.mon_seuil', 1.0))
results['mon_analyse'] = mon_analyzer.analyze(packets)
```

4. **Ajoutez dans** `config.yaml` :

```yaml
thresholds:
  mon_seuil: 1.0
```

5. **Mettez à jour la documentation** dans README.md

## Tests

Le projet utilise **pytest** pour les tests unitaires et d'intégration, et **Hypothesis** pour les tests property-based.

### Lancer les tests

```bash
# Tous les tests
pytest

# Avec couverture
pytest --cov=src --cov=app --cov-report=html --cov-report=term-missing

# Tests par catégorie
pytest tests/unit/          # Tests unitaires uniquement
pytest tests/integration/   # Tests d'intégration web

# Tests spécifiques
pytest tests/test_tcp_handshake.py -v

# Tests property-based uniquement
pytest tests/test_property_based.py -v

# Tests en parallèle (plus rapide)
pytest -n auto
```

### Tests web (FastAPI)

Les tests d'intégration utilisent `TestClient` de Starlette:

```python
from fastapi.testclient import TestClient
from app.main import app

def test_upload_endpoint(client: TestClient):
    """Test l'upload d'un fichier PCAP"""
    with open("test.pcap", "rb") as f:
        response = client.post("/api/upload", files={"file": f})
    assert response.status_code == 200
    assert "task_id" in response.json()
```

Les fixtures dans `tests/conftest.py` fournissent:
- `test_data_dir`: Répertoire temporaire pour les tests
- `test_db`: Instance de base de données SQLite
- `client`: TestClient FastAPI configuré
- `mock_worker`: Worker simulé pour éviter l'analyse réelle

### Écrire des tests

**Tests unitaires** (tests/test_*.py):
```python
import pytest
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer

def test_handshake_analyzer_init():
    analyzer = TCPHandshakeAnalyzer()
    assert analyzer.total_handshakes == 0
```

**Tests property-based** (tests/test_property_based.py):
```python
from hypothesis import given, strategies as st
from src.config import Config

@given(threshold=st.floats(min_value=0.0, max_value=10.0))
def test_positive_threshold(threshold):
    """All thresholds should be non-negative."""
    assert threshold >= 0
```

### Coverage

Objectif: **>80%** de couverture de code

Voir le rapport: `open htmlcov/index.html` après `pytest --cov`

## Docker et Kubernetes

### Tester avec Docker Compose

```bash
# Démarrer l'application
docker-compose up -d

# Vérifier les logs
docker-compose logs -f

# Tester l'API
curl http://localhost:8000/api/health

# Arrêter
docker-compose down
```

### Tester avec Kubernetes (kind)

```bash
# Build et charger l'image
docker build -t pcap-analyzer:test .
kind create cluster --name test --config kind-config.yaml
kind load docker-image pcap-analyzer:test --name test

# Installer avec Helm
helm install pcap-analyzer ./helm-chart/pcap-analyzer \
  --set image.tag=test \
  --set ingress.enabled=false \
  --set service.type=NodePort

# Vérifier
kubectl get all -n pcap-analyzer
kubectl logs -n pcap-analyzer deployment/pcap-analyzer

# Nettoyer
kind delete cluster --name test
```

## Documentation

- **README.md** : Documentation principale
- **helm-chart/pcap-analyzer/README.md** : Guide Kubernetes/Helm
- **CHANGELOG.md** : Historique des versions
- **tests/README.md** : Guide des tests
- **scripts/README.md** : Documentation scripts

Mettez à jour la documentation pertinente pour vos modifications.

## Checklist avant PR

- [ ] **Pre-commit hooks** passent (`pre-commit run --all-files`)
- [ ] **Tests** passent (`pytest`)
- [ ] **Couverture** maintenue ou améliorée (`pytest --cov=src --cov=app`)
- [ ] **Type hints** ajoutés pour toutes les nouvelles fonctions publiques
- [ ] **Docstrings** ajoutées/mises à jour
- [ ] **Documentation** mise à jour (README.md si applicable)
- [ ] **Tests unitaires** ajoutés pour les nouvelles fonctionnalités
- [ ] **Tests d'intégration** si modification de l'API web
- [ ] **Tests property-based** si applicable (Hypothesis)
- [ ] Le **commit message** suit les conventions (feat/fix/docs/etc.)
- [ ] **Docker build** réussit (`docker build -t pcap-analyzer:test .`)
- [ ] **Helm lint** passe si modification du chart (`helm lint ./helm-chart/pcap-analyzer`)
- [ ] Pas d'informations sensibles dans le code
- [ ] `config.yaml` ne contient que des exemples génériques
- [ ] Pas de fichiers inutiles committés (*.pyc, __pycache__, .DS_Store, etc.)

## Questions ?

N'hésitez pas à :
- Ouvrir une issue pour poser des questions
- Demander des clarifications sur une issue existante
- Proposer des améliorations à ce guide

## Code de conduite

- Soyez respectueux et constructif
- Accueillez les nouveaux contributeurs
- Focalisez sur le problème, pas la personne
- Assumez les bonnes intentions

## Licence

En contribuant, vous acceptez que vos contributions soient sous licence MIT, comme le reste du projet.

---

Merci de contribuer à PCAP Analyzer ! 🚀
