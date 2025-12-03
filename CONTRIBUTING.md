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

3. **Faites vos modifications** :
   - Suivez le style de code existant
   - Ajoutez des tests si applicable
   - Mettez à jour la documentation

4. **Testez** vos modifications :
   ```bash
   # Installez en mode développement
   pip install -e .

   # Testez la connexion SSH
   python3 test_ssh.py

   # Testez l'analyse
   pcap_analyzer analyze test.pcap
   ```

5. **Committez** vos changements :
   ```bash
   git commit -m "feat: ajout de ma super fonctionnalité

   Description détaillée de ce qui a été fait.

   Fixes #123"
   ```

6. **Poussez** sur votre fork :
   ```bash
   git push origin feature/ma-super-fonctionnalite
   ```

7. **Créez une Pull Request** sur GitHub

## Standards de code

### Style Python

- Suivez [PEP 8](https://pep8.org/)
- Utilisez des docstrings pour les fonctions et classes
- Maximum 100 caractères par ligne (sauf exceptions)
- Type hints recommandés pour les nouvelles fonctions

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
├── src/
│   ├── analyzers/      # Modules d'analyse
│   ├── cli.py          # Interface CLI
│   ├── config.py       # Gestion configuration
│   └── ...
├── tests/              # Tests unitaires (à créer)
├── docs/               # Documentation supplémentaire
└── examples/           # Exemples d'utilisation
```

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

Actuellement, le projet n'a pas de suite de tests automatisés. C'est une excellente opportunité de contribution !

Pour tester manuellement :

```bash
# Test SSH
python3 test_ssh.py

# Test analyse
pcap_analyzer analyze examples/test.pcap

# Test capture
pcap_analyzer capture -d 10
```

## Documentation

- **README.md** : Documentation principale
- **QUICKSTART.md** : Guide de démarrage rapide
- **TROUBLESHOOTING.md** : Résolution de problèmes
- **STRUCTURE.md** : Architecture du projet

Mettez à jour la documentation pertinente pour vos modifications.

## Checklist avant PR

- [ ] Le code suit les conventions de style
- [ ] Les docstrings sont ajoutées/mises à jour
- [ ] La documentation est à jour
- [ ] Les tests manuels passent
- [ ] Le commit message est descriptif
- [ ] Pas d'informations sensibles dans le code
- [ ] `config.yaml` ne contient que des exemples génériques

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
