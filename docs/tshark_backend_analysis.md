# Analyse: Backend tshark pour Détection de Retransmissions

**Date**: 2025-12-28
**Contexte**: Remplacer notre détection custom par tshark pour 100% précision
**Objectif**: Solution portable sans installation tshark manuelle

---

## 🎯 Objectifs

1. ✅ 100% précision vs Wireshark (gold standard)
2. ✅ Éliminer les 15% under-detection
3. ✅ Pas de maintenance du code de détection
4. ✅ Portable (macOS, Linux, containers)
5. ⚠️ Sans installation manuelle de tshark

---

## 🔍 Analyse Technique

### tshark Caractéristiques

**Version**: TShark 4.6.2 (Wireshark)
**License**: GPLv2+ (libre redistribution SI respect GPL)
**Taille binaire**: 922 KB (universal binary x86_64 + ARM64)

**Dépendances dynamiques**:
```
@rpath/libwireshark.19.dylib    (~50-80 MB)
@rpath/libwiretap.16.dylib      (~2-5 MB)
@rpath/libwsutil.17.dylib       (~1-2 MB)
@rpath/libxxhash.0.8.3.dylib    (~100 KB)
@rpath/libglib-2.0.0.dylib      (~2-5 MB)
+ 50+ autres libs transitives...
```

**Total estimé**: ~100-200 MB avec toutes les dépendances

---

## 📊 Options d'Intégration

### Option 1: PyShark (Wrapper Python) ⭐ RECOMMANDÉ

**Description**: Bibliothèque Python qui wrap tshark et parse la sortie

**Installation**:
```bash
pip install pyshark
# Requiert tshark installé sur le système
```

**Avantages**:
- ✅ Interface Python native (objets, pas parsing manuel)
- ✅ Maintenance par communauté Wireshark
- ✅ Support filtres display (BPF + Wireshark filters)
- ✅ Accès à TOUTES les analyses TCP de tshark
- ✅ Pas de parsing fragile de sortie texte

**Inconvénients**:
- ❌ Requiert tshark installé (pas portable sans install)
- ⚠️ Performance (spawn subprocess pour chaque paquet)
- ⚠️ Dépendance externe

**Code exemple**:
```python
import pyshark

# Lire PCAP avec analyse TCP
cap = pyshark.FileCapture('c1.pcap', display_filter='tcp.analysis.retransmission')

for pkt in cap:
    if 'TCP' in pkt:
        retrans_type = pkt.tcp.get_field_value('analysis_retransmission')
        fast_retrans = pkt.tcp.get_field_value('analysis_fast_retransmission')
        spurious = pkt.tcp.get_field_value('analysis_spurious_retransmission')

        print(f"Frame {pkt.number}: {retrans_type}, fast={fast_retrans}, spurious={spurious}")
```

**Stratégie Fallback**:
```python
def detect_retransmissions(pcap_path):
    try:
        # Essayer backend tshark (pyshark)
        return _detect_with_tshark(pcap_path)
    except (ImportError, FileNotFoundError):
        # Fallback vers notre détection custom
        logging.warning("tshark not found, using built-in detection (may have 15% under-detection)")
        return _detect_with_custom(pcap_path)
```

**Installation utilisateur**:
```bash
# macOS (Homebrew)
brew install --cask wireshark

# macOS (MacPorts)
port install wireshark

# Ubuntu/Debian
apt-get install tshark

# RHEL/CentOS
yum install wireshark

# Docker (déjà fait dans notre Dockerfile)
RUN apt-get update && apt-get install -y tshark
```

---

### Option 2: Subprocess Direct (tshark CLI)

**Description**: Appeler tshark en ligne de commande et parser la sortie

**Avantages**:
- ✅ Pas de dépendance Python supplémentaire (juste tshark)
- ✅ Performance correcte
- ✅ Contrôle total sur les arguments

**Inconvénients**:
- ❌ Parsing fragile (format texte peut changer)
- ❌ Requiert tshark installé
- ⚠️ Maintenance du code de parsing

**Code exemple**:
```python
import subprocess
import json

def get_retransmissions_tshark(pcap_path):
    cmd = [
        'tshark', '-r', pcap_path,
        '-Y', 'tcp.analysis.retransmission',
        '-T', 'json',
        '-e', 'frame.number',
        '-e', 'tcp.seq',
        '-e', 'tcp.len',
        '-e', 'tcp.analysis.retransmission',
        '-e', 'tcp.analysis.fast_retransmission',
        '-e', 'tcp.analysis.spurious_retransmission'
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"tshark failed: {result.stderr}")

    return json.loads(result.stdout)
```

---

### Option 3: Embarquer Binaires Statiques

**Description**: Compiler tshark statiquement et l'inclure dans le package

**Défis**:
1. **Licensing GPL**: Obligation de fournir sources + build instructions
2. **Taille**: 100-200 MB par plateforme (macOS x86_64, macOS ARM64, Linux x86_64, Linux ARM64)
3. **Compilation**: Complexe (dépendances glib, pcap, ssl, etc.)
4. **Multi-platform**: Nécessite CI/CD pour builder chaque plateforme
5. **Signature macOS**: Binaires non signés = Gatekeeper bloque

**Exemple Structure**:
```
pcap_analyzer/
├── bin/
│   ├── darwin-x86_64/
│   │   ├── tshark
│   │   └── libs/
│   │       ├── libwireshark.19.dylib
│   │       ├── libwiretap.16.dylib
│   │       └── ...
│   ├── darwin-arm64/
│   ├── linux-x86_64/
│   └── linux-arm64/
└── src/
```

**Taille PyPI wheel**: ~500 MB (4 plateformes × 125 MB)

**Verdict**: ❌ **Trop complexe** pour bénéfice marginal

---

### Option 4: Container-Only (Docker/Kubernetes)

**Description**: Installer tshark uniquement dans l'image Docker

**Avantages**:
- ✅ Facile (déjà fait dans notre Dockerfile!)
- ✅ Pas de problème de portabilité
- ✅ Taille contrôlée

**Inconvénients**:
- ❌ Pas de solution pour CLI local
- ⚠️ Force l'utilisation de containers

**Dockerfile** (déjà implémenté):
```dockerfile
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
```

**Verdict**: ✅ **Excellent pour déploiement prod** (Kubernetes), ❌ **Insuffisant pour dev local**

---

### Option 5: Scapy Pure Python

**Description**: Utiliser Scapy (déjà installé) pour analyse TCP

**Avantages**:
- ✅ Pure Python (déjà dépendance)
- ✅ Pas d'installation supplémentaire
- ✅ Performant

**Inconvénients**:
- ❌ Scapy ne fait PAS d'analyse TCP avancée (pas de retrans detection)
- ❌ Il faudrait réimplémenter toute la logique tshark
- ❌ Retour à la case départ (notre code custom actuel)

**Verdict**: ❌ **Ne résout pas le problème**

---

## 🎯 Stratégie Recommandée

### Phase 1: Hybrid Backend (v5.4.0) ⭐

**Implémentation**:

1. **Ajouter PyShark comme dépendance optionnelle**:
   ```toml
   # pyproject.toml
   [project.optional-dependencies]
   tshark = ["pyshark>=0.6"]
   ```

2. **Détection automatique au runtime**:
   ```python
   # src/analyzers/retransmission.py

   BACKEND = "auto"  # "auto", "tshark", "builtin"

   def detect_backend():
       if BACKEND == "builtin":
           return "builtin"

       if BACKEND == "tshark" or BACKEND == "auto":
           try:
               import pyshark
               # Test if tshark is available
               subprocess.run(['tshark', '--version'],
                            capture_output=True, check=True)
               return "tshark"
           except (ImportError, FileNotFoundError):
               if BACKEND == "tshark":
                   raise RuntimeError("tshark backend requested but not available")
               # Fallback to builtin
               return "builtin"

   def analyze_retransmissions(pcap_path, backend="auto"):
       actual_backend = detect_backend() if backend == "auto" else backend

       if actual_backend == "tshark":
           logger.info("Using tshark backend (100% accuracy)")
           return TsharkRetransmissionAnalyzer().analyze(pcap_path)
       else:
           logger.warning("Using built-in backend (may have 15% under-detection)")
           return BuiltinRetransmissionAnalyzer().analyze(pcap_path)
   ```

3. **CLI option**:
   ```bash
   # Utiliser tshark si disponible
   pcap_analyzer analyze file.pcap --retrans-backend auto

   # Forcer tshark (erreur si pas dispo)
   pcap_analyzer analyze file.pcap --retrans-backend tshark

   # Forcer built-in
   pcap_analyzer analyze file.pcap --retrans-backend builtin
   ```

4. **Configuration**:
   ```yaml
   # .pcap_analyzer.yaml
   retransmission:
     backend: auto  # auto, tshark, builtin
     warn_on_fallback: true
   ```

5. **README Instructions**:
   ```markdown
   ## Installation

   ### Basic (built-in detection)
   pip install pcap-analyzer

   ### Enhanced (tshark backend for 100% accuracy)
   # macOS
   brew install --cask wireshark
   pip install pcap-analyzer[tshark]

   # Linux
   sudo apt-get install tshark
   pip install pcap-analyzer[tshark]

   ### Docker (tshark included)
   docker run -v $(pwd):/data macflurry/pcap-analyzer analyze /data/file.pcap
   ```

**Avantages**:
- ✅ Best of both worlds (précision tshark + fallback portable)
- ✅ Aucune régression (builtin toujours disponible)
- ✅ Docker users get tshark automatically
- ✅ CLI users can opt-in
- ✅ Pas de packaging complexe

**Inconvénients**:
- ⚠️ Deux chemins de code à maintenir (mais builtin existe déjà)
- ⚠️ Doc doit expliquer les différences

---

### Phase 2: tshark par Défaut (v6.0.0)

**Changement**:
```python
BACKEND = "auto"  # Mais tshark devient le défaut si disponible
```

**Communication**:
- Blog post expliquant les bénéfices
- Migration guide
- Deprecation warning pour builtin backend (sera retiré en v7.0)

---

### Phase 3: tshark Uniquement (v7.0.0)

**Changement**:
```python
# Retirer builtin backend complètement
# tshark devient obligatoire
```

**Justification**:
- Simplification du code (une seule logique)
- Meilleure précision garantie
- Alignement avec Wireshark (standard industrie)

---

## 📈 Comparaison des Options

| Option | Précision | Portabilité | Complexité | Taille | Verdict |
|--------|-----------|-------------|------------|--------|---------|
| **PyShark + Fallback** | 🟢 100% (si tshark) | 🟢 Excellente | 🟢 Faible | 🟢 ~10 KB | ⭐ **RECOMMANDÉ** |
| Subprocess Direct | 🟢 100% | 🟢 Bonne | 🟡 Moyenne | 🟢 0 KB | ✅ Alternative |
| Binaires Embarqués | 🟢 100% | 🟢 Parfaite | 🔴 Très haute | 🔴 500 MB | ❌ Non viable |
| Container-Only | 🟢 100% | 🟡 Limitée | 🟢 Faible | 🟢 0 KB | ✅ Prod only |
| Scapy | 🔴 85% | 🟢 Parfaite | 🔴 Très haute | 🟢 0 KB | ❌ Inutile |
| **Builtin (actuel)** | 🟡 85% | 🟢 Parfaite | 🟢 Faible | 🟢 0 KB | ✅ Fallback |

---

## 🔧 Plan d'Implémentation (v5.4.0)

### Tâches

- [ ] **1. Créer TsharkRetransmissionAnalyzer**
  - Fichier: `src/analyzers/retransmission_tshark.py`
  - Utiliser PyShark pour lire PCAP
  - Extraire `tcp.analysis.*` fields
  - Mapper vers notre structure TCPRetransmission

- [ ] **2. Ajouter backend detection**
  - Fichier: `src/analyzers/retransmission.py`
  - Function `detect_backend()`
  - Function `analyze_retransmissions(backend="auto")`

- [ ] **3. CLI option**
  - Fichier: `src/cli.py`
  - Ajouter `--retrans-backend {auto,tshark,builtin}`
  - Default: "auto"

- [ ] **4. Tests**
  - Tester avec tshark disponible
  - Tester sans tshark (fallback)
  - Tester avec c1.pcap (27 retrans attendues)

- [ ] **5. Documentation**
  - README: Installation instructions
  - CHANGELOG: New feature
  - conductor/tech-stack.md: Backend options

**Temps estimé**: 4-6 heures

---

## 🎓 Conclusion

**Recommendation**: ✅ **Option 1 (PyShark + Fallback)**

**Justifications**:
1. ✅ 100% précision si tshark disponible
2. ✅ Fallback gracieux vers builtin (85% précision)
3. ✅ Docker users get tshark automatiquement
4. ✅ CLI users peuvent l'installer facilement
5. ✅ Pas de complexité de packaging
6. ✅ Maintenance faible (PyShark maintenu par communauté)
7. ✅ Alignement avec industrie (Wireshark = gold standard)

**Next Steps**:
1. Créer track `conductor/tracks/tshark_backend_v540/`
2. Implémenter TsharkRetransmissionAnalyzer
3. Tests avec c1.pcap
4. Release v5.4.0

---

**Généré le**: 2025-12-28
**Auteur**: PCAP Analyzer Development Team
