# Track: Add Owner Column in History View for Admins

## 🎯 Objectif

Ajouter une colonne "PROPRIÉTAIRE" dans la vue historique pour que les administrateurs puissent identifier rapidement à qui appartient chaque fichier PCAP.

## 💡 Problème Actuel

Le mode multi-tenant fonctionne correctement :
- ✅ Users voient uniquement leurs propres uploads
- ✅ Admins voient tous les uploads

**MAIS** : Quand un admin voit l'historique avec tous les PCAPs de tous les utilisateurs, il ne peut pas savoir d'un coup d'œil à qui appartient chaque fichier.

## ✅ Solution

Ajouter une colonne **"PROPRIÉTAIRE"** qui :
- Affiche le **username** du propriétaire de chaque PCAP
- **Visible UNIQUEMENT pour les admins**
- Positionnée entre les colonnes "FICHIER" et "STATUT"

## 📋 Changements Requis

### Backend (Python)
1. **Schema** : Ajouter `owner_username: Optional[str]` à `TaskInfo`
2. **Database** : Modifier `get_recent_tasks()` pour faire un LEFT JOIN avec la table `users`
3. **Tests** : Vérifier que `owner_username` est retourné correctement

### Frontend (HTML/JS/CSS)
1. **HTML** : Ajouter header "PROPRIÉTAIRE" dans `history.html`
2. **JavaScript** :
   - Détecter si user est admin
   - Toggle visibilité de la colonne owner
   - Afficher username dans chaque ligne
3. **CSS** : Styles pour `.grid-cell-owner`

### Tests E2E
1. Admin voit la colonne avec usernames corrects
2. User normal ne voit PAS la colonne

### Documentation
1. **CHANGELOG.md** : Documenter la nouvelle feature
2. **README.md** : Mettre à jour section admin features
3. **Version** : Bump selon SemVer (recommandé: v5.2.0)

## ⚠️ IMPORTANT pour Conductor : Gestion de Version SemVer

### Règles SemVer

**Cette feature est un ENHANCEMENT (nouvelle fonctionnalité)** :
- Type : **MINOR** version bump
- Raison : Nouvelle fonctionnalité, backward compatible, pas de breaking change
- Version recommandée : **v5.2.0** (si actuelle = v5.1.0)

### Fichiers de Version à Synchroniser

Conductor DOIT synchroniser les versions dans TOUS ces fichiers :

1. **`src/__version__.py`** :
   ```python
   __version__ = "5.2.0"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`** :
   ```yaml
   appVersion: "5.2.0"
   version: 1.4.0  # Bump chart version aussi
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`** :
   ```yaml
   image:
     tag: v5.2.0
   ```

4. **`pyproject.toml`** (si existe) :
   ```toml
   version = "5.2.0"
   ```

### Commit Message Pattern

```
feat(admin): add owner column in history view for admins

- Backend: Add owner_username to TaskInfo schema
- Backend: LEFT JOIN users table in get_recent_tasks
- Frontend: Toggle owner column visibility based on user role
- Frontend: Display username for each task (admins only)
- Tests: E2E tests for admin/user visibility
- Docs: Update CHANGELOG and README

BREAKING CHANGE: None (backward compatible)
Type: Enhancement (feature addition)
Version: v5.2.0
```

## 🚀 Quick Start (Conductor)

```bash
# 1. Lire le plan complet
cat conductor/tracks/add_owner_column_history/plan.md

# 2. Implémenter les changements selon les 4 phases
# Phase 1: Backend (schema + database LEFT JOIN)
# Phase 2: Frontend (HTML + JS + CSS)
# Phase 3: Tests E2E
# Phase 4: Documentation + Version bump

# 3. Tester localement
pytest tests/e2e/test_history_owner_column.py -v --headed

# 4. Vérifier toutes les versions sont synchronisées
grep -r "5.2.0" src/__version__.py helm-chart/pcap-analyzer/Chart.yaml helm-chart/pcap-analyzer/values.yaml

# 5. Commit avec message conventionnel
git add .
git commit -m "feat(admin): add owner column in history view for admins ..."
```

## 📊 Critères de Succès

- [ ] Admin voit colonne "PROPRIÉTAIRE" avec usernames
- [ ] User normal ne voit PAS la colonne
- [ ] LEFT JOIN performant (< 100ms pour 50 tâches)
- [ ] Tests E2E passent (2 tests)
- [ ] CHANGELOG.md mis à jour
- [ ] Version bump à v5.2.0 dans tous les fichiers
- [ ] Aucune régression sur tests existants

## 🎨 Mockup Visuel

**Vue Admin** (avec colonne owner) :
```
┌──────┬──────────────────┬──────────────┬────────┬────────┬─────────┬──────────┬──────────┐
│  ☐   │  FICHIER         │ PROPRIÉTAIRE │ STATUT │  DATE  │ PAQUETS │  SCORE   │ ACTIONS  │
├──────┼──────────────────┼──────────────┼────────┼────────┼─────────┼──────────┼──────────┤
│  ☐   │ capture1.pcap    │ alice        │ ✓ OK   │ 10:30  │ 1,234   │ 95%      │ 👁 📥 🗑  │
│  ☐   │ network-test.cap │ bob          │ ✓ OK   │ 09:15  │ 5,678   │ 88%      │ 👁 📥 🗑  │
│  ☐   │ debug.pcap       │ charlie      │ ⚠ Fail │ 08:00  │ N/A     │ N/A      │ 🗑       │
└──────┴──────────────────┴──────────────┴────────┴────────┴─────────┴──────────┴──────────┘
```

**Vue User Normal** (colonne owner CACHÉE) :
```
┌──────┬──────────────────┬────────┬────────┬─────────┬──────────┬──────────┐
│  ☐   │  FICHIER         │ STATUT │  DATE  │ PAQUETS │  SCORE   │ ACTIONS  │
├──────┼──────────────────┼────────┼────────┼─────────┼──────────┼──────────┤
│  ☐   │ my_capture.pcap  │ ✓ OK   │ 10:30  │ 1,234   │ 95%      │ 👁 📥 🗑  │
│  ☐   │ test-network.cap │ ✓ OK   │ 09:15  │ 5,678   │ 88%      │ 👁 📥 🗑  │
└──────┴──────────────────┴────────┴────────┴─────────┴──────────┴──────────┘
```

## 📝 Notes Techniques

- **LEFT JOIN** utilisé (pas INNER) pour supporter les tâches orphelines (owner supprimé)
- Si owner supprimé : afficher "Unknown" au lieu de crash
- Performance : OK car index sur `users.id` et limite de 50 tâches
- Security : Pas de fuite d'info (users voient toujours que leurs propres tâches)

---

**Status**: ⏳ Ready for Implementation
**Priority**: Medium
**Complexity**: Low (10 files, straightforward changes)
**Version Target**: v5.2.0
