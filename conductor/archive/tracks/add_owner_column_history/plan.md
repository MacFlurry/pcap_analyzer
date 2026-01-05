# Plan: Add Owner Column in History View for Admins

**Objectif**: Ajouter une colonne "PROPRIÉTAIRE" dans l'historique pour que les admins puissent voir d'un coup d'œil à qui appartient chaque PCAP

**Type**: Feature Enhancement (Admin UX)
**Priorité**: Moyenne
**Statut**: Proposition initiale

---

## Contexte

### Fonctionnalité Actuelle

Le mode multi-tenant fonctionne correctement :
- **User normal** : Voit UNIQUEMENT ses propres uploads (`owner_id` filtré)
- **Admin** : Voit TOUS les uploads (pas de filtre `owner_id`)

**Problème UX** :
- L'admin voit tous les PCAPs mais ne sait pas d'un coup d'œil à qui chaque fichier appartient
- Les données `owner_id` (UUID) sont retournées par l'API mais pas affichées
- Difficile de gérer/auditer les uploads des différents utilisateurs

### Solution Proposée

Ajouter une colonne **"PROPRIÉTAIRE"** dans la vue historique :
- **Visible UNIQUEMENT pour les admins**
- Affiche le `username` du propriétaire (pas l'UUID)
- Positionnée entre la colonne "FICHIER" et "STATUT"

---

## Phase 1: Backend - Enrichissement de l'API

### Tâche 1.1: Modifier TaskInfo Schema
[~]
**Ligne**: 47-72 (classe TaskInfo)

**Changement**:

```python
class TaskInfo(BaseModel):
    """Informations sur une tâche (pour historique)"""

    task_id: str
    filename: str
    status: TaskStatus
    uploaded_at: datetime
    analyzed_at: Optional[datetime] = None
    file_size_bytes: int
    total_packets: Optional[int] = None
    health_score: Optional[float] = None
    report_html_url: Optional[str] = None
    report_json_url: Optional[str] = None
    error_message: Optional[str] = None
    expires_at: Optional[datetime] = None
    owner_id: Optional[str] = None  # User ID (multi-tenant)
    owner_username: Optional[str] = None  # ← NOUVEAU: Username du propriétaire (pour admins)
```

**SHA Commit**: `[ ]`

---

### Tâche 1.2: Modifier get_recent_tasks pour JOIN avec users
[~]
**Ligne**: 253-314 (fonction `get_recent_tasks`)

**Changement**:

**AVANT** (ligne 280-290):
```python
query, params = self.pool.translate_query(
    """
    SELECT task_id, filename, status, uploaded_at, analyzed_at,
           file_size_bytes, total_packets, health_score,
           report_html_path, report_json_path, error_message, owner_id
    FROM tasks
    ORDER BY uploaded_at DESC
    LIMIT ?
    """,
    (limit,),
)
```

**APRÈS**:
```python
query, params = self.pool.translate_query(
    """
    SELECT t.task_id, t.filename, t.status, t.uploaded_at, t.analyzed_at,
           t.file_size_bytes, t.total_packets, t.health_score,
           t.report_html_path, t.report_json_path, t.error_message,
           t.owner_id, u.username as owner_username
    FROM tasks t
    LEFT JOIN users u ON t.owner_id = u.id
    ORDER BY t.uploaded_at DESC
    LIMIT ?
    """,
    (limit,),
)
```

**Même changement pour la requête avec filtre owner_id** (lignes 266-277):

```python
query, params = self.pool.translate_query(
    """
    SELECT t.task_id, t.filename, t.status, t.uploaded_at, t.analyzed_at,
           t.file_size_bytes, t.total_packets, t.health_score,
           t.report_html_path, t.report_json_path, t.error_message,
           t.owner_id, u.username as owner_username
    FROM tasks t
    LEFT JOIN users u ON t.owner_id = u.id
    WHERE t.owner_id = ?
    ORDER BY t.uploaded_at DESC
    LIMIT ?
    """,
    (owner_id, limit),
)
```

**Modifier la construction de TaskInfo** (ligne 310):

**AVANT**:
```python
owner_id=str(row["owner_id"]) if row["owner_id"] else None,
```

**APRÈS**:
```python
owner_id=str(row["owner_id"]) if row["owner_id"] else None,
owner_username=row["owner_username"] if row["owner_username"] else None,  # ← NOUVEAU
```

**Note**: Utiliser LEFT JOIN (pas INNER JOIN) pour supporter les tâches orphelines (owner supprimé)

**SHA Commit**: `[ ]`

---

### Tâche 1.3: Tests Backend

**Fichier**: `tests/integration/test_history_api.py` (nouveau ou augmenter existant)

**Tests à ajouter**:

```python
async def test_admin_get_history_with_owner_username(admin_client, test_users):
    """Admin should see owner_username in task history."""
    # Create task for user1
    user1 = test_users["user1"]
    task_id = await create_test_task(owner_id=user1.id)

    # Admin fetches history
    response = await admin_client.get("/api/history")
    assert response.status_code == 200

    data = response.json()
    assert len(data["tasks"]) >= 1

    # Find the task
    task = next((t for t in data["tasks"] if t["task_id"] == task_id), None)
    assert task is not None

    # Verify owner_username is present
    assert task["owner_username"] == user1.username
    assert task["owner_id"] == str(user1.id)


async def test_user_get_history_with_owner_username(user_client, current_user):
    """Regular user should also see owner_username (their own)."""
    response = await user_client.get("/api/history")
    assert response.status_code == 200

    data = response.json()

    # All tasks should have owner_username = current_user.username
    for task in data["tasks"]:
        assert task["owner_username"] == current_user.username
```

**SHA Commit**: `[ ]`

### Tâche 2.1: Modifier history.html - Ajouter Header Colonne
[x] `fbb14fd`

### Tâche 2.2: Modifier history.js - Détection Admin et Toggle Colonne
[x] `fbb14fd`

### Tâche 2.3: Modifier createRow() pour Ajouter Cellule Owner
[x] `fbb14fd`

### Tâche 2.4: Ajouter Styles CSS pour Colonne Owner
[x] `fbb14fd`

---

## Phase 3: Tests E2E

### Tâche 3.1: Test E2E - Admin Voit Colonne Owner
[x] `dd420bb`

**Fichier**: `tests/e2e/test_history_owner_column.py` (nouveau)

**Test**:

```python
def test_admin_sees_owner_column(page: Page, postgres_db_url, base_url, apply_migrations):
    """Admin should see the OWNER column in history view."""

    # 1. Setup: Create admin and 2 regular users
    admin_username = f"admin_{uuid4().hex[:8]}"
    user1_username = f"user1_{uuid4().hex[:8]}"
    user2_username = f"user2_{uuid4().hex[:8]}"

    password = "Strong-Password-123!"

    admin_json = run_db_action("create_user", postgres_db_url, admin_username,
                                f"{admin_username}@example.com", password, "admin", "true")
    user1_json = run_db_action("create_user", postgres_db_url, user1_username,
                                f"{user1_username}@example.com", password, "user", "true")
    user2_json = run_db_action("create_user", postgres_db_url, user2_username,
                                f"{user2_username}@example.com", password, "user", "true")

    user1_id = json.loads(user1_json)["id"]
    user2_id = json.loads(user2_json)["id"]

    # 2. Create tasks for both users
    task1_id = run_db_action("create_task", postgres_db_url, user1_id, "user1_capture.pcap")
    task2_id = run_db_action("create_task", postgres_db_url, user2_id, "user2_capture.pcap")

    # 3. Login as admin
    page.goto(f"{base_url}/login")
    page.fill("#username", admin_username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/$"))

    # 4. Go to history page
    page.goto(f"{base_url}/history")
    page.wait_for_selector("#history-container:not(.hidden)")

    # 5. Verify OWNER column header is visible
    owner_header = page.locator("#owner-column-header")
    expect(owner_header).to_be_visible()
    expect(owner_header).to_have_text("PROPRIÉTAIRE")

    # 6. Verify owner usernames are displayed
    # Find rows and check owner cells
    rows = page.locator(".history-grid-row")

    # Check that at least one row shows user1_username
    user1_owner_cell = page.locator(f"text={user1_username}").first
    expect(user1_owner_cell).to_be_visible()

    # Check that at least one row shows user2_username
    user2_owner_cell = page.locator(f"text={user2_username}").first
    expect(user2_owner_cell).to_be_visible()


def test_regular_user_does_not_see_owner_column(page: Page, postgres_db_url, base_url, apply_migrations):
    """Regular user should NOT see the OWNER column in history view."""

    # 1. Setup: Create regular user
    username = f"user_{uuid4().hex[:8]}"
    password = "Strong-Password-123!"

    user_json = run_db_action("create_user", postgres_db_url, username,
                               f"{username}@example.com", password, "user", "true")
    user_id = json.loads(user_json)["id"]

    # 2. Create a task
    task_id = run_db_action("create_task", postgres_db_url, user_id, "my_capture.pcap")

    # 3. Login as user
    page.goto(f"{base_url}/login")
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("button[type='submit']")
    page.wait_for_url(re.compile(r"/$"))

    # 4. Go to history page
    page.goto(f"{base_url}/history")
    page.wait_for_selector("#history-container:not(.hidden)")

    # 5. Verify OWNER column header is HIDDEN
    owner_header = page.locator("#owner-column-header")
    expect(owner_header).to_have_class(re.compile(r"hidden"))

    # 6. Verify no owner cells are visible
    owner_cells = page.locator(".grid-cell-owner:not(.hidden)")
    expect(owner_cells).to_have_count(0)
```

**SHA Commit**: `[ ]`

---

## Phase 4: Documentation et Version

### Tâche 4.1: Mettre à Jour CHANGELOG.md
[x] `6d879f4`

### Tâche 4.2: Gestion des Versions (SemVer)
[x] `6d879f4`

### Tâche 4.3: Mettre à Jour README.md
[x] `6d879f4`
**Fichier**: `CHANGELOG.md`
**Section**: `## [Unreleased]` (ou nouvelle version)

**Ajout**:

```markdown
## [Unreleased]

### Enhancements
- **UI Admin**: Added "PROPRIÉTAIRE" (Owner) column in history view for administrators
  - Admins can now see at a glance which user owns each PCAP file
  - Column displays username of the file owner
  - Only visible for admin users (hidden for regular users)
  - Backend enriched with LEFT JOIN to users table for owner_username
```

**SHA Commit**: `[ ]`

---

### Tâche 4.2: Gestion des Versions (SemVer)
[~]

**IMPORTANT** : Conductor doit décider de la version selon SemVer :

**Règles SemVer** :
- **Patch (x.x.PATCH)** : Bug fixes uniquement
- **Minor (x.MINOR.x)** : Nouvelles fonctionnalités (backward compatible)
- **Major (MAJOR.x.x)** : Breaking changes

**Recommandation pour cette feature** :
- Type : **Enhancement (nouvelle fonctionnalité UI pour admins)**
- Impact : **Minor** (pas de breaking change, feature additive)
- Version suggérée : **v5.2.0** (si version actuelle = v5.1.0)

**Fichier à modifier** : `src/__version__.py`

**AVANT**:
```python
__version__ = "5.1.0"
```

**APRÈS**:
```python
__version__ = "5.2.0"
```

**Autres fichiers à synchroniser** :
- `helm-chart/pcap-analyzer/Chart.yaml` (appVersion)
- `helm-chart/pcap-analyzer/values.yaml` (image.tag)
- `pyproject.toml` (si présent)

**SHA Commit**: `[ ]`

---

### Tâche 4.3: Mettre à Jour README.md
[~]

**Fichier**: `README.md`
**Section**: Features ou Admin Features

**Ajout** (si section admin features existe):

```markdown
### Admin Features
- **User Management**: Approve/reject, activate/deactivate, reset passwords
- **Multi-Tenant Visibility**: View all users' uploads with owner identification
- **Owner Column in History**: See which user owns each PCAP file at a glance ← NOUVEAU
- **Bulk Actions**: Approve, delete, or manage multiple users at once
```

**SHA Commit**: `[ ]`

---

## Critères de Succès

### Backend
- [ ] `TaskInfo` schema a le champ `owner_username`
- [ ] `get_recent_tasks()` fait un LEFT JOIN avec `users` table
- [ ] `owner_username` est correctement retourné par `/api/history`
- [ ] Tests backend passent (admin et user voir owner_username)

### Frontend
- [ ] Colonne "PROPRIÉTAIRE" visible dans le header pour admins
- [ ] Colonne "PROPRIÉTAIRE" CACHÉE pour users normaux
- [ ] Username du propriétaire affiché correctement pour chaque tâche
- [ ] Styles CSS cohérents avec le design existant
- [ ] Responsive design préservé

### Tests
- [ ] Test E2E: Admin voit colonne owner avec usernames corrects
- [ ] Test E2E: User normal ne voit PAS la colonne owner
- [ ] Tous les tests existants passent (non-régression)

### Documentation
- [ ] CHANGELOG.md mis à jour
- [ ] README.md mis à jour (si nécessaire)
- [ ] Version bump selon SemVer (probablement v5.2.0)
- [ ] Helm chart appVersion synchronisée

---

## Notes d'Implémentation

1. **LEFT JOIN vs INNER JOIN** :
   - Utiliser LEFT JOIN pour supporter les tâches orphelines (owner supprimé)
   - Si owner supprimé, afficher "Utilisateur supprimé" ou "Unknown"

2. **Performance** :
   - LEFT JOIN sur `users` table devrait être performant (index sur `id`)
   - Pas de pagination actuellement (limit 50), acceptable

3. **Security** :
   - Pas de fuite d'information : users normaux ne voient toujours que leurs propres tâches
   - Admin voit username mais pas de données sensibles (email, etc.)

4. **UX** :
   - Colonne positionnée après FICHIER pour logique visuelle
   - Icône user (<i class="fas fa-user">) pour cohérence design
   - Pas de tri/filtre sur cette colonne pour l'instant (feature future possible)

---

## Résumé des Changements

| Type | Fichier | Description |
|------|---------|-------------|
| Schema | `app/models/schemas.py` | Ajouter `owner_username` à TaskInfo |
| Backend | `app/services/database.py` | LEFT JOIN avec users, retourner owner_username |
| Frontend HTML | `app/templates/history.html` | Ajouter header colonne PROPRIÉTAIRE |
| Frontend JS | `app/static/js/history.js` | Détecter admin, toggle colonne, afficher owner cell |
| Styles | `app/static/css/style.css` | Styles pour grid-cell-owner |
| Tests | `tests/e2e/test_history_owner_column.py` | Tests E2E admin/user |
| Tests | `tests/integration/test_history_api.py` | Tests API backend |
| Docs | `CHANGELOG.md` | Feature documentation |
| Docs | `README.md` | Update admin features |
| Version | `src/__version__.py` | Bump to v5.2.0 (recommandé) |

**Total** : 10 fichiers modifiés/créés

---

**Prêt pour implémentation par Conductor** ✓
