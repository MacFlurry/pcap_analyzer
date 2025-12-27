# Plan d'Implémentation: Bouton Annuler dans Modal 2FA

**Objectif**: Ajouter un bouton "Annuler" dans la modal de configuration 2FA pour permettre à l'utilisateur de fermer la modal sans recharger la page.

**Version cible**: v5.2.1 (PATCH)

**Estimation**: 1 phase, ~30 minutes

---

## Contexte Actuel

**Problème identifié**:
- La modal de configuration 2FA (`profile.html` ligne 67-91) affiche :
  - Le QR code pour scanner
  - Le secret manuel
  - Un champ input pour le code de vérification
  - Un bouton "Activer" (submit)

- **Manque** : Aucun bouton pour annuler/fermer la modal
- **Conséquence** : Si l'utilisateur veut reporter l'activation, il doit recharger la page entière → mauvaise UX

**Impact utilisateur**:
- Utilisateur clique par erreur → bloqué dans la modal
- Utilisateur veut y revenir plus tard → doit recharger
- Pas de moyen évident de sortir sans activer

---

## Architecture Proposée

### 1. Frontend (HTML)
**Fichier**: `app/templates/profile.html` (ligne 82-90)

**Modification**: Ajouter un bouton "Annuler" dans le formulaire

**Emplacement**: Après le bouton "Activer", créer une structure avec 2 boutons côte à côte

**Style proposé**:
- Bouton Activer : Primary (bleu) - déjà existant
- Bouton Annuler : Secondary (gris/neutre) - à ajouter

### 2. Frontend (JavaScript)
**Fichier**: `app/static/js/profile.js`

**Logique**:
1. Ajouter un event listener sur le bouton Cancel
2. Au clic, fermer la modal `setup2faModal`
3. Réinitialiser le formulaire (clear input code)
4. Pas d'appel API (juste fermeture UI)

### 3. Tests (Optionnel mais recommandé)
**Fichier**: `tests/e2e/test_2fa_setup.py` (ou créer si n'existe pas)

**Test Case**: Vérifier que le bouton Cancel ferme la modal sans activer 2FA

---

## Phase Unique: Implémentation du Bouton Cancel

### Tâches:

#### **Task 1**: Modifier le HTML de la modal 2FA [x]
**Fichier**: `app/templates/profile.html`

**Action**:
1. Localiser le formulaire `verify-2fa-form` (ligne 82)
2. Remplacer le bouton "Activer" actuel (ligne 87-89) par une structure à 2 boutons
3. Ajouter classes Tailwind pour layout flex horizontal

**Code actuel** (ligne 87-89):
```html
<button type="submit" class="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">
    Activer
</button>
```

**Code proposé**:
```html
<div class="flex space-x-3">
    <button type="button" id="cancel-2fa-setup-btn" class="flex-1 py-2 px-4 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500">
        Annuler
    </button>
    <button type="submit" class="flex-1 py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-primary-dark focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">
        Activer
</button>
</div>
```

**Notes**:
- `type="button"` pour Cancel évite de soumettre le formulaire
- `id="cancel-2fa-setup-btn"` pour cibler en JS
- `flex-1` pour que les 2 boutons prennent la même largeur
- `space-x-3` pour espacement horizontal
- Styles dark mode inclus

---

#### **Task 2**: Ajouter la logique JavaScript [x]
...
#### **Task 5**: Synchroniser les versions [x]
**Fichiers à modifier** (dans l'ordre):

1. **`src/__version__.py`**
   ```python
   __version__ = "5.2.1"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.4.1  # Helm chart version
   appVersion: "5.2.1"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.2.1"
   ```

4. **`CHANGELOG.md`** (ajouter en haut de la section `[Unreleased]` ou créer une nouvelle section):
   ```markdown
   ## [5.2.1] - 2025-12-27

   ### Fixed
   - **UX**: Added "Cancel" button in 2FA setup modal to allow users to close the modal without page reload when postponing activation
   ```

**Validation**:
- [ ] Version dans `__version__.py` = 5.2.1
- [ ] Version Helm Chart = 1.4.1
- [ ] App Version Helm = 5.2.1
- [ ] Image tag = v5.2.1
- [ ] CHANGELOG.md mis à jour avec la date du jour

---

#### **Task 6**: Commit et documentation [x]
**Actions**:
1. Créer un commit avec message clair:
   ```
   fix(ux): add cancel button to 2FA setup modal (v5.2.1)

   - Users can now close the 2FA setup modal without reloading the page
   - Added "Cancel" button next to "Activate" button in profile.html
   - Implemented cancel logic in profile.js to close modal and reset form
   - Updated version to 5.2.1 (PATCH - UX bugfix)
   ```

2. Archiver ce track:
   ```bash
   mv conductor/tracks/add_cancel_button_2fa_modal conductor/archive/tracks/
   ```

3. Mettre à jour `conductor/tracks.md`:
   ```markdown
   ## [x] Track: Add Cancel Button to 2FA Setup Modal
   *Link: [./conductor/archive/tracks/add_cancel_button_2fa_modal/](./conductor/archive/tracks/add_cancel_button_2fa_modal/)*
   ```

---

## Critères de Succès

- [x] Bouton "Annuler" visible dans la modal 2FA setup
- [x] Cliquer sur "Annuler" ferme la modal sans erreur
- [x] Pas d'appel API lors de l'annulation
- [x] Formulaire réinitialisé après annulation
- [x] Peut rouvrir la modal après avoir annulé
- [x] Styles cohérents avec le reste de l'application (primary vs secondary)
- [x] Dark mode fonctionne correctement
- [x] Versions synchronisées (5.2.1)
- [x] CHANGELOG.md mis à jour
- [x] Tests manuels passés

---

## Edge Cases Gérés

| Scénario | Comportement |
|----------|--------------|
| Cliquer Cancel sans entrer de code | Modal se ferme, rien n'est modifié |
| Cliquer Cancel après avoir entré un code | Modal se ferme, code est effacé, 2FA pas activé |
| Rouvrir la modal après Cancel | Fonctionne normalement, nouveau QR généré si besoin |
| Cliquer Cancel puis Activer dans une 2ème tentative | Fonctionne normalement |
| Dark mode activé | Boutons bien stylés avec classes dark: |

---

## Fichiers Modifiés (Résumé)

**Critiques**:
- `app/templates/profile.html` - Ajout bouton Cancel
- `app/static/js/profile.js` - Logique de fermeture modal

**Version Sync**:
- `src/__version__.py`
- `helm-chart/pcap-analyzer/Chart.yaml`
- `helm-chart/pcap-analyzer/values.yaml`
- `CHANGELOG.md`

**Optionnel**:
- `tests/e2e/test_2fa_setup.py` - Test E2E du bouton Cancel

---

## Notes d'Implémentation

1. **Réutiliser les patterns existants**: Ne pas réinventer la logique de fermeture de modal, utiliser le même pattern que les autres modals de l'app

2. **Accessibilité**: Ajouter `aria-label` si nécessaire pour screen readers

3. **Keyboard shortcuts**: Considérer d'ajouter `Escape` key pour fermer la modal (si pas déjà géré globalement)

4. **Style guide**: Vérifier que les couleurs utilisées pour le bouton Cancel correspondent au design system (probablement `bg-white`, `border-gray-300`, `text-gray-700`)

5. **Mobile responsive**: Tester sur petits écrans que les 2 boutons restent lisibles et cliquables (flex-1 devrait gérer ça)

---

**Prêt pour implémentation** ✓

**Estimation temps**: 20-30 minutes pour un développeur connaissant le codebase
