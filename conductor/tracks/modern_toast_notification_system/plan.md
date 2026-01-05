# Plan d'Implémentation: Modern Toast Notification System

**Objectif**: Créer un système de notifications toast moderne pour remplacer les alerts JavaScript génériques.

**Version cible**: v5.3.0 (MINOR)

**Estimation**: 2 phases, ~3-4 heures

---

## Contexte

**Problème actuel**:
- L'utilisateur mentionne "je n'ai pas ce popup"
- Pas de système de notification unifié dans l'application
- Probablement des `alert()` JavaScript basiques (bloquants, moches, pas modern

es)
- Pas de feedback visuel cohérent pour les actions utilisateur

**Impact utilisateur**:
- Expérience utilisateur dégradée
- Pas de confirmation visuelle après actions (upload, delete, etc.)
- Interface semble datée

---

## Architecture Proposée

### 1. Toast Manager (JavaScript Class)

**Fichier**: `app/static/js/toast.js`

**Structure**:
```javascript
class ToastManager {
    constructor() {
        this.container = null;
        this.toasts = [];
        this.maxToasts = 5;
        this.init();
    }

    init() {
        // Find or create toast container
        this.container = document.getElementById('toast-container');
    }

    success(message, options = {}) {
        return this.show('success', message, options);
    }

    error(message, options = {}) {
        return this.show('error', message, options);
    }

    warning(message, options = {}) {
        return this.show('warning', message, options);
    }

    info(message, options = {}) {
        return this.show('info', message, options);
    }

    show(type, message, options = {}) {
        // Create toast element
        // Add to DOM
        // Animate entrance
        // Setup auto-dismiss
        // Return toast ID for manual control
    }

    dismiss(toastId) {
        // Animate exit
        // Remove from DOM
    }
}

// Global instance
window.toast = new ToastManager();
```

### 2. HTML Structure

**Fichier**: `app/templates/components/toast_container.html`

```html
<!-- Toast Container (fixed top-right) -->
<div id="toast-container"
     class="fixed top-4 right-4 z-[9999] flex flex-col gap-3 pointer-events-none"
     role="status"
     aria-live="polite"
     aria-atomic="false">
    <!-- Toasts will be dynamically inserted here -->
</div>
```

**Toast Card Template** (créé dynamiquement en JS):
```html
<div class="toast pointer-events-auto bg-white dark:bg-gray-800 rounded-lg shadow-lg border-l-4 border-{color}-500 max-w-sm w-full overflow-hidden transform transition-all duration-300 ease-out"
     role="alert"
     aria-live="assertive">
    <div class="p-4">
        <div class="flex items-start">
            <div class="flex-shrink-0">
                <!-- Icon SVG -->
            </div>
            <div class="ml-3 flex-1">
                <p class="text-sm font-medium text-gray-900 dark:text-white">
                    {message}
                </p>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {secondary text - optional}
                </p>
            </div>
            <button class="ml-4 flex-shrink-0 rounded-md inline-flex text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-{color}-500">
                <span class="sr-only">Close</span>
                <!-- Close icon SVG -->
            </button>
        </div>
    </div>
    <!-- Progress bar for auto-dismiss -->
    <div class="h-1 bg-{color}-200 dark:bg-{color}-800">
        <div class="h-full bg-{color}-500 transition-all ease-linear"
             style="width: 100%; transition-duration: {timeout}ms"></div>
    </div>
</div>
```

---

## Phase 1: Core Toast System

### Tâche 1.1: Créer le Toast Manager

**Fichier**: `app/static/js/toast.js`

**Code complet**:
```javascript
/**
 * Modern Toast Notification System
 *
 * Usage:
 *   toast.success("File uploaded successfully!");
 *   toast.error("Failed to delete item");
 *   toast.warning("Low disk space");
 *   toast.info("Update available");
 */

class ToastManager {
    constructor() {
        this.container = null;
        this.toasts = new Map(); // Map<toastId, element>
        this.maxToasts = 5;
        this.defaultTimeout = {
            success: 3000,
            info: 5000,
            warning: 6000,
            error: 7000
        };
        this.init();
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this._setupContainer());
        } else {
            this._setupContainer();
        }
    }

    _setupContainer() {
        this.container = document.getElementById('toast-container');
        if (!this.container) {
            console.error('Toast container not found in DOM');
        }
    }

    /**
     * Show a success toast
     */
    success(message, options = {}) {
        return this.show('success', message, options);
    }

    /**
     * Show an error toast
     */
    error(message, options = {}) {
        return this.show('error', message, options);
    }

    /**
     * Show a warning toast
     */
    warning(message, options = {}) {
        return this.show('warning', message, options);
    }

    /**
     * Show an info toast
     */
    info(message, options = {}) {
        return this.show('info', message, options);
    }

    /**
     * Show a toast notification
     *
     * @param {string} type - 'success', 'error', 'warning', 'info'
     * @param {string} message - Main message text
     * @param {object} options - { secondary, timeout, persistent }
     */
    show(type, message, options = {}) {
        if (!this.container) {
            console.error('Toast container not initialized');
            return null;
        }

        // Limit number of toasts
        if (this.toasts.size >= this.maxToasts) {
            const oldestId = Array.from(this.toasts.keys())[0];
            this.dismiss(oldestId);
        }

        const toastId = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const timeout = options.timeout || this.defaultTimeout[type];
        const persistent = options.persistent || false;

        const toastElement = this._createToastElement(toastId, type, message, options.secondary, timeout);

        // Store toast
        this.toasts.set(toastId, toastElement);

        // Add to DOM
        this.container.appendChild(toastElement);

        // Trigger entrance animation
        requestAnimationFrame(() => {
            toastElement.classList.remove('translate-x-full', 'opacity-0');
            toastElement.classList.add('translate-x-0', 'opacity-100');
        });

        // Setup auto-dismiss (unless persistent)
        if (!persistent) {
            // Start progress bar animation
            const progressBar = toastElement.querySelector('.toast-progress-bar');
            if (progressBar) {
                requestAnimationFrame(() => {
                    progressBar.style.width = '0%';
                });
            }

            // Auto-dismiss after timeout
            setTimeout(() => {
                this.dismiss(toastId);
            }, timeout);
        }

        return toastId;
    }

    /**
     * Dismiss a toast by ID
     */
    dismiss(toastId) {
        const toastElement = this.toasts.get(toastId);
        if (!toastElement) return;

        // Trigger exit animation
        toastElement.classList.remove('translate-x-0', 'opacity-100');
        toastElement.classList.add('translate-x-full', 'opacity-0');

        // Remove from DOM after animation
        setTimeout(() => {
            if (toastElement.parentNode) {
                toastElement.parentNode.removeChild(toastElement);
            }
            this.toasts.delete(toastId);
        }, 200); // Match transition duration
    }

    /**
     * Dismiss all toasts
     */
    dismissAll() {
        Array.from(this.toasts.keys()).forEach(id => this.dismiss(id));
    }

    /**
     * Create toast DOM element
     */
    _createToastElement(toastId, type, message, secondary, timeout) {
        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = `toast pointer-events-auto bg-white dark:bg-gray-800 rounded-lg shadow-lg border-l-4 max-w-sm w-full overflow-hidden transform transition-all duration-300 ease-out translate-x-full opacity-0 ${this._getTypeClasses(type)}`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');

        const icon = this._getIcon(type);
        const colors = this._getColors(type);

        toast.innerHTML = `
            <div class="p-4">
                <div class="flex items-start">
                    <div class="flex-shrink-0">
                        ${icon}
                    </div>
                    <div class="ml-3 flex-1">
                        <p class="text-sm font-medium text-gray-900 dark:text-white">
                            ${this._escapeHtml(message)}
                        </p>
                        ${secondary ? `<p class="text-xs text-gray-500 dark:text-gray-400 mt-1">${this._escapeHtml(secondary)}</p>` : ''}
                    </div>
                    <button type="button"
                            class="toast-close ml-4 flex-shrink-0 rounded-md inline-flex text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 focus:outline-none focus:ring-2 focus:ring-offset-2 ${colors.focusRing}"
                            aria-label="Close notification">
                        <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
            </div>
            <div class="h-1 ${colors.progressBg}">
                <div class="toast-progress-bar h-full ${colors.progress} transition-all ease-linear"
                     style="width: 100%; transition-duration: ${timeout}ms"></div>
            </div>
        `;

        // Attach close button event
        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => this.dismiss(toastId));

        // Keyboard accessibility (Escape to close)
        toast.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.dismiss(toastId);
            }
        });

        return toast;
    }

    _getTypeClasses(type) {
        const classes = {
            success: 'border-green-500',
            error: 'border-red-500',
            warning: 'border-yellow-500',
            info: 'border-blue-500'
        };
        return classes[type] || classes.info;
    }

    _getColors(type) {
        const colors = {
            success: {
                icon: 'text-green-500',
                progress: 'bg-green-500',
                progressBg: 'bg-green-200 dark:bg-green-800',
                focusRing: 'focus:ring-green-500'
            },
            error: {
                icon: 'text-red-500',
                progress: 'bg-red-500',
                progressBg: 'bg-red-200 dark:bg-red-800',
                focusRing: 'focus:ring-red-500'
            },
            warning: {
                icon: 'text-yellow-500',
                progress: 'bg-yellow-500',
                progressBg: 'bg-yellow-200 dark:bg-yellow-800',
                focusRing: 'focus:ring-yellow-500'
            },
            info: {
                icon: 'text-blue-500',
                progress: 'bg-blue-500',
                progressBg: 'bg-blue-200 dark:bg-blue-800',
                focusRing: 'focus:ring-blue-500'
            }
        };
        return colors[type] || colors.info;
    }

    _getIcon(type) {
        const colors = this._getColors(type);
        const icons = {
            success: `<svg class="h-6 w-6 ${colors.icon}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>`,
            error: `<svg class="h-6 w-6 ${colors.icon}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>`,
            warning: `<svg class="h-6 w-6 ${colors.icon}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>`,
            info: `<svg class="h-6 w-6 ${colors.icon}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>`
        };
        return icons[type] || icons.info;
    }

    _escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize global toast instance
if (typeof window !== 'undefined') {
    window.toast = new ToastManager();
}
```

---

### Tâche 1.2: Créer le HTML container

**Fichier**: `app/templates/components/toast_container.html`

**Code**:
```html
<!-- Toast Notification Container -->
<div id="toast-container"
     class="fixed top-4 right-4 z-[9999] flex flex-col gap-3 pointer-events-none max-w-sm"
     role="status"
     aria-live="polite"
     aria-atomic="false">
    <!-- Toasts will be dynamically inserted here by ToastManager -->
</div>
```

---

### Tâche 1.3: Inclure dans `base.html`

**Fichier**: `app/templates/base.html`

**Modifications**:

1. **Ajouter le container** (avant `</body>`):
```html
    {% include 'components/toast_container.html' %}

    </body>
</html>
```

2. **Ajouter le script toast.js** (dans `<head>` ou avant `</body>`):
```html
<script src="{{ url_for('static', path='/js/toast.js') }}"></script>
```

---

## Phase 2: Integration & Remplacement des Alerts

### Tâche 2.1: Remplacer alerts dans `upload.js`

**Fichier**: `app/static/js/upload.js`

**Avant**:
```javascript
// Vieux code (supposé)
alert("File uploaded successfully!");
alert("Error uploading file");
```

**Après**:
```javascript
// Upload success
toast.success("Fichier uploadé avec succès !", {
    secondary: `${filename} - Analyse en cours...`
});

// Upload error
toast.error("Échec de l'upload", {
    secondary: error.message,
    timeout: 7000  // Longer for errors
});

// Upload started
toast.info("Upload en cours...", {
    secondary: "Veuillez patienter"
});
```

---

### Tâche 2.2: Remplacer alerts dans `history.js`

**Fichier**: `app/static/js/history.js`

**Exemples**:
```javascript
// Delete success
toast.success("Fichier supprimé", {
    secondary: "1 fichier supprimé de l'historique"
});

// Bulk delete
toast.success("Fichiers supprimés", {
    secondary: `${count} fichiers supprimés`
});

// Delete error
toast.error("Échec de la suppression", {
    secondary: "Veuillez réessayer"
});
```

---

### Tâche 2.3: Remplacer alerts dans `profile.js`

**Fichier**: `app/static/js/profile.js`

**Exemples**:
```javascript
// Password changed
toast.success("Mot de passe modifié", {
    secondary: "Votre mot de passe a été mis à jour"
});

// 2FA enabled
toast.success("Authentification 2FA activée", {
    secondary: "Votre compte est maintenant plus sécurisé"
});

// Settings saved
toast.success("Paramètres enregistrés");
```

---

### Tâche 2.4: Remplacer alerts dans `admin.js`

**Fichier**: `app/static/js/admin.js`

**Exemples**:
```javascript
// User approved
toast.success("Utilisateur approuvé", {
    secondary: username
});

// User deleted
toast.success("Utilisateur supprimé", {
    secondary: `${username} a été supprimé`
});

// Bulk action
toast.success("Action groupée effectuée", {
    secondary: `${count} utilisateurs modifiés`
});

// Admin action error
toast.error("Action refusée", {
    secondary: "Permissions insuffisantes"
});
```

---

## Phase 3: Tests & Deployment

### Tâche 3.1: Tests E2E avec Playwright

**Fichier**: `tests/e2e/test_toast_notifications.py`

**Code**:
```python
import pytest
import re
from playwright.sync_api import Page, expect

def test_toast_appears_on_upload_success(page: Page, auth_token: str):
    """Toast should appear when file is uploaded successfully"""
    page.goto("/upload")

    # Upload a file
    # ... (upload logic)

    # Check toast appears
    toast = page.locator('.toast').first
    expect(toast).to_be_visible()
    expect(toast).to_contain_text("succès")  # Contains "succès"

    # Check it has success styling
    expect(toast).to_have_class(re.compile(r'border-green-500'))

def test_toast_auto_dismisses(page: Page, auth_token: str):
    """Toast should auto-dismiss after timeout"""
    page.goto("/upload")

    # Trigger a toast
    page.evaluate("toast.success('Test message')")

    # Toast visible immediately
    toast = page.locator('.toast').first
    expect(toast).to_be_visible()

    # Wait for auto-dismiss (default 3s for success)
    page.wait_for_timeout(3500)

    # Toast should be gone
    expect(toast).to_be_hidden()

def test_toast_manual_close(page: Page):
    """Toast close button should dismiss immediately"""
    page.goto("/")

    # Trigger a toast
    page.evaluate("toast.info('Test message', { timeout: 10000 })")  # Long timeout

    toast = page.locator('.toast').first
    expect(toast).to_be_visible()

    # Click close button
    close_btn = toast.locator('.toast-close')
    close_btn.click()

    # Toast should disappear quickly
    page.wait_for_timeout(300)
    expect(toast).to_be_hidden()

def test_toast_stacking(page: Page):
    """Multiple toasts should stack vertically"""
    page.goto("/")

    # Trigger 3 toasts
    page.evaluate("""
        toast.success('Message 1');
        toast.warning('Message 2');
        toast.error('Message 3');
    """)

    toasts = page.locator('.toast')
    expect(toasts).to_have_count(3)

    # All should be visible
    for i in range(3):
        expect(toasts.nth(i)).to_be_visible()

def test_toast_dark_mode(page: Page):
    """Toast should render correctly in dark mode"""
    page.goto("/")

    # Enable dark mode
    page.evaluate("document.documentElement.classList.add('dark')")

    # Trigger toast
    page.evaluate("toast.error('Dark mode test')")

    toast = page.locator('.toast').first
    expect(toast).to_be_visible()

    # Check dark mode classes applied
    expect(toast).to_have_class(re.compile(r'dark:bg-gray-800'))

def test_toast_accessibility_aria(page: Page):
    """Toast should have proper ARIA attributes"""
    page.goto("/")

    page.evaluate("toast.error('Accessibility test')")

    toast = page.locator('.toast').first

    # Check ARIA attributes
    expect(toast).to_have_attribute('role', 'alert')
    expect(toast).to_have_attribute('aria-live', 'assertive')  # Error = assertive

def test_toast_keyboard_navigation(page: Page):
    """Escape key should close toast"""
    page.goto("/")

    page.evaluate("toast.info('Keyboard test')")

    toast = page.locator('.toast').first
    expect(toast).to_be_visible()

    # Press Escape
    toast.press('Escape')

    # Toast should close
    page.wait_for_timeout(300)
    expect(toast).to_be_hidden()
```

---

### Tâche 3.2: Tests manuels

**Procédure**:
1. **Test Success Toast**:
   - Upload un fichier → Toast vert avec checkmark apparaît
   - Auto-dismiss après 3s
   - Cliquer sur X ferme immédiatement

2. **Test Error Toast**:
   - Trigger une erreur (upload fichier invalide) → Toast rouge apparaît
   - Auto-dismiss après 7s (plus long pour erreurs)
   - Message clair

3. **Test Stacking**:
   - Déclencher 3-4 toasts rapidement (upload plusieurs fichiers)
   - Toasts s'empilent verticalement avec gap
   - Nouveaux toasts en haut

4. **Test Dark Mode**:
   - Activer dark mode
   - Déclencher un toast → Couleurs dark mode correctes

5. **Test Animations**:
   - Toast slide-in depuis la droite (smooth)
   - Progress bar se remplit de 100% → 0%
   - Toast slide-out en fermant

6. **Test Responsive**:
   - Tester sur mobile (toast adapte sa largeur)
   - Touch sur bouton close fonctionne

---

### Tâche 3.3: Synchroniser les versions

1. **`src/__version__.py`**
   ```python
   __version__ = "5.3.0"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.5.0
   appVersion: "5.3.0"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.3.0"
   ```

4. **`CHANGELOG.md`**
   ```markdown
   ## [5.3.0] - 2025-12-27

   ### Added
   - **UI**: Modern toast notification system with slide-in/slide-out animations
   - **UX**: Consistent user feedback for all actions (success, info, warning, error toasts)
   - **Accessibility**: ARIA live regions and keyboard navigation (Escape to close)
   - **Features**: Auto-dismiss with progress bar, manual close button, stacking support for multiple toasts
   - **Design**: Full dark mode support, responsive on mobile

   ### Improved
   - **Notifications**: Replaced generic JavaScript alerts with elegant toast notifications across the entire app
   ```

---

### Tâche 3.4: Build & Deploy

1. **Commit**:
   ```bash
   git add .
   git commit -m "feat(ui) v5.3.0: Add modern toast notification system

   - Created ToastManager class with support for 4 types (success, error, warning, info)
   - Animated slide-in/slide-out with progress bar for auto-dismiss
   - Manual close button and keyboard navigation (Escape)
   - Stacking support for multiple simultaneous toasts
   - Full dark mode compatibility
   - ARIA live regions for screen reader accessibility
   - Replaced all generic alerts with toast notifications across the app
   "
   ```

2. **Build Docker image**:
   ```bash
   docker build -t macflurry/pcap-analyzer:v5.3.0 -t macflurry/pcap-analyzer:latest .
   ```

3. **Deploy** (kind local ou production):
   ```bash
   kind load docker-image macflurry/pcap-analyzer:v5.3.0 --name pcap-analyzer
   helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer --namespace pcap-analyzer
   ```

4. **Verify**:
   ```bash
   kubectl get pods -n pcap-analyzer
   kubectl logs -n pcap-analyzer deployment/pcap-analyzer --tail=50
   ```

---

### Tâche 3.5: Archiver le track

```bash
mv conductor/tracks/modern_toast_notification_system conductor/archive/tracks/
```

**Mettre à jour** `conductor/tracks.md`:
```markdown
## [x] Track: Modern Toast Notification System
*Link: [./conductor/archive/tracks/modern_toast_notification_system/](./conductor/archive/tracks/modern_toast_notification_system/)*
```

---

## Critères de Succès

- [x] ToastManager class fonctionne correctement
- [x] 4 types de toast (success, error, warning, info) fonctionnent
- [x] Animations smooth (slide-in, slide-out, fade)
- [x] Progress bar auto-dismiss fonctionne
- [x] Bouton close manual fonctionne
- [x] Stacking de 3+ toasts fonctionne
- [x] Dark mode rendering correct
- [x] Keyboard navigation (Escape) fonctionne
- [x] ARIA attributes présents et corrects
- [x] Tous les alerts remplacés dans upload/history/profile/admin
- [x] Tests E2E passent
- [x] Tests manuels validés
- [x] Versions synchronisées (5.3.0)
- [x] Déployé en Kubernetes
- [x] Responsive sur mobile

---

## Edge Cases Gérés

| Scénario | Comportement |
|----------|--------------|
| > 5 toasts simultanés | Oldest toast auto-dismissed |
| Toast avec message très long | Overflow handled, max-width respected |
| Toast container pas trouvé | Console error, graceful degradation |
| Spam de toasts rapides | Stacking limité à 5 max |
| Dark mode toggle pendant toast | CSS classes responsive |
| Click close pendant auto-dismiss | Dismiss immédiatement |

---

## Notes d'Implémentation

1. **Performance**: Utiliser `transform` et `opacity` pour animations GPU-accelerated
2. **Z-index**: Container à 9999 pour être au-dessus de tout
3. **Pointer events**: Container `pointer-events-none`, toasts `pointer-events-auto`
4. **Timing**: Success 3s, Info 5s, Warning 6s, Error 7s (configurable)
5. **Mobile**: Toasts full-width sur petits écrans (< 640px)
6. **RTL**: Considérer support RTL si i18n future (mirror animations)

---

**Prêt pour implémentation** ✓

**Estimation temps**: 3-4 heures pour un développeur expérimenté
