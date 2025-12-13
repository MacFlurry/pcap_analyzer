# Guide Rapide - Classes CSS Modernes (Page Historique)

## Table des Classes

### 1. Table et Structure

| Classe | Usage | Caractéristiques |
|--------|-------|------------------|
| `.history-table` | Table principale | Border-spacing 12px, separate borders |
| `.history-card` | Container de la table | Padding 2rem, gradient background |

**Exemple :**
```html
<div class="history-card">
    <table class="history-table">
        <!-- content -->
    </table>
</div>
```

---

### 2. Checkboxes

| Classe | Taille | Features |
|--------|--------|----------|
| `.checkbox-modern` | 22x22px | Gradient au checked, glow effect, checkmark icon |

**Code :**
```html
<input type="checkbox" class="checkbox-modern">
```

**États :**
- Default: Border gris, background blanc
- Hover: Border bleu, scale 1.1, glow
- Checked: Gradient bleu, shadow, checkmark

---

### 3. Badges de Statut

| Classe | Couleur | Animation |
|--------|---------|-----------|
| `.badge-modern.badge-pending` | Gris | - |
| `.badge-modern.badge-processing` | Bleu | Pulse (2s) |
| `.badge-modern.badge-completed` | Vert | - |
| `.badge-modern.badge-failed` | Rouge | - |
| `.badge-modern.badge-expired` | Orange | - |

**Code :**
```html
<span class="badge-modern badge-completed">
    <i class="fas fa-check-circle"></i>
    <span>Terminé</span>
</span>
```

**Propriétés communes :**
- Padding: 10px 18px
- Border-radius: 10px
- Font-weight: 600
- Box-shadow: douce
- Hover: translateY(-1px)

---

### 4. Score de Santé

| Classe | Score | Couleur |
|--------|-------|---------|
| `.score-excellent` | ≥80 | Vert (#10b981) |
| `.score-good` | ≥60 | Jaune (#fbbf24) |
| `.score-warning` | ≥40 | Orange (#fb923c) |
| `.score-critical` | <40 | Rouge (#ef4444) |

**Structure :**
```html
<div class="score-display">
    <div class="score-bar-container">
        <div class="score-bar-fill score-excellent" style="width: 85%"></div>
    </div>
    <span class="score-value score-excellent">85</span>
</div>
```

**Composants :**
- `.score-display`: Flexbox container (gap 12px)
- `.score-bar-container`: Barre background (120x10px)
- `.score-bar-fill`: Fill avec gradient + shimmer animation
- `.score-value`: Valeur numérique (1.125rem, bold)

---

### 5. Boutons d'Actions

| Classe | Couleur | Usage |
|--------|---------|-------|
| `.action-btn.btn-view` | Bleu | Voir le rapport |
| `.action-btn.btn-progress` | Violet | Voir la progression |
| `.action-btn.btn-download` | Vert | Télécharger JSON |
| `.action-btn.btn-delete` | Rouge | Supprimer |

**Code :**
```html
<a href="/report" class="action-btn btn-view" title="Voir le rapport">
    <i class="fas fa-eye"></i>
</a>
```

**Propriétés :**
- Taille: 42x42px
- Border-radius: 10px
- Transition: 0.2s cubic-bezier
- Hover: translateY(-3px) scale(1.05)
- Tooltip: CSS pure (::after et ::before)

**Hover States :**
```css
/* Exemple btn-view */
.action-btn.btn-view:hover {
    background: linear-gradient(135deg, #3498db, #60a5fa);
    color: white;
    box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
}
```

---

## Animations

### Shimmer (Barre de score)
```css
@keyframes shimmer {
    from { transform: translateX(-100%); }
    to { transform: translateX(100%); }
}
```
**Durée :** 2s infinite

### Pulse (Badge processing)
```css
@keyframes pulse-processing {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.85; transform: scale(1.02); }
}
```
**Durée :** 2s ease-in-out infinite

### Tooltip Fade-in
```css
@keyframes tooltip-fade-in {
    from { opacity: 0; transform: translateX(-50%) translateY(4px); }
    to { opacity: 1; transform: translateX(-50%) translateY(0); }
}
```
**Durée :** 0.2s ease

---

## Hover Effects

### Ligne de table (tr)
```css
.history-table tbody tr:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(52, 152, 219, 0.15);
    background: #fafbfc;
}

/* Bande bleue gauche */
.history-table tbody tr:hover::before {
    background: linear-gradient(180deg, #3498db, #60a5fa);
}
```

### Badge
```css
.badge-modern:hover {
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.12);
}
```

### Checkbox
```css
.checkbox-modern:hover {
    border-color: #3498db;
    transform: scale(1.1);
    box-shadow: 0 0 0 4px rgba(52, 152, 219, 0.1);
}
```

---

## Gradients

### Backgrounds
```css
/* Card */
.history-card {
    background: linear-gradient(135deg, #ffffff 0%, #f9fafb 100%);
}

/* Dark mode */
.dark .history-card {
    background: linear-gradient(135deg, #1f2937 0%, #111827 100%);
}
```

### Badges
```css
/* Completed */
background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);

/* Processing */
background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);

/* Failed */
background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
```

### Scores
```css
/* Excellent */
background: linear-gradient(90deg, #10b981 0%, #059669 100%);

/* Good */
background: linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%);

/* Warning */
background: linear-gradient(90deg, #fb923c 0%, #f97316 100%);

/* Critical */
background: linear-gradient(90deg, #ef4444 0%, #dc2626 100%);
```

---

## Dark Mode

### Principes
1. **Inversion des gradients** : Light → Dark, Dark → Light
2. **Box-shadows** : Plus prononcées (opacity +0.1-0.2)
3. **Borders** : Plus visibles (#4b5563 vs #d1d5db)
4. **Text** : #f3f4f6 vs #1f2937

### Exemples
```css
/* Checkbox */
.dark .checkbox-modern {
    border-color: #475569;
    background: #1f2937;
}

.dark .checkbox-modern:checked {
    background: linear-gradient(135deg, #60a5fa, #3498db);
    box-shadow: 0 4px 12px rgba(96, 165, 250, 0.5);
}

/* Table row */
.dark .history-table tbody tr {
    background: #1f2937;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.3);
}

.dark .history-table tbody tr:hover {
    background: #374151;
    box-shadow: 0 8px 24px rgba(96, 165, 250, 0.2);
}
```

---

## Responsive

### Breakpoint 1024px (Tablet)
```css
.history-table th, .history-table td {
    padding: 16px;  /* vs 20-24px */
    font-size: 0.875rem;  /* vs 0.9375rem */
}

.score-bar-container {
    width: 80px;  /* vs 120px */
}

.action-btn {
    width: 36px; height: 36px;  /* vs 42px */
}
```

### Breakpoint 768px (Mobile)
```css
.history-card {
    padding: 1rem !important;  /* vs 2rem */
}

.history-table {
    border-spacing: 0 8px;  /* vs 12px */
}

.history-table th, .history-table td {
    padding: 12px;  /* vs 16px */
    font-size: 0.8125rem;  /* vs 0.875rem */
}

.badge-modern {
    padding: 8px 14px;  /* vs 10px 18px */
    font-size: 0.75rem;  /* vs 0.875rem */
}
```

---

## Quick Reference: Tailwind Utilities Utilisées

### Spacing
- `space-x-3`: 0.75rem gap horizontal
- `space-x-4`: 1rem gap horizontal
- `gap-3`: 0.75rem gap (flexbox/grid)
- `gap-4`: 1rem gap

### Sizing
- `w-8 h-8`: 2rem x 2rem
- `w-10 h-10`: 2.5rem x 2.5rem
- `w-16`: 4rem width
- `min-w-0`: min-width 0 (pour truncate)

### Typography
- `text-base`: 1rem (16px)
- `text-sm`: 0.875rem (14px)
- `text-xs`: 0.75rem (12px)
- `font-semibold`: 600 weight
- `font-bold`: 700 weight

### Flexbox
- `flex items-center`: Vertical center
- `flex-shrink-0`: No shrink
- `flex-1`: Grow to fill
- `justify-end`: Align right

### Colors
- `text-gray-900 dark:text-white`: Adaptive text
- `bg-gray-100 dark:bg-gray-700`: Adaptive background
- `text-primary`: #3498db

---

## Patterns de Code Communs

### Icône avec background coloré
```html
<div class="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-100 to-blue-200 dark:from-blue-900 dark:to-blue-800 flex items-center justify-center">
    <i class="fas fa-file-alt text-blue-600 dark:text-blue-300"></i>
</div>
```

### Texte principal + métadonnée
```html
<div>
    <p class="font-semibold text-gray-900 dark:text-white text-base">
        Titre principal
    </p>
    <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
        Métadonnée secondaire
    </p>
</div>
```

### Container flex avec icône et texte
```html
<div class="flex items-center space-x-2">
    <i class="fas fa-icon text-gray-400"></i>
    <span>Texte</span>
</div>
```

### Groupe de boutons actions
```html
<div class="flex items-center justify-end space-x-4">
    <a href="#" class="action-btn btn-view" title="Voir">
        <i class="fas fa-eye"></i>
    </a>
    <a href="#" class="action-btn btn-download" title="Télécharger">
        <i class="fas fa-download"></i>
    </a>
    <button class="action-btn btn-delete" title="Supprimer">
        <i class="fas fa-trash"></i>
    </button>
</div>
```

---

## Debugging Tips

### 1. Vérifier le dark mode
```javascript
// Dans la console
document.documentElement.classList.contains('dark')
```

### 2. Inspecter les transitions
```css
/* Temporairement désactiver */
* { transition: none !important; }
```

### 3. Voir les box-shadows
```css
/* Augmenter pour debug */
box-shadow: 0 0 0 2px red;
```

### 4. Tester le responsive
```javascript
// Simuler mobile
document.body.style.width = '375px';
```

---

## Performance Checklist

- [ ] Transitions sur `transform` et `opacity` uniquement
- [ ] Pas d'animations sur `width`, `height`, `top`, `left`
- [ ] Box-shadows légères (blur max 24px)
- [ ] Gradients avec max 2 couleurs
- [ ] Animations avec `will-change` si nécessaire
- [ ] Media queries groupées en fin de fichier

---

## Ressources

### Font Awesome Icons utilisées
- `fa-file-alt`: Fichiers
- `fa-check-circle`: Succès/Completed
- `fa-times-circle`: Erreur/Failed
- `fa-clock`: Temps/Date
- `fa-network-wired`: Réseau/Paquets
- `fa-heartbeat`: Santé/Score
- `fa-eye`: Voir
- `fa-download`: Télécharger
- `fa-trash`: Supprimer
- `fa-chart-line`: Progression

### Couleurs de base
```css
:root {
    --primary: #3498db;
    --primary-light: #60a5fa;
    --success: #10b981;
    --danger: #ef4444;
    --warning: #fb923c;
    --gray-100: #f3f4f6;
    --gray-900: #111827;
}
```

---

**Note :** Ce guide couvre toutes les classes spécifiques à la page d'historique. Les classes Tailwind standards restent disponibles et peuvent être combinées avec ces classes custom.
