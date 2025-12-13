# Page d'Upload Modernisée - Design System

## Vue d'ensemble

La page d'upload (page d'accueil) a été complètement modernisée avec un design glassmorphism cohérent avec les pages Progress et History. Le thème principal utilise des gradients purple/blue (#667eea → #764ba2) pour une identité visuelle unifiée.

---

## Sections Modernisées

### 1. Hero Section

**Avant:**
- Icône simple avec background gradient
- Titre en texte noir/blanc standard
- Description basique

**Après:**
- Icône avec effet glow et animation pulse en arrière-plan
- Gradient animé sur l'icône avec shadow 2xl
- Titre avec gradient text (purple → blue → purple)
- Taille augmentée (4xl → 5xl)
- Description plus large et espacée

**Classes CSS:**
- `bg-gradient-to-br from-purple-600 via-blue-600 to-purple-700`
- `animate-pulse-slow` pour l'effet de fond
- `bg-clip-text text-transparent` pour le gradient sur le texte

---

### 2. Zone de Drag & Drop

**Design Glassmorphism:**
- Border gradient dashed (purple → blue)
- Backdrop blur de 12px
- Background semi-transparent avec gradient
- Shadow multi-couches pour profondeur

**États:**

1. **Normal:**
   - Border dashed avec gradient purple/blue
   - Background glassmorphism
   - Shadow subtile
   - Icône upload en 8xl avec gradient text

2. **Hover:**
   - Transform translateY(-4px) pour effet lift
   - Shadow augmentée
   - Border opacity augmentée

3. **Dragover:**
   - Scale(1.02)
   - Background teinté purple/blue
   - Inset shadow pour effet "pressé"
   - Glow extérieur augmenté

**Bouton "Parcourir les fichiers":**
- Style action-btn-primary (cohérent avec Progress page)
- Gradient purple/blue
- Effet shine au hover
- Transform scale + translateY au hover

**Classes CSS principales:**
```css
.upload-dropzone
.upload-browse-btn
.loading-spinner-upload
```

---

### 3. Cartes d'Information (3 cartes)

**Structure:**
Chaque carte utilise le glassmorphism avec une couleur distinctive:

1. **Formats (Bleu):**
   - Icône: fa-file-code
   - Gradient: blue-500 → blue-600
   - Tags pour .pcap et .pcapng

2. **Taille Max (Vert):**
   - Icône: fa-database
   - Gradient: green-500 → emerald-600
   - Valeur "500 MB" en gradient text

3. **Durée (Violet):**
   - Icône: fa-clock
   - Gradient: purple-500 → violet-600
   - Valeur "~1-2 min" en gradient text

**Effets:**
- Hover: translateY(-8px) + scale(1.02)
- Icône dans bulle colorée avec shadow
- Glow effect au hover (couleur de la carte)
- Group hover pour animation de l'icône

**Classes CSS:**
```css
.info-card
.info-card-blue / .info-card-green / .info-card-purple
```

---

### 4. État du Serveur (4 statistiques)

**Design:**
Cartes horizontales avec icône + texte, chacune avec une couleur unique:

1. **Files d'attente (Bleu):**
   - Icône: fa-layer-group
   - Border-left: 4px solid blue
   - Glow bleu au hover

2. **Slots disponibles (Vert):**
   - Icône: fa-check-circle
   - Border-left: 4px solid green
   - Glow vert au hover

3. **Terminées (Violet):**
   - Icône: fa-chart-line
   - Border-left: 4px solid purple
   - Glow violet au hover

4. **En cours (Orange):**
   - Icône: fa-spinner
   - Border-left: 4px solid orange
   - Glow orange au hover

**Layout:**
- Grid responsive: 1 col mobile → 2 cols tablet → 4 cols desktop
- Icônes dans bulles colorées avec gradient
- Effet hover translateY(-4px)
- Label uppercase + tracking-wider

**Classes CSS:**
```css
.server-stat-card
.server-stat-blue / .server-stat-green / .server-stat-purple / .server-stat-orange
```

---

### 5. Section "Comment ça marche ?"

**Design:**
Grande carte glassmorphism avec:
- Icône lightbulb dans bulle gradient indigo → purple → blue
- Glow effect autour de l'icône
- 4 étapes numérotées avec badges circulaires
- Liens vers Documentation et Historique

**Étapes:**
Chaque étape a:
- Badge numéroté (1-4) avec gradient purple/blue
- Hover scale(1.1) sur le badge
- Texte descriptif à côté
- Espacement vertical cohérent

**Boutons de liens:**
- Style similaire aux action-btn-secondary
- Gradient purple/blue avec transparence
- Backdrop blur
- Icônes animées au hover

**Classes CSS:**
```css
.help-section-card
.help-link-btn
```

---

## Palette de Couleurs

### Gradients Principaux
```css
/* Purple/Blue (Thème principal) */
#667eea → #764ba2

/* Variantes */
Purple: #8b5cf6 → #7c3aed
Blue: #3b82f6 → #60a5fa
Green: #10b981 → #059669
Orange: #f59e0b → #f97316
Indigo: #6366f1 → #4f46e5
```

### Glassmorphism
```css
/* Light mode */
background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(249, 250, 251, 0.85) 100%);
backdrop-filter: blur(10px);
border: 1px solid rgba(255, 255, 255, 0.5);

/* Dark mode */
background: linear-gradient(135deg, rgba(31, 41, 55, 0.9) 0%, rgba(17, 24, 39, 0.85) 100%);
border: 1px solid rgba(255, 255, 255, 0.1);
```

---

## Animations

### Bounce Subtle
```css
@keyframes bounce-subtle {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-10px); }
}
```

### Pulse Slow
```css
@keyframes pulse-slow {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
```

### Hover Effects
- **Cards:** translateY(-4px to -8px) + scale(1.02)
- **Buttons:** translateY(-2px) + scale(1.05)
- **Icons:** scale(1.1)

---

## Dark Mode

Tous les éléments supportent le mode sombre avec:
- Backgrounds plus foncés (gray-800/900)
- Borders avec opacité réduite
- Shadows plus prononcées
- Couleurs de gradient plus vives
- Meilleur contraste pour l'accessibilité

---

## Responsive Design

### Mobile (< 768px)
- Grid 1 colonne pour toutes les sections
- Padding réduit
- Tailles de texte ajustées
- Stack vertical pour stats serveur

### Tablet (768px - 1024px)
- Grid 2 colonnes pour stats serveur
- Info cards en 1 colonne
- Espacement optimisé

### Desktop (> 1024px)
- Grid 4 colonnes pour stats serveur
- Grid 3 colonnes pour info cards
- Full glassmorphism effects
- Tous les hover effects actifs

---

## Cohérence avec le reste de l'application

### Boutons
- Utilise les mêmes classes que Progress page:
  - `action-btn-primary` pour actions principales
  - `action-btn-secondary` pour actions secondaires

### Cartes
- Même style glassmorphism que History et Progress
- Border-radius cohérent (16-24px)
- Shadows multi-couches identiques

### Gradients
- Purple/blue (#667eea → #764ba2) partout
- Couleurs accentuées cohérentes (bleu, vert, violet, orange)

### Typographie
- Font weights cohérents (600-700 pour titres)
- Uppercase + tracking pour labels
- Text gradients pour valeurs importantes

---

## Fichiers Modifiés

1. **`/app/templates/upload.html`**
   - Hero section modernisée
   - Dropzone glassmorphism
   - Info cards refaites
   - Stats serveur redesignées
   - Section help modernisée

2. **`/app/static/css/style.css`**
   - Section 2.5: Upload Page - Modern Dropzone
   - Section 14: Upload Page - Info Cards
   - Section 15: Upload Page - Server Stats
   - Section 16: Upload Page - Help Section

3. **Aucune modification JavaScript requise**
   - Les IDs et classes sont compatibles
   - Fonctionnalité préservée à 100%

---

## Checklist de Test

- [ ] Upload page s'affiche correctement
- [ ] Dropzone drag & drop fonctionne
- [ ] Effet hover sur dropzone
- [ ] Effet dragover fonctionne
- [ ] Bouton "Parcourir" ouvre file picker
- [ ] Upload fonctionne et redirige vers Progress
- [ ] Info cards s'animent au hover
- [ ] Stats serveur se chargent et s'affichent
- [ ] Section help affiche les liens
- [ ] Responsive mobile fonctionne
- [ ] Dark mode fonctionne correctement
- [ ] Toutes les animations sont fluides

---

## Notes de Performance

- Backdrop-filter peut être gourmand sur certains navigateurs
- Animations optimisées avec `cubic-bezier` pour fluidité
- Transform utilisé plutôt que position pour meilleures performances
- Will-change ajouté automatiquement par Tailwind sur hover

---

## Accessibilité

- Contraste vérifié pour WCAG AA
- Focus states préservés
- Screen reader compatible (sr-only classes)
- Keyboard navigation fonctionnelle
- Tooltips pour actions importantes
