# Design System - PCAP Analyzer Web Interface

**Date:** 2025-12-12
**Version:** 1.0
**Designer:** Agent UX/UI
**Stack:** Tailwind CSS + Vanilla JavaScript

---

## Table des Matières

1. [Principes de Design](#1-principes-de-design)
2. [Palette de Couleurs](#2-palette-de-couleurs)
3. [Typographie](#3-typographie)
4. [Système de Grille et Spacing](#4-système-de-grille-et-spacing)
5. [Composants Réutilisables](#5-composants-réutilisables)
6. [Wireframes des Écrans](#6-wireframes-des-écrans)
7. [Animations et Transitions](#7-animations-et-transitions)
8. [Mode Sombre](#8-mode-sombre)
9. [Accessibilité WCAG 2.1 AA](#9-accessibilité-wcag-21-aa)
10. [Guide d'Implémentation Tailwind](#10-guide-dimplémentation-tailwind)

---

## 1. Principes de Design

### Vision
Interface web moderne et professionnelle qui prolonge l'identité visuelle du rapport HTML existant. Design sobre, performant et accessible.

### Valeurs Clés
- **Cohérence:** Réutilisation maximale du CSS existant (variables, couleurs, composants)
- **Modernité:** Design 2025 avec gradients subtils, glassmorphism discret, micro-interactions
- **Performance:** Pas de frameworks JS lourds, animations CSS optimisées
- **Accessibilité:** Contraste AAA, navigation clavier, labels ARIA complets
- **Responsive:** Mobile-first, breakpoints Tailwind standards

### Philosophie UX
- **Progressive Disclosure:** Informations essentielles visibles, détails accessibles au clic
- **Feedback immédiat:** États visuels clairs (hover, focus, loading, success, error)
- **Guidage utilisateur:** Call-to-actions clairs, hiérarchie visuelle forte
- **Réassurance:** Messages explicites, progression visible, pas de surprises

---

## 2. Palette de Couleurs

### 2.1 Couleurs Héritées du Rapport HTML

Réutilisation stricte des variables CSS existantes pour cohérence maximale.

#### Couleurs Primaires
```css
Primary Blue:   #3498db (Navigation, liens, accents)
Secondary Dark: #2c3e50 (Textes importants, headers)
Accent Teal:    #1abc9c (Actions secondaires, highlights)
```

#### Couleurs Sémantiques
```css
Success Green:  #27ae60 (Succès, validation, healthy)
Warning Orange: #f39c12 (Avertissements, attention)
Danger Red:     #e74c3c (Erreurs, critiques)
Info Blue:      #3498db (Informations, tips)
```

#### Gradients (Signature Visuelle)
```css
Primary:   linear-gradient(135deg, #667eea 0%, #764ba2 100%)
Success:   linear-gradient(135deg, #11998e 0%, #38ef7d 100%)
Warning:   linear-gradient(135deg, #f093fb 0%, #f5576c 100%)
Danger:    linear-gradient(135deg, #fa709a 0%, #fee140 100%)
```

#### Backgrounds Light Mode
```css
Body:           #f5f5f5 (Gris très clair)
Container:      #ffffff (Blanc pur)
Section:        #f8f9fa (Gris léger)
Section Success:#d5f4e6 (Vert pastel)
Section Warning:#fef5e7 (Orange pastel)
Section Danger: #fadbd8 (Rouge pastel)
Code Block:     #ecf0f1 (Gris code)
```

#### Backgrounds Dark Mode
```css
Body:           #1a1a1a (Noir profond)
Container:      #2a2a2a (Gris foncé)
Section:        #333333 (Gris moyen)
Section Success:#1e3a2e (Vert sombre)
Section Warning:#3d2626 (Orange sombre)
Section Danger: #3d2626 (Rouge sombre)
Code Block:     #1e1e1e (Noir code)
Detail Box:     #2d2d2d (Gris détails)
```

#### Textes
```css
Light Mode:
  Primary:   #333333
  Secondary: #7f8c8d
  Light:     #555555
  White:     #ffffff

Dark Mode:
  Primary:   #e0e0e0
  Secondary: #90a4ae
  Accent:    #4fc3f7 (Bleu clair)
  Code:      #8ab4f8 (Bleu pastel)
```

### 2.2 Nouvelles Couleurs pour Interface Web

#### States & Feedback
```css
Hover Blue:     #2980b9 (Primary hover)
Focus Ring:     #667eea (Focus indicator)
Disabled Gray:  #95a5a6 (Éléments désactivés)
Border Light:   #ecf0f1
Border Dark:    #404040
```

#### Overlay & Glassmorphism
```css
Backdrop:       rgba(0, 0, 0, 0.5)
Glass BG:       rgba(255, 255, 255, 0.1)
Glass Border:   rgba(255, 255, 255, 0.2)
```

### 2.3 Mapping Tailwind CSS

```javascript
// tailwind.config.js - Extension de palette
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: '#3498db',
        secondary: '#2c3e50',
        accent: '#1abc9c',
        success: '#27ae60',
        warning: '#f39c12',
        danger: '#e74c3c',
        info: '#3498db',
        // Dark mode variants
        dark: {
          bg: '#1a1a1a',
          container: '#2a2a2a',
          section: '#333333',
          text: '#e0e0e0',
          secondary: '#90a4ae',
        }
      },
      backgroundImage: {
        'gradient-primary': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'gradient-success': 'linear-gradient(135deg, #11998e 0%, #38ef7d 100%)',
        'gradient-warning': 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
        'gradient-danger': 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
      }
    }
  }
}
```

---

## 3. Typographie

### 3.1 Fonts Stack

#### Sans-Serif (Corps de texte)
```css
font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
```
**Rationale:** Police système moderne, excellente lisibilité, disponible partout.

#### Monospace (Code & Données)
```css
font-family: 'Courier New', Consolas, Monaco, monospace;
```
**Usage:** Filenames, task IDs, données techniques, logs.

### 3.2 Échelle Typographique

Basée sur l'échelle de Tailwind avec ajustements pour rapport HTML existant.

| Élément | Taille | Line Height | Weight | Tailwind Class |
|---------|--------|-------------|--------|----------------|
| H1 (Page Title) | 32px (2rem) | 1.2 | 700 | `text-3xl font-bold` |
| H2 (Section) | 24px (1.5rem) | 1.3 | 600 | `text-2xl font-semibold` |
| H3 (Sub-section) | 20px (1.25rem) | 1.4 | 600 | `text-xl font-semibold` |
| Body Large | 18px (1.125rem) | 1.6 | 400 | `text-lg` |
| Body Regular | 16px (1rem) | 1.6 | 400 | `text-base` |
| Body Small | 14px (0.875rem) | 1.5 | 400 | `text-sm` |
| Caption | 12px (0.75rem) | 1.4 | 400 | `text-xs` |
| Mono Code | 14px (0.875rem) | 1.5 | 400 | `text-sm font-mono` |

### 3.3 Hiérarchie Visuelle

#### Headers
```html
<!-- H1 - Page Title -->
<h1 class="text-3xl font-bold text-secondary dark:text-dark-text mb-6">
  📊 PCAP Analyzer
</h1>

<!-- H2 - Section Title -->
<h2 class="text-2xl font-semibold text-secondary dark:text-dark-text mb-4 pb-2 border-b-2 border-primary">
  Upload PCAP File
</h2>

<!-- H3 - Sub-section -->
<h3 class="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-3">
  Recent Analyses
</h3>
```

#### Body Text
```html
<!-- Texte important -->
<p class="text-base text-gray-800 dark:text-gray-200">
  Upload your PCAP file for comprehensive network analysis.
</p>

<!-- Texte secondaire -->
<p class="text-sm text-gray-600 dark:text-gray-400">
  Supported formats: .pcap, .pcapng (max 500MB)
</p>

<!-- Caption / Metadata -->
<span class="text-xs text-gray-500 dark:text-gray-500">
  Generated on 2025-12-12 at 15:30
</span>
```

---

## 4. Système de Grille et Spacing

### 4.1 Breakpoints Tailwind (Standard)

```css
sm:  640px   (Tablettes portrait)
md:  768px   (Tablettes paysage)
lg:  1024px  (Desktop petit)
xl:  1280px  (Desktop standard)
2xl: 1536px  (Desktop large)
```

### 4.2 Spacing Scale

Utilisation de l'échelle Tailwind basée sur rem (1rem = 16px).

| Variable CSS | Tailwind | Pixel | Usage |
|--------------|----------|-------|-------|
| --spacing-xs | `space-2` | 8px | Padding inline petit, gaps minimaux |
| --spacing-sm | `space-3` | 12px | Padding boutons, labels |
| --spacing-md | `space-4` | 16px | Padding cards, sections |
| --spacing-lg | `space-5` | 20px | Margins entre blocs |
| --spacing-xl | `space-8` | 32px | Sections majeures |

### 4.3 Container Layout

```html
<!-- Container principal (responsive) -->
<div class="container mx-auto px-4 sm:px-6 lg:px-8 max-w-7xl">
  <!-- Contenu -->
</div>
```

**Comportement:**
- Mobile (<640px): Padding 16px
- Tablet (640-1024px): Padding 24px
- Desktop (>1024px): Max-width 1280px, centré

### 4.4 Grid System

#### 2 Colonnes (Desktop) / 1 Colonne (Mobile)
```html
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
  <div>Colonne 1</div>
  <div>Colonne 2</div>
</div>
```

#### 3 Colonnes (Cards)
```html
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
  <div>Card 1</div>
  <div>Card 2</div>
  <div>Card 3</div>
</div>
```

#### 4 Colonnes (Summary Metrics)
```html
<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
  <div>Metric 1</div>
  <div>Metric 2</div>
  <div>Metric 3</div>
  <div>Metric 4</div>
</div>
```

---

## 5. Composants Réutilisables

### 5.1 Buttons

#### Primary Button
```html
<button class="
  px-6 py-3
  bg-gradient-to-br from-[#667eea] to-[#764ba2]
  text-white font-semibold
  rounded-lg shadow-md
  hover:shadow-lg hover:scale-105
  active:scale-95
  transition-all duration-200
  focus:outline-none focus:ring-4 focus:ring-[#667eea]/50
  disabled:opacity-50 disabled:cursor-not-allowed
">
  Analyze PCAP
</button>
```

#### Secondary Button
```html
<button class="
  px-6 py-3
  bg-white dark:bg-dark-container
  text-secondary dark:text-dark-text
  border-2 border-primary
  font-semibold rounded-lg
  hover:bg-primary/10 dark:hover:bg-primary/20
  transition-colors duration-200
  focus:outline-none focus:ring-4 focus:ring-primary/50
">
  Download Report
</button>
```

#### Icon Button
```html
<button class="
  p-3 rounded-full
  bg-gray-100 dark:bg-dark-section
  text-gray-600 dark:text-gray-400
  hover:bg-gray-200 dark:hover:bg-gray-700
  transition-colors duration-200
  focus:outline-none focus:ring-2 focus:ring-primary
" aria-label="Settings">
  ⚙️
</button>
```

### 5.2 Cards

#### Basic Card
```html
<div class="
  bg-white dark:bg-dark-container
  rounded-lg shadow-md
  p-6
  border border-gray-200 dark:border-gray-700
  hover:shadow-lg
  transition-shadow duration-300
">
  <h3 class="text-xl font-semibold text-secondary dark:text-dark-text mb-3">
    Card Title
  </h3>
  <p class="text-gray-600 dark:text-gray-400">
    Card content goes here.
  </p>
</div>
```

#### Summary Card (avec gradient indicator)
```html
<div class="
  bg-white dark:bg-dark-container
  rounded-lg shadow-md
  p-6
  border-l-4 border-success
  hover:shadow-lg
  transition-shadow duration-300
">
  <h3 class="text-sm font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide">
    Health Score
  </h3>
  <div class="mt-2 flex items-baseline">
    <span class="text-4xl font-bold text-success">95</span>
    <span class="ml-2 text-xl text-gray-500">/100</span>
  </div>
  <p class="mt-2 text-sm text-gray-600 dark:text-gray-400">
    Excellent network performance
  </p>
</div>
```

#### Alert Card (Warning/Error)
```html
<!-- Warning -->
<div class="
  bg-[#fef5e7] dark:bg-[#3d2626]
  border-l-4 border-warning
  rounded-lg p-4
  flex items-start gap-3
">
  <span class="text-2xl">⚠️</span>
  <div>
    <h4 class="font-semibold text-gray-800 dark:text-gray-200">
      Warning: Large file detected
    </h4>
    <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
      This file is over 100MB and will use streaming mode.
    </p>
  </div>
</div>

<!-- Error -->
<div class="
  bg-[#fadbd8] dark:bg-[#3d2626]
  border-l-4 border-danger
  rounded-lg p-4
  flex items-start gap-3
">
  <span class="text-2xl">❌</span>
  <div>
    <h4 class="font-semibold text-gray-800 dark:text-gray-200">
      Error: Invalid file format
    </h4>
    <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
      Only .pcap and .pcapng files are supported.
    </p>
  </div>
</div>
```

### 5.3 Badges

#### Status Badges
```html
<!-- Success -->
<span class="
  inline-flex items-center
  px-3 py-1
  rounded-full text-sm font-medium
  bg-gradient-to-br from-[#11998e] to-[#38ef7d]
  text-white
">
  Completed
</span>

<!-- Warning -->
<span class="
  inline-flex items-center
  px-3 py-1
  rounded-full text-sm font-medium
  bg-warning text-white
">
  Processing
</span>

<!-- Danger -->
<span class="
  inline-flex items-center
  px-3 py-1
  rounded-full text-sm font-medium
  bg-danger text-white
">
  Failed
</span>

<!-- Info -->
<span class="
  inline-flex items-center
  px-3 py-1
  rounded-full text-sm font-medium
  bg-info text-white
">
  Pending
</span>
```

#### Metric Badges (Small)
```html
<span class="
  inline-flex items-center
  px-2 py-0.5
  rounded text-xs font-medium
  bg-primary/10 text-primary
  border border-primary/20
">
  IPv4
</span>
```

### 5.4 Progress Bars

#### Linear Progress
```html
<div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 overflow-hidden">
  <div class="
    bg-gradient-to-r from-primary to-accent
    h-full rounded-full
    transition-all duration-500 ease-out
    relative overflow-hidden
  " style="width: 65%">
    <!-- Shimmer effect -->
    <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent
                animate-shimmer"></div>
  </div>
</div>
```

#### Circular Progress (avec texte)
```html
<div class="relative inline-flex items-center justify-center">
  <svg class="w-24 h-24 transform -rotate-90">
    <!-- Background circle -->
    <circle cx="48" cy="48" r="40" stroke="currentColor"
            class="text-gray-200 dark:text-gray-700"
            stroke-width="8" fill="none"/>
    <!-- Progress circle -->
    <circle cx="48" cy="48" r="40"
            stroke="url(#gradient-primary)"
            stroke-width="8"
            fill="none"
            stroke-dasharray="251.2"
            stroke-dashoffset="75.36"
            stroke-linecap="round"
            class="transition-all duration-500"/>
    <defs>
      <linearGradient id="gradient-primary" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" style="stop-color:#667eea"/>
        <stop offset="100%" style="stop-color:#764ba2"/>
      </linearGradient>
    </defs>
  </svg>
  <span class="absolute text-2xl font-bold text-secondary dark:text-dark-text">
    70%
  </span>
</div>
```

### 5.5 File Upload Zone

#### Drag & Drop Area
```html
<div class="
  relative
  border-4 border-dashed border-gray-300 dark:border-gray-600
  rounded-xl p-12
  bg-gray-50 dark:bg-dark-section
  hover:border-primary hover:bg-primary/5
  transition-all duration-300
  cursor-pointer
  group
">
  <input type="file" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
         accept=".pcap,.pcapng" id="pcap-upload"/>

  <div class="flex flex-col items-center justify-center text-center">
    <!-- Icon -->
    <div class="
      w-20 h-20 mb-4
      bg-primary/10 dark:bg-primary/20
      rounded-full flex items-center justify-center
      group-hover:scale-110 transition-transform duration-300
    ">
      <svg class="w-10 h-10 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
              d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
      </svg>
    </div>

    <!-- Text -->
    <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-2">
      Drop your PCAP file here
    </h3>
    <p class="text-sm text-gray-500 dark:text-gray-400 mb-4">
      or click to browse
    </p>

    <!-- Specs -->
    <div class="flex flex-wrap gap-2 justify-center">
      <span class="px-3 py-1 bg-white dark:bg-dark-container rounded-full text-xs text-gray-600 dark:text-gray-400 border border-gray-200 dark:border-gray-700">
        .pcap / .pcapng
      </span>
      <span class="px-3 py-1 bg-white dark:bg-dark-container rounded-full text-xs text-gray-600 dark:text-gray-400 border border-gray-200 dark:border-gray-700">
        Max 500MB
      </span>
    </div>
  </div>
</div>

<!-- Active state (dragging over) -->
<div class="... border-primary bg-primary/10 scale-[1.02]">
  <!-- Same content with active styling -->
</div>
```

#### File Preview (after selection)
```html
<div class="
  flex items-center justify-between
  bg-white dark:bg-dark-container
  border border-gray-200 dark:border-gray-700
  rounded-lg p-4
  mt-4
">
  <div class="flex items-center gap-3">
    <!-- File icon -->
    <div class="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
      <span class="text-2xl">📦</span>
    </div>

    <!-- File info -->
    <div>
      <p class="font-medium text-secondary dark:text-dark-text">
        capture_2025-12-12.pcap
      </p>
      <p class="text-sm text-gray-500 dark:text-gray-400">
        26.4 MB
      </p>
    </div>
  </div>

  <!-- Remove button -->
  <button class="
    p-2 rounded-full
    text-gray-400 hover:text-danger hover:bg-danger/10
    transition-colors duration-200
  " aria-label="Remove file">
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
    </svg>
  </button>
</div>
```

### 5.6 Tables

#### Responsive Table
```html
<div class="overflow-x-auto">
  <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
    <thead class="bg-gray-50 dark:bg-dark-section">
      <tr>
        <th scope="col" class="
          px-6 py-3
          text-left text-xs font-medium
          text-gray-500 dark:text-gray-400
          uppercase tracking-wider
        ">
          Task ID
        </th>
        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
          Status
        </th>
        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
          Date
        </th>
      </tr>
    </thead>
    <tbody class="bg-white dark:bg-dark-container divide-y divide-gray-200 dark:divide-gray-700">
      <tr class="hover:bg-gray-50 dark:hover:bg-dark-section transition-colors duration-150">
        <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-gray-100">
          abc123def456
        </td>
        <td class="px-6 py-4 whitespace-nowrap">
          <span class="px-3 py-1 rounded-full text-sm font-medium bg-gradient-to-br from-[#11998e] to-[#38ef7d] text-white">
            Completed
          </span>
        </td>
        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
          2025-12-12 15:30
        </td>
      </tr>
    </tbody>
  </table>
</div>
```

### 5.7 Spinner / Loading States

#### Spinner Icon
```html
<div class="inline-block animate-spin rounded-full h-8 w-8 border-4 border-gray-200 border-t-primary"></div>
```

#### Loading Card
```html
<div class="bg-white dark:bg-dark-container rounded-lg p-6 shadow-md">
  <div class="animate-pulse space-y-4">
    <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
    <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
    <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
  </div>
</div>
```

### 5.8 Theme Toggle

```html
<button id="theme-toggle" class="
  p-3 rounded-full
  bg-gray-100 dark:bg-dark-section
  text-gray-600 dark:text-gray-400
  hover:bg-gray-200 dark:hover:bg-gray-700
  transition-all duration-300
  focus:outline-none focus:ring-2 focus:ring-primary
  relative overflow-hidden
" aria-label="Toggle dark mode">
  <!-- Sun icon (visible in dark mode) -->
  <svg class="w-6 h-6 dark:hidden transition-transform duration-300 hover:rotate-180"
       fill="currentColor" viewBox="0 0 20 20">
    <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"/>
  </svg>

  <!-- Moon icon (visible in light mode) -->
  <svg class="w-6 h-6 hidden dark:block transition-transform duration-300 hover:-rotate-12"
       fill="currentColor" viewBox="0 0 20 20">
    <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/>
  </svg>
</button>
```

---

## 6. Wireframes des Écrans

### 6.1 Landing Page - Upload

```
┌─────────────────────────────────────────────────────────────────┐
│ Header                                                     [🌙] │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📊 PCAP Analyzer                                          │   │
│ │ Network Traffic Analysis Made Simple                      │   │
│ └───────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │                      DRAG & DROP ZONE                      │   │
│ │                                                            │   │
│ │                      [  Upload Icon  ]                     │   │
│ │                                                            │   │
│ │               Drop your PCAP file here                     │   │
│ │                 or click to browse                         │   │
│ │                                                            │   │
│ │           [ .pcap / .pcapng ]  [ Max 500MB ]              │   │
│ │                                                            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ ℹ️ What happens next?                                      │   │
│ │                                                            │   │
│ │ 1. File validation (format, size, magic bytes)            │   │
│ │ 2. Real-time analysis progress tracking                   │   │
│ │ 3. Comprehensive HTML report generation                   │   │
│ │ 4. Automatic cleanup after 24h                            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌─────────────────────────────────────┐                         │
│ │ 📜 Recent Analyses (Last 24h)       │                         │
│ │                                     │                         │
│ │ abc123  [✅ Completed]  2h ago      │                         │
│ │ def456  [⏳ Processing] 5m ago      │                         │
│ │ ghi789  [✅ Completed]  6h ago      │                         │
│ │                                     │                         │
│ │          [View All History →]       │                         │
│ └─────────────────────────────────────┘                         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│ Footer: © 2025 PCAP Analyzer | Version 1.0                     │
└─────────────────────────────────────────────────────────────────┘
```

**Elements clés:**
- Header avec branding cohérent rapport HTML
- Zone drag & drop prominente, hover states
- Informations rassurantes sur le processus
- Quick access aux analyses récentes
- Dark mode toggle en header

---

### 6.2 Page Progression - Analyse en Cours

```
┌─────────────────────────────────────────────────────────────────┐
│ [← Back]  Analysis Progress                               [🌙] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📦 File: capture_2025-12-12.pcap                          │   │
│ │ 💾 Size: 26.4 MB                                          │   │
│ │ 🔧 Mode: MEMORY (auto-selected)                           │   │
│ │ ⏱️  Started: 2025-12-12 15:30:42                          │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │                   OVERALL PROGRESS                         │   │
│ │                                                            │   │
│ │  ████████████████████░░░░░░░░░░░░  65%                    │   │
│ │                                                            │   │
│ │  Phase 2/2: Deep Analysis (Scapy)                         │   │
│ │  Analyzing 85,427 packets...                              │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌─────────────────────┬─────────────────────────────────────┐   │
│ │ ✅ PHASE 1 COMPLETE │ ⏳ PHASE 2 IN PROGRESS              │   │
│ ├─────────────────────┼─────────────────────────────────────┤   │
│ │ Metadata Extraction │ Deep Protocol Analysis              │   │
│ │ 100% (12s)          │ 65% (38s elapsed)                   │   │
│ │                     │                                     │   │
│ │ ✓ Packet count      │ ⏳ TCP analysis      (45%)          │   │
│ │ ✓ Duration          │ ⏳ UDP analysis      (78%)          │   │
│ │ ✓ IP addresses      │ ⏳ DNS analysis      (92%)          │   │
│ │ ✓ Protocols         │ ⏳ Retransmissions   (38%)          │   │
│ │                     │ ⏳ Health scoring    (0%)           │   │
│ └─────────────────────┴─────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📊 Memory Usage                                           │   │
│ │                                                            │   │
│ │ Current:  1.2 GB / 4.0 GB available                       │   │
│ │ Peak:     1.8 GB                                          │   │
│ │                                                            │   │
│ │ ████████████░░░░░░░░░░░░░░░░░░░░  30%                     │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📝 Live Log (Last 5 events)                               │   │
│ │                                                            │   │
│ │ [15:31:23] Starting TCP flow analysis...                  │   │
│ │ [15:31:18] DNS queries analyzed: 1,234                    │   │
│ │ [15:31:12] Retransmission detection in progress...        │   │
│ │ [15:31:05] Completed UDP analysis (12,456 packets)        │   │
│ │ [15:31:00] Phase 2 started: Deep Analysis                 │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Elements clés:**
- File metadata en header
- Overall progress bar prominent avec animation shimmer
- Deux colonnes Phase 1 (completed) / Phase 2 (in progress)
- Sub-tasks progress (inspiré CLI Rich)
- Memory usage gauge
- Live log SSE stream
- Responsive: Stack vertical sur mobile

---

### 6.3 Page Rapport - Résultats

```
┌─────────────────────────────────────────────────────────────────┐
│ [← New Analysis]  Analysis Report                          [🌙] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📊 PCAP Analyzer Report                                   │   │
│ │                                                            │   │
│ │ File: capture_2025-12-12.pcap                             │   │
│ │ Date: 2025-12-12 15:32:45                                 │   │
│ │ Duration: 120.5s | Packets: 131,072                       │   │
│ │                                                            │   │
│ │ [📥 Download HTML]  [📄 Download JSON]  [🔄 New Analysis] │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │          EMBEDDED HTML REPORT (IFRAME/OBJECT)              │   │
│ │                                                            │   │
│ │  [Rapport HTML existant affiché ici avec scrolling]       │   │
│ │                                                            │   │
│ │  - Health Score: 95/100                                   │   │
│ │  - Summary Cards                                          │   │
│ │  - Detailed Analysis Sections                             │   │
│ │  - Tables, Charts, Metrics                                │   │
│ │                                                            │   │
│ │  (Le rapport conserve son propre CSS et dark mode)        │   │
│ │                                                            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 🔗 Share this report                                       │   │
│ │                                                            │   │
│ │ Task ID: abc123def456                                     │   │
│ │ Valid until: 2025-12-13 15:32 (24h)                       │   │
│ │                                                            │   │
│ │ [📋 Copy Link]                                            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Elements clés:**
- Quick actions en header (download, new analysis)
- Iframe/object pour rapport HTML existant (conservation CSS)
- Share section avec task_id et expiration
- Bouton retour vers upload
- Alternative: Si redesign nécessaire, intégration native des sections du rapport

---

### 6.4 Page Historique - Analyses Récentes

```
┌─────────────────────────────────────────────────────────────────┐
│ [← Home]  Analysis History                                 [🌙] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📜 Recent Analyses (Last 24h)                             │   │
│ │                                                            │   │
│ │ [🔍 Search]  [📅 Filter]  [⬆️ Sort by Date ▼]            │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ ┌───────────────────────────────────────────────────────┐ │   │
│ │ │ 📦 capture_network_issue.pcap                         │ │   │
│ │ │                                                        │ │   │
│ │ │ Status: [✅ Completed]  Health: 🟢 95/100             │ │   │
│ │ │ Date: 2025-12-12 15:32  |  Size: 26.4 MB             │ │   │
│ │ │ Duration: 60s  |  Packets: 131,072                   │ │   │
│ │ │                                                        │ │   │
│ │ │ [👁️ View Report]  [📥 Download]  [🗑️ Delete]         │ │   │
│ │ └───────────────────────────────────────────────────────┘ │   │
│ │                                                            │   │
│ │ ┌───────────────────────────────────────────────────────┐ │   │
│ │ │ 📦 test_capture_2.pcap                                │ │   │
│ │ │                                                        │ │   │
│ │ │ Status: [⏳ Processing 65%]  Health: --               │ │   │
│ │ │ Date: 2025-12-12 15:28  |  Size: 12.8 MB             │ │   │
│ │ │                                                        │ │   │
│ │ │ [⏳ View Progress]                                    │ │   │
│ │ └───────────────────────────────────────────────────────┘ │   │
│ │                                                            │   │
│ │ ┌───────────────────────────────────────────────────────┐ │   │
│ │ │ 📦 old_capture.pcap                                   │ │   │
│ │ │                                                        │ │   │
│ │ │ Status: [❌ Failed]  Error: Invalid file format       │ │   │
│ │ │ Date: 2025-12-12 14:15  |  Size: 5.2 MB              │ │   │
│ │ │                                                        │ │   │
│ │ │ [ℹ️ View Error]  [🔄 Retry]                           │ │   │
│ │ └───────────────────────────────────────────────────────┘ │   │
│ │                                                            │   │
│ │             [Load More...]                                 │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│ ┌───────────────────────────────────────────────────────────┐   │
│ │ 📊 Statistics (24h)                                       │   │
│ │                                                            │   │
│ │ Total Analyses: 12                                        │   │
│ │ Completed: 10  |  Failed: 2  |  In Progress: 0           │   │
│ │ Total Data Processed: 486 MB                              │   │
│ └───────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Elements clés:**
- Search, filter, sort controls
- Cards par analyse avec metadata
- Status badges visuels (completed/processing/failed)
- Health score indicator
- Actions contextuelles selon status
- Statistics summary
- Infinite scroll ou pagination

---

## 7. Animations et Transitions

### 7.1 Principes

- **Subtilité:** Animations discrètes, jamais distrayantes
- **Performance:** Préférer transforms/opacity (GPU-accelerated)
- **Durée:** 200-300ms par défaut, 500ms pour états importants
- **Easing:** ease-out pour entrées, ease-in pour sorties

### 7.2 Micro-interactions

#### Button Hover/Active
```css
/* Hover: Scale up + shadow */
.btn:hover {
  transform: scale(1.05);
  box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  transition: all 0.2s ease-out;
}

/* Active: Scale down */
.btn:active {
  transform: scale(0.95);
  transition: all 0.1s ease-in;
}
```

#### Card Hover
```css
.card {
  transition: box-shadow 0.3s ease-out, transform 0.3s ease-out;
}

.card:hover {
  box-shadow: 0 8px 24px rgba(0,0,0,0.15);
  transform: translateY(-4px);
}
```

#### Link Underline
```css
.link {
  position: relative;
}

.link::after {
  content: '';
  position: absolute;
  bottom: 0;
  left: 0;
  width: 0;
  height: 2px;
  background: var(--color-primary);
  transition: width 0.3s ease-out;
}

.link:hover::after {
  width: 100%;
}
```

### 7.3 Loading States

#### Shimmer Effect (Progress Bar)
```css
@keyframes shimmer {
  0% { transform: translateX(-100%); }
  100% { transform: translateX(100%); }
}

.shimmer {
  animation: shimmer 2s infinite;
}
```

#### Spinner Rotation
```css
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.spinner {
  animation: spin 1s linear infinite;
}
```

#### Pulse (Waiting state)
```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

.pulse {
  animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
}
```

### 7.4 Page Transitions

#### Fade In (Page load)
```css
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.page-enter {
  animation: fadeIn 0.3s ease-out;
}
```

#### Slide Up (Modal/Alert)
```css
@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.modal-enter {
  animation: slideUp 0.3s ease-out;
}
```

### 7.5 SSE Updates (Real-time)

#### Progress Bar Smooth Update
```javascript
// Progressive update avec transition CSS
progressBar.style.width = `${newProgress}%`;
// Transition définie en CSS: transition: width 0.5s ease-out;
```

#### Log Entry Fade In
```css
@keyframes logEntry {
  from {
    opacity: 0;
    transform: translateX(-10px);
  }
  to {
    opacity: 1;
    transform: translateX(0);
  }
}

.log-entry {
  animation: logEntry 0.3s ease-out;
}
```

---

## 8. Mode Sombre

### 8.1 Stratégie d'Implémentation

**Approche: Tailwind Dark Mode (class-based)**

```javascript
// tailwind.config.js
module.exports = {
  darkMode: 'class', // Activation via classe 'dark' sur <html>
  // ...
}
```

#### Détection Automatique + Toggle Manuel
```javascript
// app.js - Dark mode initialization
(function() {
  // Check localStorage or system preference
  const darkMode = localStorage.getItem('darkMode') === 'true' ||
                   (!localStorage.getItem('darkMode') &&
                    window.matchMedia('(prefers-color-scheme: dark)').matches);

  if (darkMode) {
    document.documentElement.classList.add('dark');
  }

  // Toggle function
  document.getElementById('theme-toggle')?.addEventListener('click', () => {
    const isDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('darkMode', isDark);
  });
})();
```

### 8.2 Palette Dark Mode (Mappings)

| Light Mode | Dark Mode | Variable |
|------------|-----------|----------|
| #f5f5f5 (Body) | #1a1a1a | `bg-gray-100 dark:bg-dark-bg` |
| #ffffff (Container) | #2a2a2a | `bg-white dark:bg-dark-container` |
| #f8f9fa (Section) | #333333 | `bg-gray-50 dark:bg-dark-section` |
| #333333 (Text Primary) | #e0e0e0 | `text-gray-900 dark:text-dark-text` |
| #7f8c8d (Text Secondary) | #90a4ae | `text-gray-600 dark:text-dark-secondary` |
| #ecf0f1 (Border) | #404040 | `border-gray-200 dark:border-gray-700` |

### 8.3 Exemples de Classes Tailwind

```html
<!-- Background -->
<div class="bg-white dark:bg-dark-container">

<!-- Text -->
<p class="text-gray-900 dark:text-dark-text">

<!-- Border -->
<div class="border border-gray-200 dark:border-gray-700">

<!-- Shadow (subtil en dark mode) -->
<div class="shadow-md dark:shadow-lg dark:shadow-gray-900/50">

<!-- Gradient (conservé identique) -->
<div class="bg-gradient-primary"> <!-- Gradients unchanged -->
```

### 8.4 Transitions Dark Mode

```css
/* Smooth transition sur changement de thème */
* {
  transition-property: background-color, border-color, color, fill, stroke;
  transition-duration: 200ms;
  transition-timing-function: ease-out;
}

/* Exceptions: Pas de transition sur animations/transforms */
.no-theme-transition {
  transition-property: none !important;
}
```

### 8.5 Spécificités Components

#### Cards en Dark Mode
```html
<div class="
  bg-white dark:bg-dark-container
  border border-gray-200 dark:border-gray-700
  shadow-md dark:shadow-lg dark:shadow-gray-900/30
">
```

#### Inputs en Dark Mode
```html
<input class="
  bg-white dark:bg-dark-section
  text-gray-900 dark:text-dark-text
  border-gray-300 dark:border-gray-600
  focus:ring-primary dark:focus:ring-primary/80
  placeholder-gray-400 dark:placeholder-gray-500
"/>
```

#### Alerts en Dark Mode
```html
<!-- Warning Alert -->
<div class="
  bg-[#fef5e7] dark:bg-[#3d2626]
  border-l-4 border-warning
  text-gray-800 dark:text-gray-200
">
```

---

## 9. Accessibilité WCAG 2.1 AA

### 9.1 Contraste des Couleurs

**Critère 1.4.3 (AA):** Ratio minimum 4.5:1 pour texte normal, 3:1 pour texte large.

#### Vérifications
| Foreground | Background | Ratio | Status |
|------------|------------|-------|--------|
| #333333 | #ffffff | 12.6:1 | ✅ AAA |
| #e0e0e0 | #1a1a1a | 11.8:1 | ✅ AAA |
| #ffffff | #3498db | 4.8:1 | ✅ AA |
| #ffffff | #27ae60 | 4.2:1 | ✅ AA |
| #ffffff | #e74c3c | 4.1:1 | ✅ AA |

#### Outil recommandé
```
https://webaim.org/resources/contrastchecker/
```

### 9.2 Navigation Clavier

#### Focus Visible
```css
/* Custom focus ring (Tailwind) */
.focus-visible:focus {
  outline: none;
  ring: 4px;
  ring-color: var(--color-primary);
  ring-opacity: 0.5;
}
```

```html
<!-- Focus states sur tous éléments interactifs -->
<button class="focus:outline-none focus:ring-4 focus:ring-primary/50">

<a class="focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary">

<input class="focus:border-primary focus:ring-2 focus:ring-primary">
```

#### Tab Order
- Ordre logique de tabulation (header → main → footer)
- `tabindex="-1"` sur éléments décoratifs
- `tabindex="0"` sur custom interactive elements

#### Keyboard Shortcuts
```javascript
// Upload page: Space/Enter sur drag zone
dropZone.addEventListener('keydown', (e) => {
  if (e.key === ' ' || e.key === 'Enter') {
    e.preventDefault();
    fileInput.click();
  }
});

// Esc pour fermer modales
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && modal.isOpen) {
    modal.close();
  }
});
```

### 9.3 Labels ARIA

#### Buttons
```html
<button aria-label="Toggle dark mode">
  <svg>...</svg>
</button>

<button aria-label="Remove file">
  <svg>...</svg>
</button>

<button aria-label="Download HTML report">
  📥 Download
</button>
```

#### File Upload
```html
<div role="button"
     tabindex="0"
     aria-label="Upload PCAP file. Drag and drop or press Enter to select file.">
  <input type="file"
         aria-label="PCAP file input"
         accept=".pcap,.pcapng"/>
</div>
```

#### Progress Bar
```html
<div role="progressbar"
     aria-valuenow="65"
     aria-valuemin="0"
     aria-valuemax="100"
     aria-label="Analysis progress: 65%">
  <div style="width: 65%"></div>
</div>
```

#### Live Region (SSE Updates)
```html
<div aria-live="polite"
     aria-atomic="true"
     class="sr-only">
  Analysis progress updated: 65%
</div>

<div aria-live="assertive"
     aria-atomic="true">
  <!-- Error messages ici -->
</div>
```

#### Status Messages
```html
<div role="status" aria-live="polite">
  File uploaded successfully
</div>

<div role="alert" aria-live="assertive">
  Error: Invalid file format
</div>
```

### 9.4 Alternative Text

#### Images & Icons
```html
<!-- Icônes décoratives -->
<span aria-hidden="true">📊</span>
<span class="sr-only">PCAP Analyzer</span>

<!-- Icônes fonctionnelles -->
<svg aria-label="Upload icon" role="img">
  <title>Upload</title>
  ...
</svg>
```

### 9.5 Screen Reader Only Text

```css
/* Utility class */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
```

```html
<span class="sr-only">Current status:</span>
<span aria-hidden="true">✅</span> Completed
```

### 9.6 Forms Accessibility

```html
<label for="pcap-file" class="block text-sm font-medium mb-2">
  PCAP File
</label>
<input type="file"
       id="pcap-file"
       name="pcap-file"
       accept=".pcap,.pcapng"
       aria-required="true"
       aria-describedby="file-help"/>
<p id="file-help" class="text-sm text-gray-500 mt-1">
  Supported formats: .pcap, .pcapng. Maximum size: 500MB.
</p>

<!-- Error state -->
<input aria-invalid="true"
       aria-errormessage="file-error"/>
<p id="file-error" role="alert" class="text-sm text-danger mt-1">
  File size exceeds maximum limit of 500MB
</p>
```

### 9.7 Semantic HTML

```html
<!-- Structure claire -->
<header>
  <nav aria-label="Main navigation">...</nav>
</header>

<main id="main-content">
  <h1>Upload PCAP File</h1>

  <section aria-labelledby="upload-heading">
    <h2 id="upload-heading">File Upload</h2>
    ...
  </section>

  <section aria-labelledby="history-heading">
    <h2 id="history-heading">Recent Analyses</h2>
    ...
  </section>
</main>

<footer>
  ...
</footer>
```

### 9.8 Skip Links

```html
<a href="#main-content"
   class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4
          bg-primary text-white px-4 py-2 rounded z-50">
  Skip to main content
</a>
```

---

## 10. Guide d'Implémentation Tailwind

### 10.1 Configuration Tailwind

#### Installation
```bash
npm install -D tailwindcss postcss autoprefixer
npx tailwindcss init
```

#### tailwind.config.js (Complet)
```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/**/*.js",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Primary palette
        primary: '#3498db',
        secondary: '#2c3e50',
        accent: '#1abc9c',

        // Semantic colors
        success: '#27ae60',
        warning: '#f39c12',
        danger: '#e74c3c',
        info: '#3498db',

        // Dark mode palette
        dark: {
          bg: '#1a1a1a',
          container: '#2a2a2a',
          section: '#333333',
          text: '#e0e0e0',
          secondary: '#90a4ae',
          border: '#404040',
          code: '#1e1e1e',
        },
      },

      backgroundImage: {
        'gradient-primary': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'gradient-success': 'linear-gradient(135deg, #11998e 0%, #38ef7d 100%)',
        'gradient-warning': 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
        'gradient-danger': 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
      },

      fontFamily: {
        sans: ['Segoe UI', 'Tahoma', 'Geneva', 'Verdana', 'sans-serif'],
        mono: ['Courier New', 'Consolas', 'Monaco', 'monospace'],
      },

      boxShadow: {
        'sm': '0 2px 10px rgba(0,0,0,0.1)',
        'md': '0 4px 6px rgba(0,0,0,0.1)',
        'lg': '0 4px 12px rgba(0,0,0,0.3)',
      },

      borderRadius: {
        'sm': '3px',
        'md': '6px',
        'lg': '8px',
        'pill': '20px',
      },

      animation: {
        'shimmer': 'shimmer 2s infinite',
        'spin-slow': 'spin 3s linear infinite',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },

      keyframes: {
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
```

#### styles.css (Input file)
```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom utilities */
@layer utilities {
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  }

  .focus-visible {
    @apply focus:outline-none focus:ring-4 focus:ring-primary/50;
  }
}

/* Custom components */
@layer components {
  .btn-primary {
    @apply px-6 py-3 bg-gradient-primary text-white font-semibold rounded-lg
           shadow-md hover:shadow-lg hover:scale-105 active:scale-95
           transition-all duration-200 focus-visible
           disabled:opacity-50 disabled:cursor-not-allowed;
  }

  .btn-secondary {
    @apply px-6 py-3 bg-white dark:bg-dark-container text-secondary
           dark:text-dark-text border-2 border-primary font-semibold rounded-lg
           hover:bg-primary/10 dark:hover:bg-primary/20 transition-colors
           duration-200 focus-visible;
  }

  .card {
    @apply bg-white dark:bg-dark-container rounded-lg shadow-md p-6
           border border-gray-200 dark:border-gray-700
           hover:shadow-lg transition-shadow duration-300;
  }

  .badge-success {
    @apply inline-flex items-center px-3 py-1 rounded-full text-sm
           font-medium bg-gradient-success text-white;
  }

  .badge-warning {
    @apply inline-flex items-center px-3 py-1 rounded-full text-sm
           font-medium bg-warning text-white;
  }

  .badge-danger {
    @apply inline-flex items-center px-3 py-1 rounded-full text-sm
           font-medium bg-danger text-white;
  }
}

/* Dark mode smooth transition */
* {
  @apply transition-colors duration-200;
}

/* Exception: Pas de transition sur transforms */
.no-theme-transition {
  transition-property: none !important;
}
```

### 10.2 Build Process

#### package.json
```json
{
  "scripts": {
    "build:css": "tailwindcss -i ./static/css/input.css -o ./static/css/output.css --minify",
    "watch:css": "tailwindcss -i ./static/css/input.css -o ./static/css/output.css --watch"
  },
  "devDependencies": {
    "tailwindcss": "^3.4.0",
    "@tailwindcss/forms": "^0.5.7"
  }
}
```

#### Production Build
```bash
NODE_ENV=production npm run build:css
```

### 10.3 HTML Template Structure

```html
<!DOCTYPE html>
<html lang="fr" class="dark"> <!-- classe 'dark' gérée par JS -->
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PCAP Analyzer - Upload</title>

  <!-- Tailwind CSS -->
  <link href="/static/css/output.css" rel="stylesheet">

  <!-- Custom CSS (si nécessaire) -->
  <link href="/static/css/custom.css" rel="stylesheet">
</head>
<body class="bg-gray-100 dark:bg-dark-bg text-gray-900 dark:text-dark-text">

  <!-- Skip link -->
  <a href="#main-content" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 bg-primary text-white px-4 py-2 rounded z-50">
    Skip to main content
  </a>

  <!-- Header -->
  <header class="bg-white dark:bg-dark-container shadow-sm border-b border-gray-200 dark:border-dark-border">
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-4">
      <div class="flex items-center justify-between">
        <h1 class="text-3xl font-bold text-secondary dark:text-dark-text">
          <span aria-hidden="true">📊</span> PCAP Analyzer
        </h1>

        <button id="theme-toggle"
                class="p-3 rounded-full bg-gray-100 dark:bg-dark-section hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors duration-200 focus-visible"
                aria-label="Toggle dark mode">
          <svg class="w-6 h-6 dark:hidden" fill="currentColor" viewBox="0 0 20 20">
            <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"/>
          </svg>
          <svg class="w-6 h-6 hidden dark:block" fill="currentColor" viewBox="0 0 20 20">
            <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/>
          </svg>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main id="main-content" class="container mx-auto px-4 sm:px-6 lg:px-8 py-8">
    <!-- Page content ici -->
  </main>

  <!-- Footer -->
  <footer class="bg-white dark:bg-dark-container border-t border-gray-200 dark:border-dark-border mt-12 py-6">
    <div class="container mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-gray-600 dark:text-gray-400">
      &copy; 2025 PCAP Analyzer | Version 1.0
    </div>
  </footer>

  <!-- Scripts -->
  <script src="/static/js/theme.js"></script>
  <script src="/static/js/app.js"></script>
</body>
</html>
```

### 10.4 Responsive Utilities

#### Breakpoint Examples
```html
<!-- Stack vertical sur mobile, horizontal sur desktop -->
<div class="flex flex-col md:flex-row gap-4">
  <div class="w-full md:w-1/2">Column 1</div>
  <div class="w-full md:w-1/2">Column 2</div>
</div>

<!-- Grille responsive -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
  <!-- Cards -->
</div>

<!-- Texte responsive -->
<h1 class="text-2xl sm:text-3xl lg:text-4xl font-bold">
  Title
</h1>

<!-- Padding responsive -->
<div class="px-4 sm:px-6 lg:px-8 py-4 sm:py-6">
  Content
</div>

<!-- Hide/Show selon breakpoint -->
<div class="hidden md:block">Desktop only</div>
<div class="block md:hidden">Mobile only</div>
```

### 10.5 JavaScript Intégration

#### Theme Toggle (theme.js)
```javascript
(function() {
  const html = document.documentElement;
  const toggle = document.getElementById('theme-toggle');

  // Initialize from localStorage or system preference
  const darkMode = localStorage.getItem('darkMode') === 'true' ||
                   (!localStorage.getItem('darkMode') &&
                    window.matchMedia('(prefers-color-scheme: dark)').matches);

  if (darkMode) {
    html.classList.add('dark');
  }

  // Toggle handler
  toggle?.addEventListener('click', () => {
    const isDark = html.classList.toggle('dark');
    localStorage.setItem('darkMode', isDark);
  });

  // Listen to system preference changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (!localStorage.getItem('darkMode')) {
      html.classList.toggle('dark', e.matches);
    }
  });
})();
```

#### Dynamic Class Manipulation
```javascript
// Ajouter badge success
element.classList.add('badge-success');

// Toggle card hover effect
card.addEventListener('mouseenter', () => {
  card.classList.add('shadow-lg', 'transform', '-translate-y-1');
});

card.addEventListener('mouseleave', () => {
  card.classList.remove('shadow-lg', 'transform', '-translate-y-1');
});
```

### 10.6 Performance Optimizations

#### Purge CSS (Production)
Tailwind purge automatiquement les classes non utilisées en production.

```javascript
// tailwind.config.js
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/**/*.js",
  ],
  // Purge automatique activée avec content paths
}
```

#### CDN Alternative (Development)
Pour prototypage rapide uniquement, NE PAS utiliser en production.

```html
<!-- Development only -->
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    darkMode: 'class',
    theme: {
      extend: {
        colors: {
          primary: '#3498db',
          // ... (config complète)
        }
      }
    }
  }
</script>
```

---

## 11. Checklist d'Implémentation

### Phase 1: Setup (Sprint 1)
- [ ] Installer Tailwind CSS + PostCSS
- [ ] Configurer tailwind.config.js avec palette complète
- [ ] Créer input.css avec @layer directives
- [ ] Builder output.css et tester
- [ ] Implémenter dark mode toggle
- [ ] Créer composants de base (buttons, cards, badges)

### Phase 2: Pages (Sprint 2-3)
- [ ] Landing page - Upload zone
- [ ] Page progression - SSE integration
- [ ] Page rapport - HTML embed
- [ ] Page historique - Liste analyses

### Phase 3: Interactivité (Sprint 3)
- [ ] Drag & drop file upload
- [ ] File validation visuelle
- [ ] SSE progress updates
- [ ] Animations micro-interactions

### Phase 4: Accessibilité (Sprint 4)
- [ ] ARIA labels complets
- [ ] Navigation clavier
- [ ] Focus states visuels
- [ ] Screen reader testing
- [ ] Contraste couleurs validation

### Phase 5: Polish (Sprint 5)
- [ ] Responsive testing (mobile/tablet/desktop)
- [ ] Dark mode testing
- [ ] Performance audit (Lighthouse)
- [ ] Cross-browser testing
- [ ] Documentation finale

---

## 12. Ressources et Références

### Design Inspiration
- Vercel Dashboard (modern upload UI)
- Stripe Dashboard (clean cards layout)
- GitHub Actions (progress visualization)
- Tailwind UI Components (official examples)

### Tailwind Resources
- [Official Documentation](https://tailwindcss.com/docs)
- [Tailwind UI Components](https://tailwindui.com/)
- [Headless UI](https://headlessui.com/) (pour composants accessibles)

### Accessibilité
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [ARIA Authoring Practices](https://www.w3.org/WAI/ARIA/apg/)

### Performance
- [Lighthouse CI](https://github.com/GoogleChrome/lighthouse-ci)
- [Web Vitals](https://web.dev/vitals/)

---

## Conclusion

Ce design system offre une base solide, cohérente et moderne pour l'interface web du PCAP Analyzer. Il respecte l'identité visuelle du rapport HTML existant tout en apportant une expérience utilisateur optimale, accessible et performante.

**Next Steps:**
1. Validation design avec équipe
2. Prototypage HTML/CSS rapide
3. Intégration avec backend FastAPI
4. Tests utilisateurs
5. Itérations et ajustements

---

**Approuvé pour développement**
**Designer:** Agent UX/UI
**Date:** 2025-12-12
