# Design Code Snippets - PCAP Analyzer Web Interface

**Date:** 2025-12-12
**Version:** 1.0
**Complément:** DESIGN_SYSTEM.md & DESIGN_MOCKUPS.md

Ce document contient des extraits de code HTML/CSS/JS prêts à l'emploi pour accélérer l'implémentation.

---

## Table des Matières

1. [Configuration Tailwind](#1-configuration-tailwind)
2. [Layout Global](#2-layout-global)
3. [Landing Page Components](#3-landing-page-components)
4. [Progress Page Components](#4-progress-page-components)
5. [Report Page Components](#5-report-page-components)
6. [History Page Components](#6-history-page-components)
7. [JavaScript Utilities](#7-javascript-utilities)
8. [API Integration Examples](#8-api-integration-examples)

---

## 1. Configuration Tailwind

### tailwind.config.js (Complet)

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
        // Primary palette (from existing report.css)
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
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
      },

      keyframes: {
        shimmer: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
```

### styles.css (Input file)

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

/* ============================================
   Custom Utilities
   ============================================ */
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

  .transition-theme {
    @apply transition-colors duration-200;
  }
}

/* ============================================
   Custom Components
   ============================================ */
@layer components {
  /* Buttons */
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

  .btn-danger {
    @apply px-4 py-2 bg-transparent text-danger hover:bg-danger/10
           rounded-lg transition-colors duration-200 focus-visible;
  }

  /* Cards */
  .card {
    @apply bg-white dark:bg-dark-container rounded-lg shadow-md p-6
           border border-gray-200 dark:border-gray-700
           hover:shadow-lg transition-shadow duration-300;
  }

  .card-gradient {
    @apply bg-gradient-primary text-white p-8 rounded-lg shadow-lg;
  }

  /* Badges */
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

  .badge-info {
    @apply inline-flex items-center px-3 py-1 rounded-full text-sm
           font-medium bg-info text-white;
  }

  /* Alerts */
  .alert-info {
    @apply bg-blue-50 dark:bg-blue-900/20 border-l-4 border-info
           rounded-lg p-4 text-gray-800 dark:text-gray-200;
  }

  .alert-warning {
    @apply bg-yellow-50 dark:bg-yellow-900/20 border-l-4 border-warning
           rounded-lg p-4 text-gray-800 dark:text-gray-200;
  }

  .alert-danger {
    @apply bg-red-50 dark:bg-red-900/20 border-l-4 border-danger
           rounded-lg p-4 text-gray-800 dark:text-gray-200;
  }

  .alert-success {
    @apply bg-green-50 dark:bg-green-900/20 border-l-4 border-success
           rounded-lg p-4 text-gray-800 dark:text-gray-200;
  }
}

/* ============================================
   Dark Mode Smooth Transition
   ============================================ */
* {
  @apply transition-theme;
}

.no-theme-transition {
  transition-property: none !important;
}

/* ============================================
   Shimmer Effect for Progress Bars
   ============================================ */
.shimmer-overlay {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: linear-gradient(
    90deg,
    transparent 0%,
    rgba(255, 255, 255, 0.3) 50%,
    transparent 100%
  );
  animation: shimmer 2s infinite;
}
```

---

## 2. Layout Global

### base.html (Template de base Jinja2)

```html
<!DOCTYPE html>
<html lang="fr" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
    <title>{% block title %}PCAP Analyzer{% endblock %}</title>

    <!-- Tailwind CSS (production build) -->
    <link href="/static/css/output.css" rel="stylesheet">

    <!-- Favicon -->
    <link rel="icon" type="image/png" href="/static/favicon.png">

    {% block extra_head %}{% endblock %}
</head>
<body class="h-full bg-gray-100 dark:bg-dark-bg text-gray-900 dark:text-dark-text">

    <!-- Skip to main content (accessibility) -->
    <a href="#main-content"
       class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4
              bg-primary text-white px-4 py-2 rounded-lg z-50 focus-visible">
        Skip to main content
    </a>

    <!-- Header -->
    <header class="bg-white dark:bg-dark-container shadow-sm border-b border-gray-200 dark:border-dark-border">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div class="flex items-center justify-between">
                <!-- Logo/Title -->
                <a href="/" class="flex items-center gap-3 hover:opacity-80 transition-opacity">
                    <span class="text-3xl" aria-hidden="true">📊</span>
                    <h1 class="text-2xl md:text-3xl font-bold text-secondary dark:text-dark-text">
                        PCAP Analyzer
                    </h1>
                </a>

                <!-- Navigation (optional) -->
                <nav class="hidden md:flex items-center gap-6" aria-label="Main navigation">
                    <a href="/"
                       class="text-gray-600 dark:text-gray-400 hover:text-primary transition-colors">
                        Upload
                    </a>
                    <a href="/history"
                       class="text-gray-600 dark:text-gray-400 hover:text-primary transition-colors">
                        History
                    </a>
                </nav>

                <!-- Theme Toggle -->
                <button id="theme-toggle"
                        class="p-3 rounded-full bg-gray-100 dark:bg-dark-section
                               hover:bg-gray-200 dark:hover:bg-gray-700
                               transition-colors duration-200 focus-visible"
                        aria-label="Toggle dark mode">
                    <!-- Sun icon (visible in dark mode) -->
                    <svg class="w-6 h-6 dark:hidden" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z"/>
                    </svg>

                    <!-- Moon icon (visible in light mode) -->
                    <svg class="w-6 h-6 hidden dark:block" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/>
                    </svg>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main id="main-content" class="container mx-auto px-4 sm:px-6 lg:px-8 py-8 min-h-screen">
        {% block content %}{% endblock %}
    </main>

    <!-- Footer -->
    <footer class="bg-white dark:bg-dark-container border-t border-gray-200 dark:border-dark-border mt-12 py-6">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex flex-col md:flex-row items-center justify-between gap-4">
                <p class="text-sm text-gray-600 dark:text-gray-400">
                    &copy; 2025 PCAP Analyzer | Version 1.0
                </p>
                <p class="text-xs text-gray-500 dark:text-gray-500">
                    Powered by FastAPI + Tailwind CSS
                </p>
            </div>
        </div>
    </footer>

    <!-- Scripts -->
    <script src="/static/js/theme.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
```

---

## 3. Landing Page Components

### upload.html (Page complète)

```html
{% extends "base.html" %}

{% block title %}Upload PCAP - PCAP Analyzer{% endblock %}

{% block content %}
<!-- Hero Section -->
<section class="text-center mb-12 animate-fade-in">
    <h2 class="text-xl md:text-2xl text-gray-600 dark:text-gray-400 mb-4">
        Network Traffic Analysis Made Simple
    </h2>
    <p class="text-base text-gray-500 dark:text-gray-500 max-w-2xl mx-auto">
        Upload, analyze, and visualize PCAP files with comprehensive network insights,
        health scoring, and automated diagnostics.
    </p>
</section>

<!-- Upload Zone -->
<section class="max-w-3xl mx-auto mb-12">
    <div id="drop-zone"
         class="relative border-4 border-dashed border-gray-300 dark:border-gray-600
                rounded-xl p-12 bg-gray-50 dark:bg-dark-section
                hover:border-primary hover:bg-primary/5 dark:hover:bg-primary/10
                transition-all duration-300 cursor-pointer group"
         role="button"
         tabindex="0"
         aria-label="Upload PCAP file. Drag and drop or press Enter to select file.">

        <!-- Hidden file input -->
        <input type="file"
               id="pcap-file-input"
               name="pcap_file"
               accept=".pcap,.pcapng"
               class="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
               aria-label="PCAP file input">

        <!-- Drop zone content -->
        <div class="flex flex-col items-center justify-center text-center pointer-events-none">
            <!-- Icon -->
            <div class="w-20 h-20 mb-4 bg-primary/10 dark:bg-primary/20 rounded-full
                        flex items-center justify-center
                        group-hover:scale-110 transition-transform duration-300">
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
                <span class="px-3 py-1 bg-white dark:bg-dark-container rounded-full
                             text-xs text-gray-600 dark:text-gray-400
                             border border-gray-200 dark:border-gray-700">
                    .pcap / .pcapng
                </span>
                <span class="px-3 py-1 bg-white dark:bg-dark-container rounded-full
                             text-xs text-gray-600 dark:text-gray-400
                             border border-gray-200 dark:border-gray-700">
                    Max 500MB
                </span>
            </div>
        </div>
    </div>

    <!-- File preview (hidden by default, shown after selection) -->
    <div id="file-preview" class="hidden mt-4 animate-slide-up">
        <div class="flex items-center justify-between bg-white dark:bg-dark-container
                    border border-gray-200 dark:border-gray-700 rounded-lg p-4">
            <div class="flex items-center gap-3">
                <!-- File icon -->
                <div class="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center">
                    <span class="text-2xl">📦</span>
                </div>

                <!-- File info -->
                <div>
                    <p id="file-name" class="font-medium text-secondary dark:text-dark-text">
                        <!-- Filled by JS -->
                    </p>
                    <p id="file-size" class="text-sm text-gray-500 dark:text-gray-400">
                        <!-- Filled by JS -->
                    </p>
                </div>
            </div>

            <!-- Remove button -->
            <button id="remove-file"
                    class="p-2 rounded-full text-gray-400 hover:text-danger
                           hover:bg-danger/10 transition-colors duration-200"
                    aria-label="Remove file">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M6 18L18 6M6 6l12 12"/>
                </svg>
            </button>
        </div>

        <!-- Validation message -->
        <div id="validation-message" class="mt-2">
            <!-- Filled by JS -->
        </div>

        <!-- Analyze button -->
        <button id="analyze-btn"
                class="btn-primary w-full mt-4 px-6 py-4 text-lg"
                disabled>
            Analyze PCAP File
        </button>
    </div>
</section>

<!-- Features Grid -->
<section class="max-w-5xl mx-auto mb-12">
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- Feature 1 -->
        <div class="card text-center">
            <div class="text-4xl mb-3">⚡</div>
            <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-2">
                Fast Analysis
            </h3>
            <p class="text-sm text-gray-600 dark:text-gray-400">
                Optimized for large captures up to 500MB with streaming mode support.
            </p>
        </div>

        <!-- Feature 2 -->
        <div class="card text-center">
            <div class="text-4xl mb-3">📊</div>
            <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-2">
                Detailed Reports
            </h3>
            <p class="text-sm text-gray-600 dark:text-gray-400">
                Comprehensive HTML + JSON exports with health scoring and insights.
            </p>
        </div>

        <!-- Feature 3 -->
        <div class="card text-center">
            <div class="text-4xl mb-3">🛡️</div>
            <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-2">
                Secure & Private
            </h3>
            <p class="text-sm text-gray-600 dark:text-gray-400">
                Files deleted after 24h automatically. No data retention.
            </p>
        </div>
    </div>
</section>

<!-- What happens next -->
<section class="max-w-3xl mx-auto mb-12">
    <div class="alert-info flex items-start gap-3">
        <span class="text-2xl flex-shrink-0">ℹ️</span>
        <div>
            <h4 class="font-semibold mb-2">What happens next?</h4>
            <ol class="list-decimal list-inside space-y-1 text-sm">
                <li>File validation (format, size, magic bytes)</li>
                <li>Real-time analysis progress tracking</li>
                <li>Comprehensive HTML report generation</li>
                <li>Automatic cleanup after 24h</li>
            </ol>
        </div>
    </div>
</section>

<!-- Recent Analyses -->
<section class="max-w-3xl mx-auto">
    <div class="card">
        <h3 class="text-xl font-semibold text-secondary dark:text-dark-text mb-4
                   flex items-center justify-between">
            <span>📜 Recent Analyses (Last 24h)</span>
            <a href="/history"
               class="text-sm text-primary hover:underline">
                View All →
            </a>
        </h3>

        <div id="recent-analyses" class="space-y-2">
            <!-- Filled by JS via API call -->
            <p class="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
                Loading recent analyses...
            </p>
        </div>
    </div>
</section>
{% endblock %}

{% block scripts %}
<script src="/static/js/upload.js"></script>
{% endblock %}
```

---

## 4. Progress Page Components

### progress.html

```html
{% extends "base.html" %}

{% block title %}Analysis Progress - PCAP Analyzer{% endblock %}

{% block content %}
<!-- Back button -->
<div class="mb-4">
    <a href="/"
       class="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400
              hover:text-primary transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
        </svg>
        Back to Upload
    </a>
</div>

<!-- File Metadata -->
<section class="card mb-6">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
        <div>
            <p class="text-gray-500 dark:text-gray-400 mb-1">File</p>
            <p id="file-name" class="font-mono font-medium text-secondary dark:text-dark-text">
                Loading...
            </p>
        </div>
        <div>
            <p class="text-gray-500 dark:text-gray-400 mb-1">Size</p>
            <p id="file-size" class="font-semibold">
                --
            </p>
        </div>
        <div>
            <p class="text-gray-500 dark:text-gray-400 mb-1">Mode</p>
            <span id="analysis-mode" class="badge-info">
                --
            </span>
        </div>
        <div>
            <p class="text-gray-500 dark:text-gray-400 mb-1">Started</p>
            <p id="start-time" class="text-gray-600 dark:text-gray-400">
                --
            </p>
        </div>
    </div>
</section>

<!-- Overall Progress -->
<section class="card mb-6">
    <h3 class="text-lg font-semibold text-center mb-4 text-secondary dark:text-dark-text">
        Overall Progress
    </h3>

    <!-- Progress bar -->
    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4 overflow-hidden mb-4">
        <div id="overall-progress-bar"
             class="h-full rounded-full bg-gradient-to-r from-primary to-accent
                    transition-all duration-500 ease-out relative overflow-hidden"
             style="width: 0%"
             role="progressbar"
             aria-valuenow="0"
             aria-valuemin="0"
             aria-valuemax="100">
            <!-- Shimmer overlay -->
            <div class="shimmer-overlay"></div>
        </div>
    </div>

    <!-- Progress text -->
    <div class="text-center">
        <p id="progress-percentage" class="text-3xl font-bold text-primary mb-2">
            0%
        </p>
        <p id="progress-phase" class="text-lg font-semibold text-secondary dark:text-dark-text mb-1">
            Initializing...
        </p>
        <p id="progress-detail" class="text-sm text-gray-600 dark:text-gray-400">
            Please wait...
        </p>
    </div>
</section>

<!-- Phase Details -->
<section class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
    <!-- Phase 1 -->
    <div id="phase1-card"
         class="card border-l-4 border-gray-300 dark:border-gray-600">
        <div class="flex items-center justify-between mb-3">
            <h3 class="text-lg font-semibold text-gray-400">
                <span id="phase1-icon">⏸️</span> PHASE 1
            </h3>
            <span id="phase1-status" class="text-sm text-gray-500">
                Pending
            </span>
        </div>

        <h4 class="font-medium text-secondary dark:text-dark-text mb-2">
            Metadata Extraction
        </h4>

        <p id="phase1-progress" class="text-sm text-gray-600 dark:text-gray-400 mb-3">
            0% (0s)
        </p>

        <!-- Sub-tasks -->
        <ul id="phase1-tasks" class="space-y-1 text-sm">
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> Packet count
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> Duration
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> IP addresses
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> Protocols
            </li>
        </ul>
    </div>

    <!-- Phase 2 -->
    <div id="phase2-card"
         class="card border-l-4 border-gray-300 dark:border-gray-600">
        <div class="flex items-center justify-between mb-3">
            <h3 class="text-lg font-semibold text-gray-400">
                <span id="phase2-icon">⏸️</span> PHASE 2
            </h3>
            <span id="phase2-status" class="text-sm text-gray-500">
                Pending
            </span>
        </div>

        <h4 class="font-medium text-secondary dark:text-dark-text mb-2">
            Deep Protocol Analysis
        </h4>

        <p id="phase2-progress" class="text-sm text-gray-600 dark:text-gray-400 mb-3">
            Waiting...
        </p>

        <!-- Sub-tasks -->
        <ul id="phase2-tasks" class="space-y-1 text-sm">
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> TCP analysis
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> UDP analysis
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> DNS analysis
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> Retransmissions
            </li>
            <li class="flex items-center gap-2 text-gray-500 dark:text-gray-400">
                <span>⏸️</span> Health scoring
            </li>
        </ul>
    </div>
</section>

<!-- Memory Usage -->
<section class="card mb-6">
    <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-3">
        📊 Memory Usage
    </h3>

    <div class="mb-2">
        <div class="flex justify-between text-sm mb-1">
            <span class="text-gray-600 dark:text-gray-400">
                Current: <span id="mem-current" class="font-semibold">0 GB</span> /
                <span id="mem-total">4.0 GB</span> available
            </span>
            <span class="text-gray-600 dark:text-gray-400">
                Peak: <span id="mem-peak" class="font-semibold">0 GB</span>
            </span>
        </div>

        <!-- Memory progress bar -->
        <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div id="mem-progress-bar"
                 class="h-full rounded-full bg-gradient-to-r from-success to-warning
                        transition-all duration-500"
                 style="width: 0%">
            </div>
        </div>
    </div>
</section>

<!-- Live Log -->
<section class="card">
    <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-3">
        📝 Live Log
    </h3>

    <div id="log-container"
         class="max-h-48 overflow-y-auto space-y-1 font-mono text-xs
                text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-dark-section
                p-3 rounded">
        <p>[--:--:--] Waiting for updates...</p>
    </div>
</section>

<!-- Screen reader live region -->
<div id="sr-progress"
     role="status"
     aria-live="polite"
     aria-atomic="true"
     class="sr-only">
</div>
{% endblock %}

{% block scripts %}
<script>
    const TASK_ID = "{{ task_id }}";
</script>
<script src="/static/js/progress.js"></script>
{% endblock %}
```

---

## 5. Report Page Components

### report.html (Iframe approach)

```html
{% extends "base.html" %}

{% block title %}Analysis Report - PCAP Analyzer{% endblock %}

{% block content %}
<!-- Back button -->
<div class="mb-4">
    <a href="/"
       class="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400
              hover:text-primary transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
        </svg>
        New Analysis
    </a>
</div>

<!-- Report Header -->
<section class="card mb-6">
    <div class="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-4">
        <div>
            <h2 class="text-2xl font-bold text-secondary dark:text-dark-text mb-2">
                📊 PCAP Analyzer Report
            </h2>
            <div class="text-sm text-gray-600 dark:text-gray-400 space-y-1">
                <p>📦 <strong>File:</strong> {{ pcap_filename }}</p>
                <p>📅 <strong>Date:</strong> {{ analysis_date }}</p>
                <p>⏱️ <strong>Duration:</strong> {{ capture_duration }}s  |
                   📈 <strong>Packets:</strong> {{ total_packets }}</p>
            </div>
        </div>

        <!-- Action buttons -->
        <div class="flex flex-wrap gap-2">
            <a href="/download/{{ task_id }}/html"
               class="btn-secondary flex items-center gap-2"
               download>
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                Download HTML
            </a>

            <a href="/download/{{ task_id }}/json"
               class="btn-secondary flex items-center gap-2"
               download>
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                </svg>
                Download JSON
            </a>

            <a href="/"
               class="btn-primary flex items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                </svg>
                New Analysis
            </a>
        </div>
    </div>
</section>

<!-- Embedded HTML Report -->
<section class="mb-6">
    <iframe id="report-iframe"
            src="/reports/{{ task_id }}.html"
            class="w-full border border-gray-200 dark:border-gray-700 rounded-lg shadow-md"
            style="height: 80vh; min-height: 600px;"
            title="PCAP Analysis Report"
            sandbox="allow-same-origin allow-scripts">
    </iframe>
</section>

<!-- Share Section -->
<section class="card max-w-2xl mx-auto">
    <h3 class="text-lg font-semibold text-secondary dark:text-dark-text mb-3 flex items-center gap-2">
        <span>🔗</span> Share this report
    </h3>

    <div class="space-y-2 text-sm mb-4">
        <p class="text-gray-600 dark:text-gray-400">
            <strong>Task ID:</strong>
            <code class="px-2 py-1 bg-gray-100 dark:bg-dark-section rounded font-mono">
                {{ task_id }}
            </code>
        </p>
        <p class="text-gray-600 dark:text-gray-400">
            <strong>Valid until:</strong> {{ expiration_date }} (24h)
        </p>
    </div>

    <button id="copy-link-btn"
            class="btn-secondary w-full md:w-auto flex items-center gap-2 justify-center">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
        </svg>
        Copy Link
    </button>
</section>
{% endblock %}

{% block scripts %}
<script>
    document.getElementById('copy-link-btn').addEventListener('click', async () => {
        const url = window.location.href;
        try {
            await navigator.clipboard.writeText(url);
            alert('Link copied to clipboard!');
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    });
</script>
{% endblock %}
```

---

## 6. History Page Components

### history.html

```html
{% extends "base.html" %}

{% block title %}Analysis History - PCAP Analyzer{% endblock %}

{% block content %}
<!-- Back button -->
<div class="mb-4">
    <a href="/"
       class="inline-flex items-center gap-2 text-gray-600 dark:text-gray-400
              hover:text-primary transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
        </svg>
        Back to Home
    </a>
</div>

<!-- Header -->
<section class="mb-6">
    <h2 class="text-2xl font-bold text-secondary dark:text-dark-text mb-4">
        📜 Recent Analyses (Last 24h)
    </h2>

    <!-- Filters & Search -->
    <div class="flex flex-col md:flex-row gap-4">
        <!-- Search -->
        <div class="flex-1">
            <label for="search" class="sr-only">Search analyses</label>
            <div class="relative">
                <input type="text"
                       id="search"
                       placeholder="Search by filename or task ID..."
                       class="w-full px-4 py-2 pl-10 border border-gray-300 dark:border-gray-600
                              rounded-lg bg-white dark:bg-dark-section
                              text-gray-900 dark:text-dark-text
                              focus:ring-2 focus:ring-primary focus:border-primary">
                <svg class="w-5 h-5 absolute left-3 top-3 text-gray-400"
                     fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                          d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
            </div>
        </div>

        <!-- Filter by status -->
        <div>
            <label for="status-filter" class="sr-only">Filter by status</label>
            <select id="status-filter"
                    class="px-4 py-2 border border-gray-300 dark:border-gray-600
                           rounded-lg bg-white dark:bg-dark-section
                           text-gray-900 dark:text-dark-text
                           focus:ring-2 focus:ring-primary focus:border-primary">
                <option value="all">All Status</option>
                <option value="completed">Completed</option>
                <option value="processing">Processing</option>
                <option value="failed">Failed</option>
            </select>
        </div>

        <!-- Sort -->
        <div>
            <label for="sort" class="sr-only">Sort by</label>
            <select id="sort"
                    class="px-4 py-2 border border-gray-300 dark:border-gray-600
                           rounded-lg bg-white dark:bg-dark-section
                           text-gray-900 dark:text-dark-text
                           focus:ring-2 focus:ring-primary focus:border-primary">
                <option value="date-desc">Date (Newest first)</option>
                <option value="date-asc">Date (Oldest first)</option>
                <option value="size-desc">Size (Largest first)</option>
                <option value="size-asc">Size (Smallest first)</option>
            </select>
        </div>
    </div>
</section>

<!-- Analyses List -->
<section id="analyses-list" class="space-y-4 mb-6">
    <!-- Filled by JavaScript -->
    <p class="text-center text-gray-500 dark:text-gray-400 py-8">
        Loading analyses...
    </p>
</section>

<!-- Load More Button -->
<div id="load-more-container" class="text-center mb-6 hidden">
    <button id="load-more-btn" class="btn-secondary">
        Load More...
    </button>
</div>

<!-- Statistics -->
<section class="card-gradient">
    <h3 class="text-xl font-semibold mb-4">📊 Statistics (Last 24h)</h3>

    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
        <div>
            <p class="text-3xl font-bold" id="stat-total">--</p>
            <p class="text-sm opacity-90">Total Analyses</p>
        </div>
        <div>
            <p class="text-3xl font-bold" id="stat-completed">--</p>
            <p class="text-sm opacity-90">Completed</p>
        </div>
        <div>
            <p class="text-3xl font-bold" id="stat-failed">--</p>
            <p class="text-sm opacity-90">Failed</p>
        </div>
        <div>
            <p class="text-3xl font-bold" id="stat-data">--</p>
            <p class="text-sm opacity-90">Data Processed</p>
        </div>
    </div>
</section>
{% endblock %}

{% block scripts %}
<script src="/static/js/history.js"></script>
{% endblock %}
```

---

## 7. JavaScript Utilities

### theme.js (Dark mode toggle)

```javascript
/**
 * Dark Mode Toggle
 * Handles theme switching with localStorage persistence
 */
(function() {
    const html = document.documentElement;
    const toggle = document.getElementById('theme-toggle');

    // Initialize from localStorage or system preference
    const initDarkMode = () => {
        const storedPreference = localStorage.getItem('darkMode');

        if (storedPreference !== null) {
            return storedPreference === 'true';
        }

        // Fall back to system preference
        return window.matchMedia('(prefers-color-scheme: dark)').matches;
    };

    // Apply dark mode
    const setDarkMode = (isDark) => {
        html.classList.toggle('dark', isDark);
        localStorage.setItem('darkMode', isDark);
    };

    // Initialize on page load
    setDarkMode(initDarkMode());

    // Toggle on button click
    toggle?.addEventListener('click', () => {
        const isDark = html.classList.contains('dark');
        setDarkMode(!isDark);
    });

    // Listen to system preference changes
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        if (localStorage.getItem('darkMode') === null) {
            setDarkMode(e.matches);
        }
    });
})();
```

### upload.js (File upload handling)

```javascript
/**
 * Upload Page Logic
 * Handles drag & drop, file validation, and upload
 */

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('pcap-file-input');
const filePreview = document.getElementById('file-preview');
const fileName = document.getElementById('file-name');
const fileSize = document.getElementById('file-size');
const removeFileBtn = document.getElementById('remove-file');
const analyzeBtn = document.getElementById('analyze-btn');
const validationMessage = document.getElementById('validation-message');

let selectedFile = null;

// File size formatter
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Validate file
function validateFile(file) {
    const maxSize = 500 * 1024 * 1024; // 500MB
    const allowedExtensions = ['.pcap', '.pcapng'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!allowedExtensions.includes(fileExtension)) {
        return {
            valid: false,
            message: 'Invalid file format. Only .pcap and .pcapng files are supported.'
        };
    }

    if (file.size > maxSize) {
        return {
            valid: false,
            message: `File size (${formatBytes(file.size)}) exceeds maximum allowed size of 500MB.`
        };
    }

    return { valid: true, message: 'File validated successfully' };
}

// Handle file selection
function handleFileSelect(file) {
    selectedFile = file;

    const validation = validateFile(file);

    // Show preview
    filePreview.classList.remove('hidden');
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);

    // Show validation message
    if (validation.valid) {
        validationMessage.innerHTML = `
            <div class="alert-success flex items-center gap-2 text-sm">
                <span>✅</span> ${validation.message}
            </div>
        `;
        analyzeBtn.disabled = false;
    } else {
        validationMessage.innerHTML = `
            <div class="alert-danger flex items-center gap-2 text-sm">
                <span>❌</span> ${validation.message}
            </div>
        `;
        analyzeBtn.disabled = true;
    }
}

// Drag & Drop handlers
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('border-primary', 'bg-primary/10', 'scale-[1.02]');
});

dropZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-primary', 'bg-primary/10', 'scale-[1.02]');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('border-primary', 'bg-primary/10', 'scale-[1.02]');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

// File input change
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

// Keyboard support for drop zone
dropZone.addEventListener('keydown', (e) => {
    if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault();
        fileInput.click();
    }
});

// Remove file
removeFileBtn.addEventListener('click', () => {
    selectedFile = null;
    fileInput.value = '';
    filePreview.classList.add('hidden');
});

// Analyze button
analyzeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `
        <svg class="inline-block animate-spin h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Uploading...
    `;

    try {
        const formData = new FormData();
        formData.append('pcap_file', selectedFile);

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Upload failed: ${response.statusText}`);
        }

        const data = await response.json();

        // Redirect to progress page
        window.location.href = `/progress/${data.task_id}`;

    } catch (error) {
        console.error('Upload error:', error);
        validationMessage.innerHTML = `
            <div class="alert-danger flex items-center gap-2 text-sm">
                <span>❌</span> Upload failed: ${error.message}
            </div>
        `;
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = 'Analyze PCAP File';
    }
});

// Load recent analyses
async function loadRecentAnalyses() {
    try {
        const response = await fetch('/api/analyses?limit=3');
        if (!response.ok) throw new Error('Failed to load recent analyses');

        const analyses = await response.json();
        const container = document.getElementById('recent-analyses');

        if (analyses.length === 0) {
            container.innerHTML = `
                <p class="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
                    No recent analyses found.
                </p>
            `;
            return;
        }

        container.innerHTML = analyses.map(analysis => `
            <div class="flex items-center justify-between p-3 rounded
                        hover:bg-gray-50 dark:hover:bg-dark-section transition-colors">
                <div class="flex items-center gap-3">
                    <span class="text-2xl">📦</span>
                    <div>
                        <p class="font-medium text-sm">${analysis.filename}</p>
                        <p class="text-xs text-gray-500 dark:text-gray-400">
                            ${analysis.task_id.substring(0, 12)}...
                        </p>
                    </div>
                </div>
                <div class="flex items-center gap-3">
                    ${getStatusBadge(analysis.status)}
                    ${analysis.health_score ? `<span class="text-sm">${getHealthEmoji(analysis.health_score)} ${analysis.health_score}/100</span>` : ''}
                    <span class="text-xs text-gray-500">${formatTimeAgo(analysis.created_at)}</span>
                </div>
            </div>
        `).join('');

    } catch (error) {
        console.error('Error loading recent analyses:', error);
    }
}

function getStatusBadge(status) {
    const badges = {
        'completed': '<span class="badge-success">✅ Completed</span>',
        'processing': '<span class="badge-warning animate-pulse">⏳ Processing</span>',
        'failed': '<span class="badge-danger">❌ Failed</span>',
        'pending': '<span class="badge-info">⏸️ Pending</span>'
    };
    return badges[status] || badges['pending'];
}

function getHealthEmoji(score) {
    if (score >= 90) return '🟢';
    if (score >= 70) return '🟡';
    if (score >= 50) return '🟠';
    return '🔴';
}

function formatTimeAgo(timestamp) {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now - then;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
}

// Initialize
loadRecentAnalyses();
```

---

## 8. API Integration Examples

### progress.js (SSE streaming)

```javascript
/**
 * Progress Page - Real-time SSE Updates
 */

const TASK_ID = window.TASK_ID || new URLSearchParams(window.location.search).get('task_id');

let eventSource = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

// DOM elements
const overallProgressBar = document.getElementById('overall-progress-bar');
const progressPercentage = document.getElementById('progress-percentage');
const progressPhase = document.getElementById('progress-phase');
const progressDetail = document.getElementById('progress-detail');
const logContainer = document.getElementById('log-container');
const srProgress = document.getElementById('sr-progress');

// Memory elements
const memCurrent = document.getElementById('mem-current');
const memPeak = document.getElementById('mem-peak');
const memProgressBar = document.getElementById('mem-progress-bar');

// Initialize SSE connection
function connectSSE() {
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource(`/api/progress/${TASK_ID}`);

    eventSource.onopen = () => {
        console.log('SSE connection established');
        reconnectAttempts = 0;
    };

    eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleProgressUpdate(data);
        } catch (error) {
            console.error('Error parsing SSE data:', error);
        }
    };

    eventSource.onerror = (error) => {
        console.error('SSE error:', error);
        eventSource.close();

        if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            reconnectAttempts++;
            setTimeout(() => {
                console.log(`Reconnecting... (attempt ${reconnectAttempts})`);
                connectSSE();
            }, 2000 * reconnectAttempts);
        } else {
            showError('Connection lost. Please refresh the page.');
        }
    };

    // Close connection on page unload
    window.addEventListener('beforeunload', () => {
        if (eventSource) {
            eventSource.close();
        }
    });
}

// Handle progress updates
function handleProgressUpdate(data) {
    console.log('Progress update:', data);

    // Update overall progress
    if (data.progress !== undefined) {
        const progress = Math.min(100, Math.max(0, data.progress));
        overallProgressBar.style.width = `${progress}%`;
        overallProgressBar.setAttribute('aria-valuenow', progress);
        progressPercentage.textContent = `${Math.round(progress)}%`;
    }

    // Update phase info
    if (data.phase) {
        progressPhase.textContent = formatPhase(data.phase);
    }

    if (data.detail) {
        progressDetail.textContent = data.detail;
    }

    // Update phase cards
    if (data.phase1) {
        updatePhaseCard('phase1', data.phase1);
    }

    if (data.phase2) {
        updatePhaseCard('phase2', data.phase2);
    }

    // Update memory usage
    if (data.memory) {
        updateMemoryUsage(data.memory);
    }

    // Add log entry
    if (data.log) {
        addLogEntry(data.log);
    }

    // Update screen reader
    srProgress.textContent = `Analysis progress: ${Math.round(data.progress)}%`;

    // Check if completed
    if (data.status === 'completed') {
        eventSource.close();
        setTimeout(() => {
            window.location.href = `/report/${TASK_ID}`;
        }, 2000);
    }

    // Check if failed
    if (data.status === 'failed') {
        eventSource.close();
        showError(data.error || 'Analysis failed');
    }
}

function formatPhase(phase) {
    const phases = {
        'metadata': 'Phase 1/2: Metadata Extraction (dpkt)',
        'analysis': 'Phase 2/2: Deep Analysis (Scapy)',
        'completed': 'Analysis Completed!',
        'failed': 'Analysis Failed'
    };
    return phases[phase] || phase;
}

function updatePhaseCard(phaseId, data) {
    const card = document.getElementById(`${phaseId}-card`);
    const icon = document.getElementById(`${phaseId}-icon`);
    const status = document.getElementById(`${phaseId}-status`);
    const progress = document.getElementById(`${phaseId}-progress`);

    if (data.status === 'completed') {
        card.classList.remove('border-gray-300', 'dark:border-gray-600', 'border-warning');
        card.classList.add('border-success', 'bg-green-50', 'dark:bg-green-900/20');
        icon.textContent = '✅';
        status.textContent = 'Completed';
        progress.textContent = `100% (${data.duration}s)`;
    } else if (data.status === 'in_progress') {
        card.classList.remove('border-gray-300', 'dark:border-gray-600');
        card.classList.add('border-warning');
        icon.textContent = '⏳';
        status.textContent = 'In Progress';
        progress.textContent = `${data.progress}% (${data.elapsed}s elapsed)`;
    }

    // Update sub-tasks if provided
    if (data.tasks) {
        const tasksList = document.getElementById(`${phaseId}-tasks`);
        data.tasks.forEach((task, index) => {
            const li = tasksList.children[index];
            if (li) {
                const iconSpan = li.querySelector('span');
                if (task.completed) {
                    iconSpan.textContent = '✅';
                    li.classList.remove('text-gray-500', 'dark:text-gray-400');
                    li.classList.add('text-success');
                } else if (task.in_progress) {
                    iconSpan.textContent = '⏳';
                }
            }
        });
    }
}

function updateMemoryUsage(memory) {
    const current = (memory.current / 1024 / 1024 / 1024).toFixed(2);
    const peak = (memory.peak / 1024 / 1024 / 1024).toFixed(2);
    const percentage = (memory.current / memory.total * 100).toFixed(0);

    memCurrent.textContent = `${current} GB`;
    memPeak.textContent = `${peak} GB`;
    memProgressBar.style.width = `${percentage}%`;

    // Change color based on usage
    if (percentage > 80) {
        memProgressBar.classList.remove('from-success', 'to-warning');
        memProgressBar.classList.add('from-warning', 'to-danger');
    }
}

function addLogEntry(message) {
    const timestamp = new Date().toLocaleTimeString('fr-FR', { hour12: false });
    const entry = document.createElement('p');
    entry.className = 'animate-slide-up';
    entry.textContent = `[${timestamp}] ${message}`;

    logContainer.insertBefore(entry, logContainer.firstChild);

    // Keep only last 50 entries
    while (logContainer.children.length > 50) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

function showError(message) {
    progressPhase.textContent = 'Analysis Failed';
    progressPhase.className = 'text-lg font-semibold text-danger mb-1';
    progressDetail.textContent = message;

    overallProgressBar.classList.remove('from-primary', 'to-accent');
    overallProgressBar.classList.add('from-danger', 'to-danger');
}

// Initialize on page load
connectSSE();
```

---

## Conclusion

Ces extraits de code fournissent une base solide pour démarrer l'implémentation. Chaque fichier est prêt à l'emploi et suit strictement le design system défini.

**Prochaines étapes:**
1. Intégrer ces composants dans l'architecture FastAPI
2. Tester les interactions utilisateur
3. Ajuster les styles selon les retours
4. Optimiser les performances

---

**Créé par:** Agent UX/UI Designer
**Date:** 2025-12-12
**Version:** 1.0
