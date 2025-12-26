/**
 * PCAP Analyzer - Common JavaScript
 * Fonctions utilitaires, dark mode, toasts, health check
 */

// ========================================
// 1. DARK MODE
// ========================================

class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'light';
        this.init();
    }

    init() {
        // Appliquer le thème initial
        if (this.theme === 'dark') {
            document.documentElement.classList.add('dark');
        }

        // Event listener pour le toggle
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.addEventListener('click', () => this.toggle());
        }
    }

    toggle() {
        // Disable transitions temporairement
        document.documentElement.classList.add('no-transition');

        if (this.theme === 'light') {
            this.theme = 'dark';
            document.documentElement.classList.add('dark');
        } else {
            this.theme = 'light';
            document.documentElement.classList.remove('dark');
        }

        localStorage.setItem('theme', this.theme);

        // Re-enable transitions
        setTimeout(() => {
            document.documentElement.classList.remove('no-transition');
        }, 100);
    }
}

// ========================================
// 2. SECURITY UTILS
// ========================================

class SecurityUtils {
    /**
     * Escape HTML special characters to prevent XSS attacks.
     * @param {string} text - The text to escape.
     * @returns {string} - The escaped HTML.
     */
    static escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// ========================================
// 3. TOAST NOTIFICATIONS
// ========================================

class ToastManager {
    constructor() {
        this.container = document.getElementById('toast-container');
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.id = 'toast-container';
            this.container.className = 'fixed top-4 right-4 z-50 space-y-2';
            document.body.appendChild(this.container);
        }
    }

    show(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icon = this.getIcon(type);
        const escapedMessage = SecurityUtils.escapeHtml(message);

        toast.innerHTML = `
            <div class="flex-shrink-0">
                <i class="${icon} text-xl"></i>
            </div>
            <div class="flex-1">
                <p class="font-medium">${escapedMessage}</p>
            </div>
            <button class="flex-shrink-0 ml-4 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                    onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        this.container.appendChild(toast);

        // Auto-remove après duration
        if (duration > 0) {
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    }

    getIcon(type) {
        const icons = {
            success: 'fas fa-check-circle text-success',
            error: 'fas fa-exclamation-circle text-danger',
            warning: 'fas fa-exclamation-triangle text-warning',
            info: 'fas fa-info-circle text-primary'
        };
        return icons[type] || icons.info;
    }

    success(message, duration) {
        return this.show(message, 'success', duration);
    }

    error(message, duration) {
        return this.show(message, 'error', duration);
    }

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    }

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
}

// ========================================
// 3. HEALTH CHECK MONITOR
// ========================================

class HealthMonitor {
    constructor(interval = 30000) {
        this.interval = interval;
        this.statusElement = document.getElementById('health-status');
        this.check();
        setInterval(() => this.check(), this.interval);
    }

    async check() {
        try {
            const response = await fetch('/api/health');
            const data = await response.json();

            if (this.statusElement) {
                this.updateStatus(data.status === 'healthy');
            }
        } catch (error) {
            console.error('Health check failed:', error);
            if (this.statusElement) {
                this.updateStatus(false);
            }
        }
    }

    updateStatus(healthy) {
        if (!this.statusElement) return;

        if (healthy) {
            this.statusElement.innerHTML = `
                <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                <span class="text-sm font-medium text-green-700 dark:text-green-300">Healthy</span>
            `;
            this.statusElement.className = 'hidden md:flex items-center space-x-2 px-3 py-1 rounded-full bg-green-100 dark:bg-green-900';
        } else {
            this.statusElement.innerHTML = `
                <span class="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
                <span class="text-sm font-medium text-red-700 dark:text-red-300">Unhealthy</span>
            `;
            this.statusElement.className = 'hidden md:flex items-center space-x-2 px-3 py-1 rounded-full bg-red-100 dark:bg-red-900';
        }
    }
}

// ========================================
// 4. UTILITY FUNCTIONS
// ========================================

const Utils = {
    /**
     * Escape HTML special characters to prevent XSS attacks.
     */
    escapeHtml(text) {
        return SecurityUtils.escapeHtml(text);
    },

    /**
     * Formate une taille de fichier en octets vers une chaîne lisible
     */
    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    },

    /**
     * Formate une durée en secondes vers une chaîne lisible
     */
    formatDuration(seconds) {
        if (seconds < 60) {
            return `${Math.round(seconds)}s`;
        } else if (seconds < 3600) {
            const mins = Math.floor(seconds / 60);
            const secs = Math.round(seconds % 60);
            return `${mins}m ${secs}s`;
        } else {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
    },

    /**
     * Formate une date ISO vers une chaîne lisible
     */
    formatDate(isoString) {
        const date = new Date(isoString);
        return date.toLocaleString('fr-FR', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    },

    /**
     * Formate un timestamp relatif (il y a X minutes)
     */
    formatRelativeTime(isoString) {
        const date = new Date(isoString);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffSec < 60) return 'À l\'instant';
        if (diffMin < 60) return `Il y a ${diffMin} min`;
        if (diffHour < 24) return `Il y a ${diffHour}h`;
        if (diffDay < 7) return `Il y a ${diffDay}j`;
        return this.formatDate(isoString);
    },

    /**
     * Copie du texte dans le clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            window.toast.success('Copié dans le presse-papier');
        } catch (err) {
            window.toast.error('Erreur lors de la copie');
        }
    },

    /**
     * Récupère le badge CSS pour un statut
     */
    getStatusBadge(status) {
        const badges = {
            pending: 'badge-pending',
            processing: 'badge-processing',
            completed: 'badge-completed',
            failed: 'badge-failed',
            expired: 'badge-expired'
        };
        return badges[status] || 'badge-pending';
    },

    /**
     * Récupère l'icône pour un statut
     */
    getStatusIcon(status) {
        const icons = {
            pending: 'fas fa-clock text-gray-500',
            processing: 'fas fa-spinner fa-spin text-blue-500',
            completed: 'fas fa-check-circle text-green-500',
            failed: 'fas fa-exclamation-circle text-red-500',
            expired: 'fas fa-hourglass-end text-orange-500'
        };
        return icons[status] || icons.pending;
    },

    /**
     * Génère un UUID v4 simple
     */
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    },

    /**
     * Debounce function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Throttle function
     */
    throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
};

// ========================================
// 5. LOADING OVERLAY
// ========================================

class LoadingOverlay {
    constructor() {
        this.overlay = null;
    }

    show(title = 'Chargement...', message = 'Veuillez patienter') {
        // Supprimer l'overlay existant si présent
        this.hide();

        // Créer l'overlay
        this.overlay = document.createElement('div');
        this.overlay.className = 'loading-overlay';
        this.overlay.innerHTML = `
            <div class="loading-content">
                <div class="loading-spinner">
                    <div class="spinner-dot"></div>
                </div>
                <div class="loading-title">${title}</div>
                <div class="loading-message">${message}</div>
            </div>
        `;

        document.body.appendChild(this.overlay);
    }

    update(title, message) {
        if (this.overlay) {
            const titleEl = this.overlay.querySelector('.loading-title');
            const messageEl = this.overlay.querySelector('.loading-message');
            if (titleEl) titleEl.textContent = title;
            if (messageEl) messageEl.textContent = message;
        }
    }

    hide() {
        if (this.overlay && this.overlay.parentNode) {
            this.overlay.parentNode.removeChild(this.overlay);
            this.overlay = null;
        }
    }
}

// ========================================
// 6. INITIALIZATION
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme manager
    window.themeManager = new ThemeManager();

    // Initialize toast manager
    window.toast = new ToastManager();

    // Initialize health monitor
    window.healthMonitor = new HealthMonitor();

    // Initialize loading overlay
    window.loadingOverlay = new LoadingOverlay();

    // Expose utils globally
    window.utils = Utils;

    // Show Admin link only for admin users
    checkAdminAccess();

    // Initialize user menu
    initializeUserMenu();

    console.log('PCAP Analyzer - Common JS initialized');
});

// ========================================
// 7. ADMIN ACCESS CHECK
// ========================================

async function checkAdminAccess() {
    const adminNavLink = document.getElementById('admin-nav-link');
    if (!adminNavLink) return; // Not on a page with admin link

    const token = localStorage.getItem('access_token');
    if (!token) return; // Not logged in

    try {
        const response = await fetch('/api/users/me', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        if (response.ok) {
            const user = await response.json();
            // Show admin link only for admin users
            if (user.role === 'admin') {
                adminNavLink.classList.remove('hidden');
            }
        }
    } catch (error) {
        // Silently fail - user is not logged in or network error
        console.debug('Admin access check failed:', error);
    }
}

// ========================================
// 8. USER MENU
// ========================================

function initializeUserMenu() {
    const userMenu = document.getElementById('user-menu');
    const userMenuButton = document.getElementById('user-menu-button');
    const userMenuDropdown = document.getElementById('user-menu-dropdown');
    const logoutBtn = document.getElementById('logout-btn');

    if (!userMenu) return; // User menu not present on this page

    // Check if user is logged in
    const token = localStorage.getItem('access_token');
    const currentUserData = localStorage.getItem('current_user');

    if (token && currentUserData) {
        try {
            const user = JSON.parse(currentUserData);

            // Show user menu
            userMenu.classList.remove('hidden');

            // Set user initials (first 2 characters of username)
            const initials = user.username.substring(0, 2).toUpperCase();
            const userInitialsEl = document.getElementById('user-initials');
            if (userInitialsEl) {
                userInitialsEl.textContent = initials;
            }

            // Set dropdown user info
            const userMenuUsername = document.getElementById('user-menu-username');
            const userMenuRole = document.getElementById('user-menu-role');
            if (userMenuUsername) {
                userMenuUsername.textContent = user.username;
            }
            if (userMenuRole) {
                userMenuRole.textContent = user.role.toUpperCase();
            }

            // Toggle dropdown on button click
            if (userMenuButton && userMenuDropdown) {
                userMenuButton.addEventListener('click', (e) => {
                    e.stopPropagation();
                    userMenuDropdown.classList.toggle('hidden');
                });
            }

            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                if (userMenuDropdown && !userMenu.contains(e.target)) {
                    userMenuDropdown.classList.add('hidden');
                }
            });

            // Handle logout
            if (logoutBtn) {
                logoutBtn.addEventListener('click', () => {
                    handleLogout();
                });
            }
        } catch (error) {
            console.error('Failed to parse user data:', error);
            // Clear invalid data
            localStorage.removeItem('current_user');
        }
    }
}

function handleLogout() {
    // Clear all localStorage auth data
    localStorage.removeItem('access_token');
    localStorage.removeItem('token_type');
    localStorage.removeItem('current_user');

    // Clear CSRF token and stop auto-refresh
    if (window.csrfManager) {
        window.csrfManager.clear();
    }

    // Show toast notification
    if (window.toast) {
        window.toast.info('Déconnexion réussie', 2000);
    }

    // Redirect to login page after short delay
    setTimeout(() => {
        window.location.href = '/login';
    }, 500);
}
