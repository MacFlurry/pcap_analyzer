/**
 * PCAP Analyzer - CSRF Protection Client Manager
 * Implements Double Submit Cookie Pattern (OWASP ASVS 4.2.2)
 *
 * Security Features:
 * - Fetches CSRF token from authenticated endpoint
 * - Stores token securely in sessionStorage (NOT localStorage for security)
 * - Auto-refreshes token every 25 minutes (before 30-min expiration)
 * - Integrates with JWT authentication
 *
 * References:
 * - OWASP ASVS 4.2.2: Anti-CSRF tokens for authenticated functionality
 * - CWE-352: Cross-Site Request Forgery (CSRF)
 */

class CsrfManager {
    constructor() {
        this.tokenKey = 'csrf_token';
        this.headerNameKey = 'csrf_header_name';
        this.expirationKey = 'csrf_expiration';
        this.defaultHeaderName = 'X-CSRF-Token';
        this.refreshInterval = null;

        // IMPORTANT: Use sessionStorage (not localStorage) for CSRF tokens
        // CSRF tokens should not persist across browser sessions
        this.storage = sessionStorage;

        console.log('CsrfManager initialized');
    }

    /**
     * Initialize CSRF protection by fetching token
     * Should be called after successful login
     */
    async init() {
        const token = localStorage.getItem('access_token');
        if (!token) {
            console.warn('CsrfManager.init() - No JWT token found, cannot fetch CSRF token');
            return false;
        }

        console.log('CsrfManager.init() - Fetching CSRF token...');
        const success = await this.fetchToken();

        if (success) {
            // Start auto-refresh timer (every 25 minutes)
            this.startAutoRefresh();
            console.log('CsrfManager.init() - CSRF protection activated');
        } else {
            console.error('CsrfManager.init() - Failed to initialize CSRF protection');
        }

        return success;
    }

    /**
     * Fetch CSRF token from server
     * Requires valid JWT authentication
     */
    async fetchToken() {
        const jwtToken = localStorage.getItem('access_token');
        if (!jwtToken) {
            console.error('CsrfManager.fetchToken() - No JWT token available');
            return false;
        }

        try {
            const response = await fetch('/api/csrf/token', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${jwtToken}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!response.ok) {
                if (response.status === 401) {
                    console.error('CsrfManager.fetchToken() - JWT token expired or invalid');
                    // JWT expired, clear all auth data
                    this.clear();
                    localStorage.removeItem('access_token');
                    localStorage.removeItem('token_type');
                    localStorage.removeItem('current_user');
                    // Redirect to login will be handled by calling code
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            // Store CSRF token and metadata
            this.storage.setItem(this.tokenKey, data.csrf_token);
            this.storage.setItem(this.headerNameKey, data.header_name || this.defaultHeaderName);

            // Calculate and store expiration timestamp
            const expiresAt = Date.now() + (data.expires_in * 1000);
            this.storage.setItem(this.expirationKey, expiresAt.toString());

            console.log(
                'CsrfManager.fetchToken() - Token fetched successfully',
                `(expires in ${data.expires_in}s)`
            );

            return true;
        } catch (error) {
            console.error('CsrfManager.fetchToken() - Error:', error);
            return false;
        }
    }

    /**
     * Get CSRF token headers to include in requests
     * Returns object with CSRF header or empty object if no token
     */
    async getHeaders() {
        const token = this.storage.getItem(this.tokenKey);
        const headerName = this.storage.getItem(this.headerNameKey) || this.defaultHeaderName;

        // Check if token exists
        if (!token) {
            console.warn('CsrfManager.getHeaders() - No CSRF token available, fetching...');
            const success = await this.fetchToken();
            if (!success) {
                console.error('CsrfManager.getHeaders() - Failed to fetch CSRF token');
                return {};
            }
            // Retry getting token after fetch
            const newToken = this.storage.getItem(this.tokenKey);
            const newHeaderName = this.storage.getItem(this.headerNameKey) || this.defaultHeaderName;
            return newToken ? { [newHeaderName]: newToken } : {};
        }

        // Check if token is expired
        const expiresAt = parseInt(this.storage.getItem(this.expirationKey) || '0');
        const now = Date.now();

        if (expiresAt && now >= expiresAt) {
            console.warn('CsrfManager.getHeaders() - Token expired, refreshing...');
            const success = await this.fetchToken();
            if (!success) {
                console.error('CsrfManager.getHeaders() - Failed to refresh expired token');
                return {};
            }
            // Retry getting token after refresh
            const newToken = this.storage.getItem(this.tokenKey);
            const newHeaderName = this.storage.getItem(this.headerNameKey) || this.defaultHeaderName;
            return newToken ? { [newHeaderName]: newToken } : {};
        }

        return { [headerName]: token };
    }

    /**
     * Start auto-refresh timer
     * Refreshes CSRF token every 25 minutes (before 30-min expiration)
     */
    startAutoRefresh() {
        // Clear existing interval if any
        this.stopAutoRefresh();

        // Refresh every 25 minutes (1500000 ms)
        const refreshIntervalMs = 25 * 60 * 1000;

        this.refreshInterval = setInterval(async () => {
            console.log('CsrfManager - Auto-refreshing CSRF token...');
            const success = await this.fetchToken();
            if (!success) {
                console.error('CsrfManager - Auto-refresh failed, stopping timer');
                this.stopAutoRefresh();
            }
        }, refreshIntervalMs);

        console.log(`CsrfManager - Auto-refresh timer started (every ${refreshIntervalMs / 60000} minutes)`);
    }

    /**
     * Stop auto-refresh timer
     */
    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
            console.log('CsrfManager - Auto-refresh timer stopped');
        }
    }

    /**
     * Clear CSRF token and stop auto-refresh
     * Should be called on logout
     */
    clear() {
        this.storage.removeItem(this.tokenKey);
        this.storage.removeItem(this.headerNameKey);
        this.storage.removeItem(this.expirationKey);
        this.stopAutoRefresh();
        console.log('CsrfManager - Cleared all CSRF data');
    }

    /**
     * Check if CSRF token is available and valid
     */
    isTokenAvailable() {
        const token = this.storage.getItem(this.tokenKey);
        const expiresAt = parseInt(this.storage.getItem(this.expirationKey) || '0');
        const now = Date.now();

        return !!(token && (!expiresAt || now < expiresAt));
    }
}

// Initialize global CSRF manager instance
// DO NOT auto-initialize - will be initialized after login
window.csrfManager = new CsrfManager();

console.log('CSRF Manager loaded - ready for initialization after login');
