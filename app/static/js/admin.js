/**
 * PCAP Analyzer - Admin Panel
 * User management interface
 */

class AdminPanel {
    constructor() {
        this.users = [];
        this.selectedUsers = new Set();
        this.currentFilter = 'all';
        this.searchQuery = '';

        // DOM elements
        this.loading = document.getElementById('loading');
        this.emptyState = document.getElementById('empty-state');
        this.tableContainer = document.getElementById('table-container');
        this.usersTbody = document.getElementById('users-tbody');
        this.selectAllCheckbox = document.getElementById('select-all');
        this.bulkActionsBar = document.getElementById('bulk-actions-bar');
        this.selectedCountSpan = document.getElementById('selected-count');

        // Stats
        this.statTotal = document.getElementById('stat-total');
        this.statPending = document.getElementById('stat-pending');
        this.statBlocked = document.getElementById('stat-blocked');

        // Check authentication before initializing
        this.checkAuthentication().then(isAuth => {
            if (isAuth) {
                this.init();
            }
        });
    }

    async checkAuthentication() {
        const token = localStorage.getItem('access_token');
        if (!token) {
            window.location.href = '/login?returnUrl=/admin';
            return false;
        }

        // Verify token and check admin role
        try {
            const response = await fetch('/api/users/me', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) {
                localStorage.removeItem('access_token');
                localStorage.removeItem('token_type');
                localStorage.removeItem('current_user');
                window.location.href = '/login?returnUrl=/admin';
                return false;
            }

            const user = await response.json();

            // Check if user is admin
            if (user.role !== 'admin') {
                window.toast.error('❌ Access denied: Admin role required');
                window.location.href = '/';
                return false;
            }

            return true;
        } catch (error) {
            console.error('Auth check error:', error);
            window.location.href = '/login?returnUrl=/admin';
            return false;
        }
    }

    getAuthHeaders() {
        const token = localStorage.getItem('access_token');
        return {
            'Authorization': `Bearer ${token}`
        };
    }

    init() {
        // Load users
        this.loadUsers();

        // Filter buttons
        document.getElementById('filter-all').addEventListener('click', () => this.setFilter('all'));
        document.getElementById('filter-pending').addEventListener('click', () => this.setFilter('pending'));
        document.getElementById('filter-approved').addEventListener('click', () => this.setFilter('approved'));
        document.getElementById('filter-blocked').addEventListener('click', () => this.setFilter('blocked'));

        // Search input
        document.getElementById('search-input').addEventListener('input', (e) => {
            this.searchQuery = e.target.value.toLowerCase();
            this.renderUsers();
        });

        // Refresh button
        document.getElementById('refresh-btn').addEventListener('click', () => this.loadUsers());

        // Select all checkbox
        this.selectAllCheckbox.addEventListener('change', () => this.toggleSelectAll());

        // Bulk actions
        document.getElementById('bulk-approve').addEventListener('click', () => this.bulkAction('approve'));
        document.getElementById('bulk-block').addEventListener('click', () => this.bulkAction('block'));
        document.getElementById('bulk-unblock').addEventListener('click', () => this.bulkAction('unblock'));
        document.getElementById('bulk-delete').addEventListener('click', () => this.bulkAction('delete'));
        document.getElementById('bulk-cancel').addEventListener('click', () => this.clearSelection());

        // Create user modal
        document.getElementById('create-user-btn').addEventListener('click', () => this.showCreateUserModal());
        document.getElementById('cancel-create-user').addEventListener('click', () => this.hideCreateUserModal());
        document.getElementById('confirm-create-user').addEventListener('click', () => this.createUser());
        document.getElementById('close-temp-password-modal').addEventListener('click', () => this.hideTempPasswordModal());
    }

    setFilter(filter) {
        this.currentFilter = filter;

        // Update button styles
        document.querySelectorAll('[id^="filter-"]').forEach(btn => {
            if (btn.id === `filter-${filter}`) {
                btn.className = 'px-4 py-2 rounded-lg bg-primary text-white font-medium text-sm transition-all';
            } else {
                btn.className = 'px-4 py-2 rounded-lg bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 font-medium text-sm transition-all hover:bg-gray-300';
            }
        });

        this.renderUsers();
    }

    async loadUsers() {
        this.showLoading();

        try {
            const response = await fetch('/api/users?limit=1000', {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                if (response.status === 401 || response.status === 403) {
                    window.location.href = '/login?returnUrl=/admin';
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            this.users = await response.json();
            this.updateStats();
            this.renderUsers();

        } catch (error) {
            console.error('Failed to load users:', error);
            window.toast.error('❌ Failed to load users');
            this.showEmpty();
        }
    }

    updateStats() {
        const total = this.users.length;
        const pending = this.users.filter(u => !u.is_approved).length;
        const blocked = this.users.filter(u => !u.is_active).length;

        this.statTotal.textContent = total;
        this.statPending.textContent = pending;
        this.statBlocked.textContent = blocked;
    }

    renderUsers() {
        let filteredUsers = this.users;

        // Apply filter
        if (this.currentFilter === 'pending') {
            filteredUsers = filteredUsers.filter(u => !u.is_approved);
        } else if (this.currentFilter === 'approved') {
            filteredUsers = filteredUsers.filter(u => u.is_approved && u.is_active);
        } else if (this.currentFilter === 'blocked') {
            filteredUsers = filteredUsers.filter(u => !u.is_active);
        }

        // Apply search
        if (this.searchQuery) {
            filteredUsers = filteredUsers.filter(u =>
                u.username.toLowerCase().includes(this.searchQuery) ||
                u.email.toLowerCase().includes(this.searchQuery)
            );
        }

        if (filteredUsers.length === 0) {
            this.showEmpty();
            return;
        }

        this.showTable();
        this.usersTbody.innerHTML = '';

        filteredUsers.forEach(user => {
            const row = this.createUserRow(user);
            this.usersTbody.appendChild(row);
        });
    }

    createUserRow(user) {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors';

        // Checkbox
        const canSelect = user.role !== 'admin'; // Cannot select admin users
        tr.innerHTML = `
            <td class="px-6 py-4">
                ${canSelect ? `<input type="checkbox" class="user-checkbox w-5 h-5 rounded border-gray-300 text-primary focus:ring-primary cursor-pointer" data-user-id="${user.id}" />` : ''}
            </td>
            <td class="px-6 py-4">
                <div class="flex items-center space-x-3">
                    <div class="w-10 h-10 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center text-white font-bold text-lg">
                        ${user.username.charAt(0).toUpperCase()}
                    </div>
                    <div>
                        <div class="font-semibold text-gray-900 dark:text-white">${user.username}</div>
                        ${user.role === 'admin' ? '<div class="text-xs text-purple-600 dark:text-purple-400 font-semibold"><i class="fas fa-crown mr-1"></i>Administrator</div>' : ''}
                    </div>
                </div>
            </td>
            <td class="px-6 py-4 text-gray-700 dark:text-gray-300">${user.email}</td>
            <td class="px-6 py-4">
                <span class="px-3 py-1 rounded-full text-xs font-semibold ${user.role === 'admin' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200' : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'}">
                    ${user.role.toUpperCase()}
                </span>
            </td>
            <td class="px-6 py-4">
                ${this.getStatusBadge(user)}
            </td>
            <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                ${this.formatDate(user.created_at)}
            </td>
            <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                ${user.last_login ? this.formatDate(user.last_login) : 'Never'}
            </td>
            <td class="px-6 py-4">
                <div class="flex items-center justify-center space-x-2">
                    ${this.getUserActions(user)}
                </div>
            </td>
        `;

        // Add checkbox event listener
        if (canSelect) {
            const checkbox = tr.querySelector('.user-checkbox');
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    this.selectedUsers.add(user.id);
                } else {
                    this.selectedUsers.delete(user.id);
                }
                this.updateSelectionUI();
            });
        }

        return tr;
    }

    getStatusBadge(user) {
        if (!user.is_active) {
            return '<span class="status-badge status-blocked"><i class="fas fa-ban"></i><span>Blocked</span></span>';
        } else if (!user.is_approved) {
            return '<span class="status-badge status-pending"><i class="fas fa-clock"></i><span>Pending</span></span>';
        } else {
            return '<span class="status-badge status-approved"><i class="fas fa-check-circle"></i><span>Approved</span></span>';
        }
    }

    getUserActions(user) {
        // Cannot perform actions on admin users
        if (user.role === 'admin') {
            return '<span class="text-xs text-gray-400">Protected</span>';
        }

        const actions = [];

        // Approve (if pending)
        if (!user.is_approved) {
            actions.push(`
                <button onclick="adminPanel.approveUser('${user.id}')" class="action-btn action-btn-approve text-xs px-2 py-1" title="Approve user">
                    <i class="fas fa-check"></i>
                </button>
            `);
        }

        // Block/Unblock
        if (user.is_active) {
            actions.push(`
                <button onclick="adminPanel.blockUser('${user.id}')" class="action-btn action-btn-block text-xs px-2 py-1" title="Block user">
                    <i class="fas fa-ban"></i>
                </button>
            `);
        } else {
            actions.push(`
                <button onclick="adminPanel.unblockUser('${user.id}')" class="action-btn action-btn-unblock text-xs px-2 py-1" title="Unblock user">
                    <i class="fas fa-unlock"></i>
                </button>
            `);
        }

        // Delete
        actions.push(`
            <button onclick="adminPanel.deleteUser('${user.id}', '${user.username}')" class="action-btn action-btn-delete text-xs px-2 py-1" title="Delete user">
                <i class="fas fa-trash"></i>
            </button>
        `);

        return actions.join('');
    }

    async approveUser(userId) {
        try {
            const csrfHeaders = await window.csrfManager.getHeaders();
            const response = await fetch(`/api/admin/users/${userId}/approve`, {
                method: 'PUT',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders
                }
            });

            if (response.ok) {
                window.toast.success('✓ User approved successfully');
                this.loadUsers();
            } else if (response.status === 403) {
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const error = await response.json();
                window.toast.error(`❌ ${error.detail || 'Failed to approve user'}`);
            }
        } catch (error) {
            console.error('Approve error:', error);
            window.toast.error('❌ Failed to approve user');
        }
    }

    async blockUser(userId) {
        if (!confirm('Are you sure you want to block this user?')) {
            return;
        }

        try {
            const csrfHeaders = await window.csrfManager.getHeaders();
            const response = await fetch(`/api/admin/users/${userId}/block`, {
                method: 'PUT',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders
                }
            });

            if (response.ok) {
                window.toast.success('✓ User blocked successfully');
                this.loadUsers();
            } else if (response.status === 403) {
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const error = await response.json();
                window.toast.error(`❌ ${error.detail || 'Failed to block user'}`);
            }
        } catch (error) {
            console.error('Block error:', error);
            window.toast.error('❌ Failed to block user');
        }
    }

    async unblockUser(userId) {
        try {
            const csrfHeaders = await window.csrfManager.getHeaders();
            const response = await fetch(`/api/admin/users/${userId}/unblock`, {
                method: 'PUT',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders
                }
            });

            if (response.ok) {
                window.toast.success('✓ User unblocked successfully');
                this.loadUsers();
            } else if (response.status === 403) {
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const error = await response.json();
                window.toast.error(`❌ ${error.detail || 'Failed to unblock user'}`);
            }
        } catch (error) {
            console.error('Unblock error:', error);
            window.toast.error('❌ Failed to unblock user');
        }
    }

    async deleteUser(userId, username) {
        if (!confirm(`⚠️ Are you sure you want to DELETE user "${username}"?\n\nThis action cannot be undone and will delete all associated tasks.`)) {
            return;
        }

        try {
            const csrfHeaders = await window.csrfManager.getHeaders();
            const response = await fetch(`/api/admin/users/${userId}`, {
                method: 'DELETE',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders
                }
            });

            if (response.ok) {
                window.toast.success(`✓ User "${username}" deleted successfully`);
                this.loadUsers();
            } else if (response.status === 403) {
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const error = await response.json();
                window.toast.error(`❌ ${error.detail || 'Failed to delete user'}`);
            }
        } catch (error) {
            console.error('Delete error:', error);
            window.toast.error('❌ Failed to delete user');
        }
    }

    toggleSelectAll() {
        const checkboxes = document.querySelectorAll('.user-checkbox');
        const isChecked = this.selectAllCheckbox.checked;

        checkboxes.forEach(checkbox => {
            checkbox.checked = isChecked;
            const userId = checkbox.dataset.userId;
            if (isChecked) {
                this.selectedUsers.add(userId);
            } else {
                this.selectedUsers.delete(userId);
            }
        });

        this.updateSelectionUI();
    }

    updateSelectionUI() {
        const count = this.selectedUsers.size;
        this.selectedCountSpan.textContent = count;

        if (count > 0) {
            this.bulkActionsBar.classList.remove('hidden');
        } else {
            this.bulkActionsBar.classList.add('hidden');
        }

        // Update "select all" checkbox state
        const checkboxes = document.querySelectorAll('.user-checkbox');
        const allChecked = checkboxes.length > 0 && count === checkboxes.length;
        this.selectAllCheckbox.checked = allChecked;
    }

    clearSelection() {
        this.selectedUsers.clear();
        document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = false);
        this.selectAllCheckbox.checked = false;
        this.updateSelectionUI();
    }

    async bulkAction(action) {
        if (this.selectedUsers.size === 0) {
            window.toast.error('❌ No users selected');
            return;
        }

        const count = this.selectedUsers.size;
        const actionName = action.charAt(0).toUpperCase() + action.slice(1);

        if (!confirm(`Are you sure you want to ${action} ${count} user(s)?`)) {
            return;
        }

        window.loadingOverlay.show(`${actionName} in progress...`, `Processing ${count} user(s)`);

        const userIds = Array.from(this.selectedUsers);
        let successCount = 0;
        let errorCount = 0;

        // Get CSRF headers once for all requests
        const csrfHeaders = await window.csrfManager.getHeaders();

        for (const userId of userIds) {
            try {
                let response;
                if (action === 'approve') {
                    response = await fetch(`/api/admin/users/${userId}/approve`, {
                        method: 'PUT',
                        headers: {
                            ...this.getAuthHeaders(),
                            ...csrfHeaders
                        }
                    });
                } else if (action === 'block') {
                    response = await fetch(`/api/admin/users/${userId}/block`, {
                        method: 'PUT',
                        headers: {
                            ...this.getAuthHeaders(),
                            ...csrfHeaders
                        }
                    });
                } else if (action === 'unblock') {
                    response = await fetch(`/api/admin/users/${userId}/unblock`, {
                        method: 'PUT',
                        headers: {
                            ...this.getAuthHeaders(),
                            ...csrfHeaders
                        }
                    });
                } else if (action === 'delete') {
                    response = await fetch(`/api/admin/users/${userId}`, {
                        method: 'DELETE',
                        headers: {
                            ...this.getAuthHeaders(),
                            ...csrfHeaders
                        }
                    });
                }

                if (response.ok) {
                    successCount++;
                } else if (response.status === 403) {
                    // CSRF error - stop processing
                    window.loadingOverlay.hide();
                    window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
                    this.clearSelection();
                    return;
                } else {
                    errorCount++;
                }
            } catch (error) {
                console.error(`Failed to ${action} user ${userId}:`, error);
                errorCount++;
            }
        }

        window.loadingOverlay.hide();

        if (successCount > 0) {
            window.toast.success(`✓ ${successCount} user(s) ${action}d successfully`);
        }
        if (errorCount > 0) {
            window.toast.error(`❌ ${errorCount} user(s) failed`);
        }

        this.clearSelection();
        this.loadUsers();
    }

    formatDate(dateStr) {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    showLoading() {
        this.loading.classList.remove('hidden');
        this.emptyState.classList.add('hidden');
        this.tableContainer.classList.add('hidden');
    }

    showEmpty() {
        this.loading.classList.add('hidden');
        this.emptyState.classList.remove('hidden');
        this.tableContainer.classList.add('hidden');
    }

    showTable() {
        this.loading.classList.add('hidden');
        this.emptyState.classList.add('hidden');
        this.tableContainer.classList.remove('hidden');
    }

    showCreateUserModal() {
        document.getElementById('create-user-modal').classList.remove('hidden');
        document.getElementById('create-user-form').reset();
    }

    hideCreateUserModal() {
        document.getElementById('create-user-modal').classList.add('hidden');
    }

    async createUser() {
        const username = document.getElementById('new-username').value;
        const email = document.getElementById('new-email').value;
        const role = document.getElementById('new-role').value;

        if (!username || !email) {
            window.toast.error('Veuillez remplir tous les champs');
            return;
        }

        try {
            const csrfHeaders = await window.csrfManager.getHeaders();
            const response = await fetch('/api/admin/users', {
                method: 'POST',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, role })
            });

            if (response.ok) {
                const data = await response.json();

                // Hide create modal
                this.hideCreateUserModal();

                // Show temporary password modal
                document.getElementById('created-username').textContent = data.user.username;
                document.getElementById('temp-password').textContent = data.temporary_password;
                document.getElementById('temp-password-modal').classList.remove('hidden');

                // Reload users
                await this.loadUsers();

                window.toast.success(`✅ Utilisateur ${username} créé avec succès`);
            } else if (response.status === 403) {
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const error = await response.json();
                window.toast.error(error.detail || 'Erreur lors de la création');
            }
        } catch (error) {
            console.error('Error creating user:', error);
            window.toast.error('Erreur réseau');
        }
    }

    hideTempPasswordModal() {
        document.getElementById('temp-password-modal').classList.add('hidden');
    }
}

// Initialize on DOM ready
let adminPanel;
document.addEventListener('DOMContentLoaded', () => {
    adminPanel = new AdminPanel();
    console.log('Admin panel initialized');
});
