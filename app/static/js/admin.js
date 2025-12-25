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
        this.limit = 50;
        this.offset = 0;
        this.totalCount = 0;

        this.loading = document.getElementById('loading');
        this.emptyState = document.getElementById('empty-state');
        this.tableContainer = document.getElementById('table-container');
        this.usersTbody = document.getElementById('users-tbody');
        this.selectAllCheckbox = document.getElementById('select-all');
        this.bulkActionsBar = document.getElementById('bulk-actions-bar');
        this.selectedCountSpan = document.getElementById('selected-count');
        
        this.prevBtn = document.getElementById('prev-page');
        this.nextBtn = document.getElementById('next-page');
        this.pageRangeSpan = document.getElementById('page-range');
        this.totalCountSpan = document.getElementById('total-count');
        this.pageSizeSelect = document.getElementById('page-size');

        this.statTotal = document.getElementById('stat-total');
        this.statPending = document.getElementById('stat-pending');
        this.statBlocked = document.getElementById('stat-blocked');

        this.checkAuthentication().then(isAuth => {
            if (isAuth) this.init();
        });
    }

    async checkAuthentication() {
        const token = localStorage.getItem('access_token');
        if (!token) { window.location.href = '/login?returnUrl=/admin'; return false; }
        try {
            const response = await fetch('/api/users/me', { headers: { 'Authorization': `Bearer ${token}` } });
            if (!response.ok) { localStorage.clear(); window.location.href = '/login?returnUrl=/admin'; return false; }
            const user = await response.json();
            if (user.role !== 'admin') { window.location.href = '/'; return false; }
            return true;
        } catch (error) { window.location.href = '/login?returnUrl=/admin'; return false; }
    }

    getAuthHeaders() {
        return { 'Authorization': `Bearer ${localStorage.getItem('access_token')}` };
    }

    init() {
        this.loadUsers();
        this.loadStats();

        ['all', 'pending', 'approved', 'blocked'].forEach(f => {
            const el = document.getElementById(`filter-${f}`);
            if (el) el.addEventListener('click', () => this.setFilter(f));
        });

        const searchInput = document.getElementById('search-input');
        let searchTimeout;
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value.toLowerCase();
                    this.offset = 0;
                    this.loadUsers();
                }, 300);
            });
        }

        const refreshBtn = document.getElementById('refresh-btn');
        if (refreshBtn) refreshBtn.addEventListener('click', () => { this.loadUsers(); this.loadStats(); });

        if (this.selectAllCheckbox) this.selectAllCheckbox.addEventListener('change', () => this.toggleSelectAll());

        ['approve', 'block', 'unblock', 'delete'].forEach(a => {
            const el = document.getElementById(`bulk-${a}`);
            if (el) el.addEventListener('click', () => this.bulkAction(a));
        });
        const bulkCancel = document.getElementById('bulk-cancel');
        if (bulkCancel) bulkCancel.addEventListener('click', () => this.clearSelection());

        const createBtn = document.getElementById('create-user-btn');
        if (createBtn) createBtn.addEventListener('click', () => this.showCreateUserModal());

        const cancelCreateBtn = document.getElementById('cancel-create-user');
        if (cancelCreateBtn) cancelCreateBtn.addEventListener('click', () => this.hideCreateUserModal());

        const confirmCreateBtn = document.getElementById('confirm-create-user');
        if (confirmCreateBtn) confirmCreateBtn.addEventListener('click', () => this.createUser());

        const createUserForm = document.getElementById('create-user-form');
        if (createUserForm) {
            createUserForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.createUser();
            });
        }

        // Close modal on Escape or click outside
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.hideCreateUserModal();
                this.hideTempPasswordModal();
            }
        });
        
        const modal = document.getElementById('create-user-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.hideCreateUserModal();
            });
        }

        const tempPasswordModal = document.getElementById('temp-password-modal');
        if (tempPasswordModal) {
            tempPasswordModal.addEventListener('click', (e) => {
                if (e.target === tempPasswordModal) this.hideTempPasswordModal();
            });
        }
        
        // Pagination
        if (this.prevBtn) this.prevBtn.addEventListener('click', () => this.changePage(-1));
        if (this.nextBtn) this.nextBtn.addEventListener('click', () => this.changePage(1));
        if (this.pageSizeSelect) this.pageSizeSelect.addEventListener('change', (e) => {
            this.limit = parseInt(e.target.value);
            this.offset = 0;
            this.loadUsers();
        });
    }

    setFilter(filter) {
        this.currentFilter = filter;
        this.offset = 0;
        document.querySelectorAll('[id^="filter-"]').forEach(btn => {
            if (btn.id === `filter-${filter}`) btn.className = 'px-4 py-2 rounded-lg bg-primary text-white font-medium text-sm transition-all';
            else btn.className = 'px-4 py-2 rounded-lg bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 font-medium text-sm transition-all hover:bg-gray-300';
        });
        this.loadUsers();
    }

    async loadUsers() {
        this.showLoading();
        this.clearSelection();
        try {
            let url = `/api/users?limit=${this.limit}&offset=${this.offset}`;
            if (this.currentFilter !== 'all') url += `&status=${this.currentFilter}`;
            
            const response = await fetch(url, { headers: this.getAuthHeaders() });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            if (data.users && typeof data.total === 'number') {
                this.users = data.users;
                this.totalCount = data.total;
            } else if (Array.isArray(data)) {
                this.users = data;
                this.totalCount = data.length;
            } else {
                this.users = []; this.totalCount = 0;
            }
        } catch (error) {
            console.error('Failed to load users:', error);
            this.users = []; this.totalCount = 0;
        } finally {
            this.renderUsers();
            this.updatePaginationUI();
        }
    }

    async loadStats() {
        try {
            const fetchCount = async (status) => {
                let url = `/api/users?limit=0&offset=0`;
                if (status) url += `&status=${status}`;
                const resp = await fetch(url, { headers: this.getAuthHeaders() });
                if (!resp.ok) return 0;
                const data = await resp.json();
                return typeof data.total === 'number' ? data.total : (Array.isArray(data) ? data.length : 0);
            };
            const [total, pending, blocked] = await Promise.all([fetchCount(null), fetchCount('pending'), fetchCount('blocked')]);
            if (this.statTotal) this.statTotal.textContent = total;
            if (this.statPending) this.statPending.textContent = pending;
            if (this.statBlocked) this.statBlocked.textContent = blocked;
        } catch (e) {}
    }

    renderUsers() {
        let displayUsers = this.users;
        if (this.searchQuery) {
            displayUsers = displayUsers.filter(u =>
                u.username.toLowerCase().includes(this.searchQuery) ||
                u.email.toLowerCase().includes(this.searchQuery)
            );
        }

        if (displayUsers.length === 0) { this.showEmpty(); return; }

        this.showTable();
        if (this.usersTbody) {
            this.usersTbody.innerHTML = '';
            displayUsers.forEach(user => this.usersTbody.appendChild(this.createUserRow(user)));
        }
    }

    createUserRow(user) {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors';
        const canSelect = user.role !== 'admin';
        tr.innerHTML = `
            <td class="px-6 py-4">${canSelect ? `<input type="checkbox" class="user-checkbox w-5 h-5 rounded border-gray-300 text-primary focus:ring-primary cursor-pointer" data-user-id="${user.id}" />` : ''}</td>
            <td class="px-6 py-4"><div class="flex items-center space-x-3"><div class="w-10 h-10 rounded-full bg-gradient-to-br from-blue-400 to-blue-600 flex items-center justify-center text-white font-bold text-lg">${user.username.charAt(0).toUpperCase()}</div><div><div class="font-semibold text-gray-900 dark:text-white">${user.username}</div>${user.role === 'admin' ? '<div class="text-xs text-purple-600 dark:text-purple-400 font-semibold"><i class="fas fa-crown mr-1"></i>Administrator</div>' : ''}</div></div></td>
            <td class="px-6 py-4 text-gray-700 dark:text-gray-300">${user.email}</td>
            <td class="px-6 py-4"><span class="px-3 py-1 rounded-full text-xs font-semibold ${user.role === 'admin' ? 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200' : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'}">${user.role.toUpperCase()}</span></td>
            <td class="px-6 py-4">${this.getStatusBadge(user)}</td>
            <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">${this.formatDate(user.created_at)}</td>
            <td class="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">${user.last_login ? this.formatDate(user.last_login) : 'Never'}</td>
            <td class="px-6 py-4"><div class="flex items-center justify-center space-x-2">${this.getUserActions(user)}</div></td>
        `;
        if (canSelect) {
            const cb = tr.querySelector('.user-checkbox');
            cb.addEventListener('change', () => { if (cb.checked) this.selectedUsers.add(user.id); else this.selectedUsers.delete(user.id); this.updateSelectionUI(); });
        }
        return tr;
    }

    getStatusBadge(user) {
        if (!user.is_active) return '<span class="status-badge status-blocked"><i class="fas fa-ban"></i><span>Blocked</span></span>';
        if (!user.is_approved) return '<span class="status-badge status-pending"><i class="fas fa-clock"></i><span>Pending</span></span>';
        return '<span class="status-badge status-approved"><i class="fas fa-check-circle"></i><span>Approved</span></span>';
    }

    getUserActions(user) {
        if (user.role === 'admin') return '<span class="text-xs text-gray-400">Protected</span>';
        const actions = [];
        if (!user.is_approved) actions.push(`<button onclick="adminPanel.approveUser('${user.id}')" class="action-btn action-btn-approve text-xs px-2 py-1"><i class="fas fa-check"></i></button>`);
        if (user.is_active) actions.push(`<button onclick="adminPanel.blockUser('${user.id}')" class="action-btn action-btn-block text-xs px-2 py-1"><i class="fas fa-ban"></i></button>`);
        else actions.push(`<button onclick="adminPanel.unblockUser('${user.id}')" class="action-btn action-btn-unblock text-xs px-2 py-1"><i class="fas fa-unlock"></i></button>`);
        actions.push(`<button onclick="adminPanel.deleteUser('${user.id}', '${user.username}')" class="action-btn action-btn-delete text-xs px-2 py-1"><i class="fas fa-trash"></i></button>`);
        return actions.join('');
    }

    async approveUser(userId) {
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            const resp = await fetch(`/api/admin/users/${userId}/approve`, { method: 'PUT', headers: { ...this.getAuthHeaders(), ...csrf } });
            if (resp.ok) { this.loadUsers(); this.loadStats(); }
        } catch (e) {}
    }

    async blockUser(userId) {
        if (!confirm('Block user?')) return;
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            const resp = await fetch(`/api/admin/users/${userId}/block`, { method: 'PUT', headers: { ...this.getAuthHeaders(), ...csrf } });
            if (resp.ok) { this.loadUsers(); this.loadStats(); }
        } catch (e) {}
    }

    async unblockUser(userId) {
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            const resp = await fetch(`/api/admin/users/${userId}/unblock`, { method: 'PUT', headers: { ...this.getAuthHeaders(), ...csrf } });
            if (resp.ok) { this.loadUsers(); this.loadStats(); }
        } catch (e) {}
    }

    async deleteUser(userId, username) {
        if (!confirm(`Delete ${username}?`)) return;
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            const resp = await fetch(`/api/admin/users/${userId}`, { method: 'DELETE', headers: { ...this.getAuthHeaders(), ...csrf } });
            if (resp.ok) { this.loadUsers(); this.loadStats(); }
        } catch (e) {}
    }

    changePage(delta) {
        const newOffset = this.offset + (delta * this.limit);
        if (newOffset >= 0 && newOffset < this.totalCount) { this.offset = newOffset; this.loadUsers(); }
    }

    updatePaginationUI() {
        if (!this.pageRangeSpan) return;
        const start = this.totalCount === 0 ? 0 : this.offset + 1;
        const end = Math.min(this.offset + this.limit, this.totalCount);
        this.pageRangeSpan.textContent = `${start}-${end}`;
        this.totalCountSpan.textContent = this.totalCount;
        this.prevBtn.disabled = this.offset === 0;
        this.nextBtn.disabled = end >= this.totalCount;
    }

    toggleSelectAll() {
        const cbs = document.querySelectorAll('.user-checkbox');
        cbs.forEach(cb => { cb.checked = this.selectAllCheckbox.checked; if (cb.checked) this.selectedUsers.add(cb.dataset.userId); else this.selectedUsers.delete(cb.dataset.userId); });
        this.updateSelectionUI();
    }

    updateSelectionUI() {
        if (!this.selectedCountSpan) return;
        this.selectedCountSpan.textContent = this.selectedUsers.size;
        if (this.selectedUsers.size > 0) this.bulkActionsBar.classList.remove('hidden');
        else this.bulkActionsBar.classList.add('hidden');
        const cbs = document.querySelectorAll('.user-checkbox');
        if (this.selectAllCheckbox) this.selectAllCheckbox.checked = cbs.length > 0 && Array.from(cbs).every(cb => cb.checked);
    }

    clearSelection() {
        this.selectedUsers.clear();
        document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = false);
        if (this.selectAllCheckbox) this.selectAllCheckbox.checked = false;
        this.updateSelectionUI();
    }

    async bulkAction(action) {
        if (this.selectedUsers.size === 0) return;
        if (!confirm(`Bulk ${action}?`)) return;
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            if (action === 'delete') {
                for (const id of this.selectedUsers) await fetch(`/api/admin/users/${id}`, { method: 'DELETE', headers: { ...this.getAuthHeaders(), ...csrf } });
            } else {
                await fetch(`/api/admin/users/bulk/${action}`, {
                    method: 'POST',
                    headers: { ...this.getAuthHeaders(), ...csrf, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_ids: Array.from(this.selectedUsers) })
                });
            }
            this.loadUsers(); this.loadStats();
        } catch (e) {} finally { this.clearSelection(); }
    }

    formatDate(d) { if (!d) return 'N/A'; return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
    showLoading() { if (this.loading) this.loading.classList.remove('hidden'); if (this.emptyState) this.emptyState.classList.add('hidden'); if (this.tableContainer) this.tableContainer.classList.add('hidden'); }
    showEmpty() { if (this.loading) this.loading.classList.add('hidden'); if (this.emptyState) this.emptyState.classList.remove('hidden'); if (this.tableContainer) this.tableContainer.classList.add('hidden'); }
    showTable() { if (this.loading) this.loading.classList.add('hidden'); if (this.emptyState) this.emptyState.classList.add('hidden'); if (this.tableContainer) this.tableContainer.classList.remove('hidden'); }
    showCreateUserModal() { 
        const el = document.getElementById('create-user-modal'); 
        if (el) {
            el.classList.remove('hidden'); 
            const form = document.getElementById('create-user-form');
            if (form) form.reset();
            const usernameInput = document.getElementById('new-username');
            if (usernameInput) usernameInput.focus();
        }
    }
    
    hideCreateUserModal() { 
        const el = document.getElementById('create-user-modal'); 
        if (el) el.classList.add('hidden'); 
    }
    hideTempPasswordModal() { const el = document.getElementById('temp-password-modal'); if (el) el.classList.add('hidden'); }

    async createUser() {
        const username = document.getElementById('new-username').value;
        const email = document.getElementById('new-email').value;
        const role = document.getElementById('new-role').value;
        if (!username || !email) {
            if (window.toast) window.toast.error('Veuillez remplir tous les champs');
            return;
        }
        try {
            const csrf = window.csrfManager ? await window.csrfManager.getHeaders() : {};
            const resp = await fetch('/api/admin/users', {
                method: 'POST',
                headers: { ...this.getAuthHeaders(), ...csrf, 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, role })
            });
            if (resp.ok) {
                const data = await resp.json();
                this.hideCreateUserModal();
                document.getElementById('created-username').textContent = data.user.username;
                document.getElementById('temp-password').textContent = data.temporary_password;
                document.getElementById('temp-password-modal').classList.remove('hidden');
                if (window.toast) window.toast.success(`✅ Utilisateur ${username} créé avec succès`);
                this.loadUsers(); this.loadStats();
            } else {
                const err = await resp.json(); 
                if (window.toast) window.toast.error(`❌ ${err.detail || 'Erreur lors de la création'}`);
            }
        } catch (e) { 
            console.error('Error creating user:', e);
            if (window.toast) window.toast.error('❌ Erreur réseau'); 
        }
    }
}

let adminPanel;
document.addEventListener('DOMContentLoaded', () => { adminPanel = new AdminPanel(); });
