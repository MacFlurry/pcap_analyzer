/**
 * PCAP Analyzer - History Page
 * Affichage de l'historique des analyses
 */

class HistoryManager {
    constructor() {
        this.loading = document.getElementById('loading');
        this.emptyState = document.getElementById('empty-state');
        this.historyContainer = document.getElementById('history-container');
        this.historyTbody = document.getElementById('history-tbody');
        this.count = document.getElementById('count');

        this.selectAllCheckbox = document.getElementById('select-all');
        this.deleteSelectedBtn = document.getElementById('delete-selected');
        this.selectedCountSpan = document.getElementById('selected-count');

        this.currentFilter = 'all';
        this.selectedTasks = new Set();
        this.isAdmin = false;

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
            window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            return false;
        }

        // Verify token is still valid
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
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
                return false;
            }

            const user = await response.json();
            this.isAdmin = user.role === 'admin';
            console.log(`User role: ${user.role}, isAdmin: ${this.isAdmin}`);

            return true;
        } catch (error) {
            console.error('Auth check error:', error);
            window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            return false;
        }
    }

    getAuthHeaders() {
        const token = localStorage.getItem('access_token');
        return {
            'Authorization': `Bearer ${token}`
        };
    }

    addTokenToUrl(url) {
        /**
         * Add authentication token to URL as query parameter.
         * Used for navigation links (reports) where we can't send headers.
         */
        const token = localStorage.getItem('access_token');
        if (!token || !url) return url;

        const separator = url.includes('?') ? '&' : '?';
        return `${url}${separator}token=${encodeURIComponent(token)}`;
    }

    init() {
        // Load history
        this.loadHistory();

        // Filter buttons
        document.getElementById('filter-all').addEventListener('click', () => {
            this.setFilter('all');
        });
        document.getElementById('filter-completed').addEventListener('click', () => {
            this.setFilter('completed');
        });
        document.getElementById('filter-failed').addEventListener('click', () => {
            this.setFilter('failed');
        });

        // Select all checkbox
        this.selectAllCheckbox.addEventListener('change', () => {
            this.toggleSelectAll();
        });

        // Delete selected button
        this.deleteSelectedBtn.addEventListener('click', () => {
            this.deleteSelected();
        });
    }

    setFilter(filter) {
        this.currentFilter = filter;

        // Update button styles
        document.querySelectorAll('[id^="filter-"]').forEach(btn => {
            if (btn.id === `filter-${filter}`) {
                btn.className = 'btn btn-primary btn-sm';
            } else {
                btn.className = 'btn btn-secondary btn-sm';
            }
        });

        // Reload with filter
        this.loadHistory();
    }

    async loadHistory() {
        this.showLoading();

        try {
            const response = await fetch('/api/history?limit=50', {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                if (response.status === 401) {
                    window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            if (data.tasks && data.tasks.length > 0) {
                // Filter tasks
                let tasks = data.tasks;

                // Exclure les tâches expirées par défaut (sauf si filtre spécifique)
                if (this.currentFilter === 'all') {
                    tasks = tasks.filter(task => task.status !== 'expired');
                } else {
                    tasks = tasks.filter(task => task.status === this.currentFilter);
                }

                if (tasks.length > 0) {
                    this.displayHistory(tasks);
                } else {
                    this.showEmpty();
                }
            } else {
                this.showEmpty();
            }
        } catch (error) {
            console.error('Failed to load history:', error);
            window.toast.error('Erreur lors du chargement de l\'historique');
            this.showEmpty();
        }
    }

    showLoading() {
        this.loading.classList.remove('hidden');
        this.emptyState.classList.add('hidden');
        this.historyContainer.classList.add('hidden');
    }

    showEmpty() {
        this.loading.classList.add('hidden');
        this.emptyState.classList.remove('hidden');
        this.historyContainer.classList.add('hidden');

        // Clear selections when showing empty state
        this.selectedTasks.clear();
        this.selectAllCheckbox.checked = false;
        this.updateSelectionUI();
    }

    displayHistory(tasks) {
        this.loading.classList.add('hidden');
        this.emptyState.classList.add('hidden');
        this.historyContainer.classList.remove('hidden');

        // Clear existing rows and selection
        this.historyTbody.innerHTML = '';
        this.selectedTasks.clear();
        this.selectAllCheckbox.checked = false;
        this.updateSelectionUI();

        // Add admin-view class for CSS grid adjustment
        if (this.isAdmin) {
            this.historyContainer.classList.add('admin-view');
        } else {
            this.historyContainer.classList.remove('admin-view');
        }

        // Toggle owner column visibility based on admin role
        const ownerColumnHeader = document.getElementById('owner-column-header');
        if (ownerColumnHeader) {
            if (this.isAdmin) {
                ownerColumnHeader.classList.remove('hidden');
            } else {
                ownerColumnHeader.classList.add('hidden');
            }
        }

        // Add rows
        tasks.forEach(task => {
            const row = this.createRow(task);
            this.historyTbody.appendChild(row);
        });

        // Update count
        this.count.textContent = tasks.length;
    }

    createRow(task) {
        // Create a grid row container
        const gridRow = document.createElement('div');
        gridRow.className = 'history-grid-row';
        gridRow.dataset.taskId = task.task_id;

        // Checkbox cell (only for deletable tasks)
        const checkboxCell = document.createElement('div');
        checkboxCell.className = 'grid-cell grid-cell-checkbox';
        const escapedTaskId = window.utils.escapeHtml(task.task_id);
        const escapedFilename = window.utils.escapeHtml(task.filename);

        if (['completed', 'failed', 'expired'].includes(task.status)) {
            checkboxCell.innerHTML = `
                <input type="checkbox" class="checkbox-modern task-checkbox" data-task-id="${escapedTaskId}">
            `;
            const checkbox = checkboxCell.querySelector('.task-checkbox');
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    this.selectedTasks.add(task.task_id);
                } else {
                    this.selectedTasks.delete(task.task_id);
                }
                this.updateSelectionUI();
            });
        }
        
        // Filename cell
        const filenameCell = document.createElement('div');
        filenameCell.className = 'grid-cell grid-cell-file';
        filenameCell.innerHTML = `
            <div class="flex items-center space-x-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-gradient-to-br from-blue-100 to-blue-200 dark:from-blue-900 dark:to-blue-800 flex items-center justify-center">
                    <i class="fas fa-file-alt text-blue-600 dark:text-blue-300"></i>
                </div>
                <div class="flex-1 min-w-0">
                    <p class="font-semibold text-gray-900 dark:text-white truncate text-base">${escapedFilename}</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">Fichier PCAP</p>
                </div>
            </div>
        `;

        // Owner cell (only for admins)
        const ownerCell = document.createElement('div');
        ownerCell.className = 'grid-cell grid-cell-owner';
        if (this.isAdmin) {
            const ownerUsername = window.utils.escapeHtml(task.owner_username || 'Unknown');
            ownerCell.innerHTML = `
                <div class="flex items-center space-x-2">
                    <div class="flex-shrink-0 w-8 h-8 rounded-full bg-gradient-to-br from-green-100 to-green-200 dark:from-green-900 dark:to-green-800 flex items-center justify-center">
                        <i class="fas fa-user text-xs text-green-600 dark:text-green-300"></i>
                    </div>
                    <span class="text-gray-900 dark:text-white font-medium text-sm">
                        ${ownerUsername}
                    </span>
                </div>
            `;
        } else {
            ownerCell.classList.add('hidden');
        }

        // Status cell
        const statusCell = document.createElement('div');
        statusCell.className = 'grid-cell grid-cell-status';
        const statusIcon = window.utils.getStatusIcon(task.status);
        const statusBadge = window.utils.getStatusBadge(task.status);
        const statusText = {
            pending: 'En attente',
            processing: 'En cours',
            completed: 'Terminé',
            failed: 'Échec',
            expired: 'Expiré'
        }[task.status] || task.status;

        statusCell.innerHTML = `
            <span class="badge-modern ${statusBadge}">
                <i class="${statusIcon}"></i>
                <span>${statusText}</span>
            </span>
        `;

        // Date cell
        const dateCell = document.createElement('div');
        dateCell.className = 'grid-cell grid-cell-date';
        dateCell.innerHTML = `
            <div>
                <div class="text-sm font-medium text-gray-900 dark:text-white">
                    ${window.utils.formatDate(task.uploaded_at)}
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    <i class="far fa-clock mr-1"></i>${window.utils.formatRelativeTime(task.uploaded_at)}
                </div>
            </div>
        `;

        // Packets cell
        const packetsCell = document.createElement('div');
        packetsCell.className = 'grid-cell grid-cell-packets';
        if (task.total_packets) {
            packetsCell.innerHTML = `
                <div class="flex items-center space-x-2">
                    <div class="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-br from-purple-100 to-purple-200 dark:from-purple-900 dark:to-purple-800 flex items-center justify-center">
                        <i class="fas fa-network-wired text-xs text-purple-600 dark:text-purple-300"></i>
                    </div>
                    <span class="text-gray-900 dark:text-white font-semibold text-base">
                        ${task.total_packets.toLocaleString('fr-FR')}
                    </span>
                </div>
            `;
        } else {
            packetsCell.innerHTML = `<span class="text-gray-400 text-sm">N/A</span>`;
        }

        // Health Score cell
        const scoreCell = document.createElement('div');
        scoreCell.className = 'grid-cell grid-cell-score';
        if (task.health_score !== null && task.health_score !== undefined) {
            const scoreClass = this.getScoreClass(task.health_score);
            const scoreColorClass = this.getScoreColorClass(task.health_score);
            scoreCell.innerHTML = `
                <div class="score-display">
                    <div class="score-bar-container">
                        <div class="score-bar-fill ${scoreClass}" style="width: ${task.health_score}%"></div>
                    </div>
                    <span class="score-value ${scoreColorClass}">
                        ${task.health_score.toFixed(0)}
                    </span>
                </div>
            `;
        } else {
            scoreCell.innerHTML = `<span class="text-gray-400 text-sm">N/A</span>`;
        }

        // Actions cell
        const actionsCell = document.createElement('div');
        actionsCell.className = 'grid-cell grid-cell-actions';

        const actions = [];

        // View report (si completed)
        if (task.status === 'completed' && task.report_html_url) {
            actions.push(`
                <a href="${this.addTokenToUrl(task.report_html_url)}" target="_blank" rel="noopener noreferrer" class="action-btn btn-view" title="Voir le rapport">
                    <i class="fas fa-eye"></i>
                </a>
            `);
        }

        // View progress (si processing)
        if (task.status === 'processing') {
            actions.push(`
                <a href="/progress/${task.task_id}" class="action-btn btn-progress" title="Voir la progression">
                    <i class="fas fa-chart-line"></i>
                </a>
            `);
        }

        // Download JSON (si completed)
        if (task.status === 'completed' && task.report_json_url) {
            actions.push(`
                <a href="${this.addTokenToUrl(task.report_json_url)}" class="action-btn btn-download" title="Télécharger JSON">
                    <i class="fas fa-download"></i>
                </a>
            `);
        }

        // Delete (si completed ou failed ou expired)
        if (['completed', 'failed', 'expired'].includes(task.status)) {
            actions.push(`
                <button onclick="window.historyManager.deleteTask('${task.task_id}')"
                        class="action-btn btn-delete"
                        title="Supprimer">
                    <i class="fas fa-trash"></i>
                </button>
            `);
        }

        actionsCell.innerHTML = `
            <div class="flex items-center justify-end space-x-2">
                ${actions.join('')}
            </div>
        `;

        // Append all cells to grid row
        gridRow.appendChild(checkboxCell);
        gridRow.appendChild(filenameCell);
        gridRow.appendChild(ownerCell);
        gridRow.appendChild(statusCell);
        gridRow.appendChild(dateCell);
        gridRow.appendChild(packetsCell);
        gridRow.appendChild(scoreCell);
        gridRow.appendChild(actionsCell);

        return gridRow;
    }

    getScoreColor(score) {
        if (score >= 80) return 'bg-green-500';
        if (score >= 60) return 'bg-yellow-500';
        if (score >= 40) return 'bg-orange-500';
        return 'bg-red-500';
    }

    getScoreClass(score) {
        if (score >= 80) return 'score-excellent';
        if (score >= 60) return 'score-good';
        if (score >= 40) return 'score-warning';
        return 'score-critical';
    }

    getScoreColorClass(score) {
        if (score >= 80) return 'score-excellent';
        if (score >= 60) return 'score-good';
        if (score >= 40) return 'score-warning';
        return 'score-critical';
    }

    toggleSelectAll() {
        const checkboxes = document.querySelectorAll('.task-checkbox');
        const isChecked = this.selectAllCheckbox.checked;

        checkboxes.forEach(checkbox => {
            checkbox.checked = isChecked;
            const taskId = checkbox.dataset.taskId;
            if (isChecked) {
                this.selectedTasks.add(taskId);
            } else {
                this.selectedTasks.delete(taskId);
            }
        });

        this.updateSelectionUI();
    }

    updateSelectionUI() {
        const count = this.selectedTasks.size;
        this.selectedCountSpan.textContent = count;

        if (count > 0) {
            this.deleteSelectedBtn.classList.remove('hidden');
        } else {
            this.deleteSelectedBtn.classList.add('hidden');
        }

        // Update "select all" checkbox state
        const checkboxes = document.querySelectorAll('.task-checkbox');
        const allChecked = checkboxes.length > 0 && count === checkboxes.length;
        this.selectAllCheckbox.checked = allChecked;
    }

    async deleteSelected() {
        const count = this.selectedTasks.size;
        if (count === 0) return;

        if (!confirm(`Êtes-vous sûr de vouloir supprimer ${count} analyse(s) ?`)) {
            return;
        }

        // Show loading overlay
        window.loadingOverlay.show(
            `Suppression en cours...`,
            `Suppression de ${count} analyse(s)`
        );

        const taskIds = Array.from(this.selectedTasks);
        let successCount = 0;
        let errorCount = 0;

        // Get CSRF headers
        const csrfHeaders = await window.csrfManager.getHeaders();

        // Delete tasks one by one
        for (const taskId of taskIds) {
            try {
                const response = await fetch(`/api/reports/${taskId}`, {
                    method: 'DELETE',
                    headers: {
                        ...this.getAuthHeaders(),
                        ...csrfHeaders
                    }
                });

                if (response.ok) {
                    successCount++;
                } else if (response.status === 401) {
                    window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
                    return;
                } else if (response.status === 403) {
                    // CSRF error
                    window.loadingOverlay.hide();
                    window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
                    return;
                } else {
                    errorCount++;
                }
            } catch (error) {
                console.error(`Failed to delete task ${taskId}:`, error);
                errorCount++;
            }
        }

        // Hide loading overlay
        window.loadingOverlay.hide();

        // Show result
        if (successCount > 0) {
            window.toast.success(`✓ ${successCount} analyse(s) supprimée(s) avec succès`);
        }
        if (errorCount > 0) {
            window.toast.error(`❌ ${errorCount} analyse(s) n'ont pas pu être supprimée(s)`);
        }

        // Clear selections before reloading
        this.selectedTasks.clear();
        this.updateSelectionUI();

        // Reload history
        this.loadHistory();
    }

    async deleteTask(taskId) {
        if (!confirm('Êtes-vous sûr de vouloir supprimer cette analyse ?')) {
            return;
        }

        try {
            // Get CSRF headers
            const csrfHeaders = await window.csrfManager.getHeaders();

            const response = await fetch(`/api/reports/${taskId}`, {
                method: 'DELETE',
                headers: {
                    ...this.getAuthHeaders(),
                    ...csrfHeaders
                }
            });

            if (response.ok) {
                window.toast.success('✓ Analyse supprimée avec succès');
                // Recharger l'historique pour retirer l'élément de la liste
                this.loadHistory();
            } else if (response.status === 401) {
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            } else if (response.status === 403) {
                // CSRF error
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
            } else {
                const data = await response.json();
                throw new Error(data.detail || 'Erreur lors de la suppression');
            }
        } catch (error) {
            console.error('Delete error:', error);
            window.toast.error('❌ ' + (error.message || 'Erreur lors de la suppression'));
        }
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.historyManager = new HistoryManager();
    console.log('History manager initialized');
});
