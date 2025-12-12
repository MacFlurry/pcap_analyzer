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

        this.currentFilter = 'all';

        this.init();
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
            const response = await fetch('/api/history?limit=50');
            const data = await response.json();

            if (data.tasks && data.tasks.length > 0) {
                // Filter tasks
                let tasks = data.tasks;
                if (this.currentFilter !== 'all') {
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
    }

    displayHistory(tasks) {
        this.loading.classList.add('hidden');
        this.emptyState.classList.add('hidden');
        this.historyContainer.classList.remove('hidden');

        // Clear existing rows
        this.historyTbody.innerHTML = '';

        // Add rows
        tasks.forEach(task => {
            const row = this.createRow(task);
            this.historyTbody.appendChild(row);
        });

        // Update count
        this.count.textContent = tasks.length;
    }

    createRow(task) {
        const tr = document.createElement('tr');

        // Filename
        const filenameTd = document.createElement('td');
        filenameTd.innerHTML = `
            <div class="flex items-center space-x-2">
                <i class="fas fa-file-alt text-gray-400"></i>
                <span class="font-medium text-gray-900 dark:text-white">${task.filename}</span>
            </div>
        `;

        // Status
        const statusTd = document.createElement('td');
        const statusIcon = window.utils.getStatusIcon(task.status);
        const statusBadge = window.utils.getStatusBadge(task.status);
        const statusText = {
            pending: 'En attente',
            processing: 'En cours',
            completed: 'Terminé',
            failed: 'Échec',
            expired: 'Expiré'
        }[task.status] || task.status;

        statusTd.innerHTML = `
            <span class="badge ${statusBadge}">
                <i class="${statusIcon} mr-1"></i>
                ${statusText}
            </span>
        `;

        // Date
        const dateTd = document.createElement('td');
        dateTd.innerHTML = `
            <div>
                <div class="text-sm text-gray-900 dark:text-white">
                    ${window.utils.formatDate(task.uploaded_at)}
                </div>
                <div class="text-xs text-gray-500 dark:text-gray-400">
                    ${window.utils.formatRelativeTime(task.uploaded_at)}
                </div>
            </div>
        `;

        // Packets
        const packetsTd = document.createElement('td');
        if (task.total_packets) {
            packetsTd.innerHTML = `
                <span class="text-gray-900 dark:text-white font-medium">
                    ${task.total_packets.toLocaleString('fr-FR')}
                </span>
            `;
        } else {
            packetsTd.innerHTML = `<span class="text-gray-400">-</span>`;
        }

        // Health Score
        const scoreTd = document.createElement('td');
        if (task.health_score !== null && task.health_score !== undefined) {
            const scoreColor = this.getScoreColor(task.health_score);
            scoreTd.innerHTML = `
                <div class="flex items-center space-x-2">
                    <div class="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                        <div class="h-full ${scoreColor}" style="width: ${task.health_score}%"></div>
                    </div>
                    <span class="text-sm font-medium text-gray-900 dark:text-white">
                        ${task.health_score.toFixed(0)}
                    </span>
                </div>
            `;
        } else {
            scoreTd.innerHTML = `<span class="text-gray-400">-</span>`;
        }

        // Actions
        const actionsTd = document.createElement('td');
        actionsTd.className = 'text-right';

        const actions = [];

        // View report (si completed)
        if (task.status === 'completed' && task.report_html_url) {
            actions.push(`
                <a href="${task.report_html_url}" class="text-primary hover:text-blue-700 transition-colors" title="Voir le rapport">
                    <i class="fas fa-eye"></i>
                </a>
            `);
        }

        // View progress (si processing)
        if (task.status === 'processing') {
            actions.push(`
                <a href="/progress/${task.task_id}" class="text-blue-600 hover:text-blue-700 transition-colors" title="Voir la progression">
                    <i class="fas fa-chart-line"></i>
                </a>
            `);
        }

        // Download JSON (si completed)
        if (task.status === 'completed' && task.report_json_url) {
            actions.push(`
                <a href="${task.report_json_url}" class="text-green-600 hover:text-green-700 transition-colors" title="Télécharger JSON">
                    <i class="fas fa-download"></i>
                </a>
            `);
        }

        // Delete (si completed ou failed ou expired)
        if (['completed', 'failed', 'expired'].includes(task.status)) {
            actions.push(`
                <button onclick="window.historyManager.deleteTask('${task.task_id}')"
                        class="text-red-600 hover:text-red-700 transition-colors"
                        title="Supprimer">
                    <i class="fas fa-trash"></i>
                </button>
            `);
        }

        actionsTd.innerHTML = `
            <div class="flex items-center justify-end space-x-3">
                ${actions.join('')}
            </div>
        `;

        // Append all cells
        tr.appendChild(filenameTd);
        tr.appendChild(statusTd);
        tr.appendChild(dateTd);
        tr.appendChild(packetsTd);
        tr.appendChild(scoreTd);
        tr.appendChild(actionsTd);

        return tr;
    }

    getScoreColor(score) {
        if (score >= 80) return 'bg-green-500';
        if (score >= 60) return 'bg-yellow-500';
        if (score >= 40) return 'bg-orange-500';
        return 'bg-red-500';
    }

    async deleteTask(taskId) {
        if (!confirm('Êtes-vous sûr de vouloir supprimer cette analyse ?')) {
            return;
        }

        try {
            const response = await fetch(`/api/reports/${taskId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                window.toast.success('Analyse supprimée');
                this.loadHistory();
            } else {
                const data = await response.json();
                throw new Error(data.detail || 'Erreur lors de la suppression');
            }
        } catch (error) {
            console.error('Delete error:', error);
            window.toast.error(error.message || 'Erreur lors de la suppression');
        }
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.historyManager = new HistoryManager();
    console.log('History manager initialized');
});
