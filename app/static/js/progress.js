/**
 * PCAP Analyzer - Progress Page
 * Suivi temps réel via Server-Sent Events (SSE)
 */

class ProgressMonitor {
    constructor(taskId) {
        this.taskId = taskId;
        this.eventSource = null;
        this.startTime = new Date();
        this.elapsedTimer = null;

        // Elements
        this.progressCircle = document.getElementById('progress-circle');
        this.progressPercent = document.getElementById('progress-percent');
        this.progressPhase = document.getElementById('progress-phase');
        this.progressBarFill = document.getElementById('progress-bar-fill');
        this.currentPhase = document.getElementById('current-phase');
        this.packetsCount = document.getElementById('packets-count');
        this.currentAnalyzer = document.getElementById('current-analyzer');
        this.currentMessage = document.getElementById('current-message');
        this.statusBadge = document.getElementById('status-badge');
        this.actionButtons = document.getElementById('action-buttons');
        this.eventLog = document.getElementById('event-log');

        this.init();
    }

    init() {
        // Start SSE connection
        this.connectSSE();

        // Start elapsed time timer
        this.startElapsedTimer();

        // Add initial event
        this.addLogEvent('Connexion au serveur établie', 'info');
    }

    connectSSE() {
        const url = `/api/progress/${this.taskId}`;
        this.eventSource = new EventSource(url);

        this.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                this.handleProgressUpdate(data);
            } catch (error) {
                console.error('Error parsing SSE data:', error);
            }
        };

        this.eventSource.onerror = (error) => {
            console.error('SSE connection error:', error);
            this.handleConnectionError();
        };

        console.log(`SSE connected to ${url}`);
    }

    handleProgressUpdate(data) {
        console.log('Progress update:', data);

        // Update progress circle
        if (data.progress_percent !== undefined) {
            this.updateProgress(data.progress_percent);
        }

        // Update phase
        if (data.phase) {
            this.updatePhase(data.phase);
        }

        // Update packets count
        if (data.packets_processed !== undefined && data.total_packets !== undefined) {
            this.updatePackets(data.packets_processed, data.total_packets);
        }

        // Update current analyzer
        if (data.current_analyzer) {
            this.currentAnalyzer.textContent = data.current_analyzer;
        }

        // Update message
        if (data.message) {
            this.currentMessage.textContent = data.message;
            this.addLogEvent(data.message, this.getPhaseType(data.phase));
        }

        // Update status badge
        if (data.status) {
            this.updateStatus(data.status);
        }

        // Handle completion
        if (data.status === 'completed' || data.phase === 'completed') {
            this.handleCompletion(data);
        }

        // Handle failure
        if (data.status === 'failed' || data.phase === 'failed') {
            this.handleFailure(data);
        }
    }

    updateProgress(percent) {
        // Update percentage display
        this.progressPercent.textContent = `${percent}%`;

        // Update progress bar
        this.progressBarFill.style.width = `${percent}%`;

        // Update SVG circle (stroke-dashoffset)
        // Circle circumference = 2 * PI * radius = 2 * 3.14159 * 90 = 565
        const circumference = 565;
        const offset = circumference - (percent / 100) * circumference;
        this.progressCircle.style.strokeDashoffset = offset;
    }

    updatePhase(phase) {
        const phases = {
            metadata: 'Extraction métadonnées',
            analysis: 'Analyse des paquets',
            finalize: 'Finalisation',
            completed: 'Terminé',
            failed: 'Échec'
        };

        const phaseName = phases[phase] || phase;
        this.progressPhase.textContent = phaseName;
        this.currentPhase.textContent = phaseName;
    }

    updatePackets(processed, total) {
        this.packetsCount.textContent = `${processed.toLocaleString('fr-FR')} / ${total.toLocaleString('fr-FR')}`;
    }

    updateStatus(status) {
        const statusConfig = {
            pending: {
                class: 'badge-pending',
                icon: 'fas fa-clock',
                text: 'En attente'
            },
            processing: {
                class: 'badge-processing',
                icon: 'fas fa-spinner fa-spin',
                text: 'En cours'
            },
            completed: {
                class: 'badge-completed',
                icon: 'fas fa-check-circle',
                text: 'Terminé'
            },
            failed: {
                class: 'badge-failed',
                icon: 'fas fa-exclamation-circle',
                text: 'Échec'
            }
        };

        const config = statusConfig[status] || statusConfig.processing;

        this.statusBadge.className = `badge ${config.class}`;
        this.statusBadge.innerHTML = `
            <i class="${config.icon} mr-1"></i>
            ${config.text}
        `;
    }

    handleCompletion(data) {
        // Stop SSE
        if (this.eventSource) {
            this.eventSource.close();
        }

        // Stop timer
        if (this.elapsedTimer) {
            clearInterval(this.elapsedTimer);
        }

        // Show success message
        window.toast.success('Analyse terminée avec succès !', 10000);

        // Update progress to 100%
        this.updateProgress(100);

        // Show action buttons
        this.actionButtons.classList.remove('hidden');

        // Set report URLs
        if (data.report_html_url) {
            document.getElementById('view-report-btn').href = data.report_html_url;
        }
        if (data.report_json_url) {
            document.getElementById('download-json-btn').href = data.report_json_url;
        }

        // Add completion log
        this.addLogEvent('✓ Analyse terminée avec succès', 'success');

        if (data.health_score !== undefined) {
            this.addLogEvent(`Score de santé: ${data.health_score.toFixed(1)}/100`, 'success');
        }
    }

    handleFailure(data) {
        // Stop SSE
        if (this.eventSource) {
            this.eventSource.close();
        }

        // Stop timer
        if (this.elapsedTimer) {
            clearInterval(this.elapsedTimer);
        }

        // Show error message
        const errorMsg = data.message || 'Erreur lors de l\'analyse';
        window.toast.error(errorMsg, 15000);

        // Update progress to 0%
        this.updateProgress(0);

        // Add error log
        this.addLogEvent(`✗ Erreur: ${errorMsg}`, 'error');

        // Show back button
        this.actionButtons.innerHTML = `
            <a href="/" class="btn btn-primary flex-1">
                <i class="fas fa-arrow-left mr-2"></i>
                Retour à l'upload
            </a>
        `;
        this.actionButtons.classList.remove('hidden');
    }

    handleConnectionError() {
        this.addLogEvent('⚠ Perte de connexion avec le serveur', 'warning');

        // Tentative de reconnexion après 3 secondes
        setTimeout(() => {
            this.addLogEvent('Tentative de reconnexion...', 'info');
            if (this.eventSource) {
                this.eventSource.close();
            }
            this.connectSSE();
        }, 3000);
    }

    startElapsedTimer() {
        const elapsedElement = document.getElementById('elapsed-time');

        this.elapsedTimer = setInterval(() => {
            const elapsed = Math.floor((new Date() - this.startTime) / 1000);
            elapsedElement.textContent = window.utils.formatDuration(elapsed);
        }, 1000);
    }

    addLogEvent(message, type = 'info') {
        const timestamp = new Date().toLocaleTimeString('fr-FR');

        // Icons et couleurs par type
        const config = {
            info: { icon: 'fas fa-info-circle', color: 'text-blue-600 dark:text-blue-400' },
            success: { icon: 'fas fa-check-circle', color: 'text-green-600 dark:text-green-400' },
            warning: { icon: 'fas fa-exclamation-triangle', color: 'text-orange-600 dark:text-orange-400' },
            error: { icon: 'fas fa-exclamation-circle', color: 'text-red-600 dark:text-red-400' }
        };

        const { icon, color } = config[type] || config.info;

        const eventElement = document.createElement('div');
        eventElement.className = 'flex items-start space-x-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg animate-slide-in-right';
        eventElement.innerHTML = `
            <i class="${icon} ${color} mt-0.5"></i>
            <div class="flex-1">
                <p class="text-sm text-gray-900 dark:text-gray-100">${message}</p>
                <p class="text-xs text-gray-500 dark:text-gray-400 mt-1">${timestamp}</p>
            </div>
        `;

        // Clear placeholder si nécessaire
        if (this.eventLog.querySelector('.text-center')) {
            this.eventLog.innerHTML = '';
        }

        // Ajouter en haut du log
        this.eventLog.insertBefore(eventElement, this.eventLog.firstChild);

        // Limiter à 50 événements
        while (this.eventLog.children.length > 50) {
            this.eventLog.removeChild(this.eventLog.lastChild);
        }
    }

    getPhaseType(phase) {
        const types = {
            metadata: 'info',
            analysis: 'info',
            finalize: 'info',
            completed: 'success',
            failed: 'error'
        };
        return types[phase] || 'info';
    }
}
