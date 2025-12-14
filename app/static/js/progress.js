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
        this.smoothProgressTimer = null;
        this.currentProgress = 0;
        this.targetProgress = 0;
        this.simulatedProgressTimer = null;
        this.lastRealProgress = 0;

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

    async init() {
        // Set initial message immediately
        this.currentMessage.textContent = 'Initialisation...';
        this.currentMessage.className = 'text-center text-gray-600 dark:text-gray-400 font-medium';

        // Fetch initial task status first
        await this.fetchInitialStatus();

        // Start SSE connection
        this.connectSSE();

        // Start elapsed time timer
        this.startElapsedTimer();

        // Start fallback polling (check status every 3 seconds as backup)
        this.startFallbackPolling();

        // Add initial event
        this.addLogEvent('Connexion au serveur établie', 'info');
    }

    async fetchInitialStatus() {
        /**
         * Récupère le statut initial de la tâche via API REST.
         * Cela permet d'afficher les données même si la page est chargée
         * après que l'analyse soit terminée.
         */
        try {
            const response = await fetch(`/api/status/${this.taskId}`);

            if (!response.ok) {
                console.error('Failed to fetch initial status:', response.status);
                return;
            }

            const taskData = await response.json();
            console.log('Initial task status:', taskData);

            // Update filename if available
            if (taskData.filename) {
                this.updateFilename(taskData.filename);
            }

            // Populate UI with initial data
            if (taskData.status) {
                this.updateStatus(taskData.status);
            }

            // Si la tâche est en cours ou terminée, afficher les données disponibles
            if (taskData.total_packets !== undefined) {
                const isCompleted = taskData.status === 'completed' || taskData.status === 'expired';
                // Utiliser packets_processed si disponible, sinon total si terminé, sinon 0
                const processed = taskData.packets_processed !== undefined
                    ? taskData.packets_processed
                    : (isCompleted ? taskData.total_packets : 0);
                this.updatePackets(processed, taskData.total_packets);
            }

            // Mettre à jour le score si disponible
            if (taskData.health_score !== null && taskData.health_score !== undefined) {
                this.addLogEvent(`Score de santé: ${taskData.health_score.toFixed(1)}/100`, 'success');
            }

            // Si déjà terminé (completed ou expired), afficher l'état de complétion
            if (taskData.status === 'completed' || taskData.status === 'expired') {
                this.updateProgress(100);
                this.updatePhase('completed');
                this.currentAnalyzer.textContent = 'Terminé';
                this.currentMessage.textContent = taskData.status === 'expired'
                    ? 'Analyse terminée (rapport expiré)'
                    : 'Analyse terminée avec succès';

                // Afficher les boutons d'action seulement si les rapports existent encore
                if (taskData.report_html_url && taskData.status === 'completed') {
                    this.actionButtons.classList.remove('hidden');
                    document.getElementById('view-report-btn').href = taskData.report_html_url;

                    if (taskData.report_json_url) {
                        document.getElementById('download-json-btn').href = taskData.report_json_url;
                    }
                } else if (taskData.status === 'expired') {
                    // Pour les tâches expirées, afficher un message
                    this.actionButtons.innerHTML = `
                        <div class="card glass">
                            <div class="bg-orange-50 dark:bg-orange-900/20 border-l-4 border-orange-500 p-4 mb-4 rounded">
                                <div class="flex items-start">
                                    <i class="fas fa-hourglass-end text-orange-500 mt-1 mr-3"></i>
                                    <div>
                                        <h3 class="text-sm font-semibold text-orange-800 dark:text-orange-300 mb-1">
                                            Rapport expiré
                                        </h3>
                                        <p class="text-sm text-orange-700 dark:text-orange-400">
                                            Les rapports ont expiré (conservation 24h). Veuillez réanalyser le fichier.
                                        </p>
                                    </div>
                                </div>
                            </div>
                            <a href="/" class="btn btn-primary w-full">
                                <i class="fas fa-upload mr-2"></i>
                                Nouvelle analyse
                            </a>
                        </div>
                    `;
                    this.actionButtons.classList.remove('hidden');
                }

                this.addLogEvent(
                    taskData.status === 'expired'
                        ? '⏰ Analyse expirée (24h)'
                        : '✓ Analyse terminée avec succès',
                    taskData.status === 'expired' ? 'warning' : 'success'
                );
            } else if (taskData.status === 'failed') {
                this.updatePhase('failed');
                this.currentAnalyzer.textContent = 'Échec';
                const errorMsg = taskData.error_message || 'Erreur lors de l\'analyse';
                this.currentMessage.textContent = errorMsg;
                this.currentMessage.className = 'text-center text-red-600 dark:text-red-400 font-medium';
                this.addLogEvent(`✗ ${errorMsg}`, 'error');

                // Show error box with detailed message
                this.actionButtons.innerHTML = `
                    <div class="card glass">
                        <div class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 mb-4 rounded">
                            <div class="flex items-start">
                                <i class="fas fa-exclamation-triangle text-red-500 mt-1 mr-3"></i>
                                <div>
                                    <h3 class="text-sm font-semibold text-red-800 dark:text-red-300 mb-1">
                                        Analyse échouée
                                    </h3>
                                    <p class="text-sm text-red-700 dark:text-red-400">
                                        ${errorMsg}
                                    </p>
                                </div>
                            </div>
                        </div>
                        <a href="/" class="btn btn-primary w-full">
                            <i class="fas fa-upload mr-2"></i>
                            Réessayer avec un autre fichier
                        </a>
                    </div>
                `;
                this.actionButtons.classList.remove('hidden');
            } else if (taskData.status === 'processing') {
                this.updatePhase('analysis');
                this.currentMessage.textContent = 'Analyse en cours...';
                this.currentMessage.className = 'text-center text-gray-600 dark:text-gray-400 font-medium';
            } else if (taskData.status === 'pending') {
                this.updatePhase('metadata');
                this.currentMessage.textContent = 'En attente de démarrage...';
                this.currentMessage.className = 'text-center text-gray-600 dark:text-gray-400 font-medium';
            }

        } catch (error) {
            console.error('Error fetching initial status:', error);
            // Continue anyway - SSE will provide updates
        }
    }

    updateFilename(filename) {
        /**
         * Met à jour le nom du fichier affiché.
         * Corrige le bug où "Chargement..." reste affiché.
         */
        const filenameElement = document.getElementById('filename-text');
        if (filenameElement && filename) {
            filenameElement.textContent = filename;
        }
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

        // Update filename if provided
        if (data.filename) {
            this.updateFilename(data.filename);
        }

        // Update progress circle with smooth animation
        if (data.progress_percent !== undefined) {
            this.lastRealProgress = data.progress_percent;
            this.setTargetProgress(data.progress_percent);

            // Si on passe à 10%, démarrer la simulation de progrès
            if (data.progress_percent === 10 && data.phase === 'metadata') {
                this.startSimulatedProgress();
            }

            // Si on reçoit 90% ou plus, arrêter la simulation
            if (data.progress_percent >= 90) {
                this.stopSimulatedProgress();
            }
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
            this.currentMessage.className = 'text-center text-gray-600 dark:text-gray-400 font-medium';
            this.addLogEvent(data.message, this.getPhaseType(data.phase));
        } else if (data.phase) {
            // Si pas de message spécifique, toujours utiliser un message basé sur la phase
            const phaseMessages = {
                metadata: 'Extraction des métadonnées...',
                analysis: 'Analyse des paquets en cours...',
                finalize: 'Finalisation du rapport...',
                completed: 'Analyse terminée avec succès',
                failed: 'Analyse échouée'
            };
            const defaultMessage = phaseMessages[data.phase];
            if (defaultMessage) {
                this.currentMessage.textContent = defaultMessage;
                this.currentMessage.className = 'text-center text-gray-600 dark:text-gray-400 font-medium';
            }
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
        // Circle circumference = 2 * PI * radius = 2 * 3.14159 * 110 = 691
        const circumference = 691;
        const offset = circumference - (percent / 100) * circumference;
        this.progressCircle.style.strokeDashoffset = offset;
    }

    setTargetProgress(target) {
        /**
         * Anime le progrès de manière fluide de currentProgress vers target.
         * Au lieu de sauter directement de 10% à 90%, l'animation se fait graduellement.
         */
        this.targetProgress = target;

        // Si c'est la première mise à jour (currentProgress = 0 et target > 0), initialiser
        if (this.currentProgress === 0 && target > 0) {
            this.currentProgress = target;
            this.updateProgress(this.currentProgress);
            return;
        }

        // Si on est déjà au bon niveau, pas besoin d'animer
        if (this.currentProgress === this.targetProgress) {
            return;
        }

        // Démarrer l'animation fluide si pas déjà en cours
        if (!this.smoothProgressTimer) {
            this.smoothProgressTimer = setInterval(() => {
                if (this.currentProgress < this.targetProgress) {
                    // Incrémenter graduellement
                    // Pour un saut de 80% (10→90), avec un interval de 50ms et increment de 2%:
                    // Durée = 80 / 2 * 50ms = 2 secondes
                    const increment = Math.min(2, this.targetProgress - this.currentProgress);
                    this.currentProgress = Math.min(
                        this.currentProgress + increment,
                        this.targetProgress
                    );
                    this.updateProgress(Math.round(this.currentProgress));
                } else if (this.currentProgress > this.targetProgress) {
                    // Si on recule (rare mais possible), décrémenter
                    const decrement = Math.min(2, this.currentProgress - this.targetProgress);
                    this.currentProgress = Math.max(
                        this.currentProgress - decrement,
                        this.targetProgress
                    );
                    this.updateProgress(Math.round(this.currentProgress));
                }

                // Arrêter quand on atteint la cible
                if (this.currentProgress === this.targetProgress) {
                    clearInterval(this.smoothProgressTimer);
                    this.smoothProgressTimer = null;
                }
            }, 50); // 50ms interval pour une animation fluide
        }
    }

    startSimulatedProgress() {
        /**
         * Démarre une simulation de progrès pour donner un retour visuel pendant l'analyse.
         * Le backend ne renvoie que 10% → 90%, donc on simule 10% → 85% graduellement.
         * Cela évite que l'utilisateur voie le progrès bloqué à 10% pendant toute l'analyse.
         */
        console.log('Starting simulated progress from 10% to 85%');

        // Arrêter toute simulation en cours
        this.stopSimulatedProgress();

        // Progresser lentement de 10% à 85% (max avant le vrai 90% du serveur)
        // Incrément de 1% par seconde
        // Exemples:
        //   - Analyse rapide (10s) → 10% → 20%
        //   - Analyse moyenne (30s) → 10% → 40%
        //   - Analyse longue (60s) → 10% → 70%
        this.simulatedProgressTimer = setInterval(() => {
            // Ne progresser que si on est entre 10% et 85%
            if (this.targetProgress >= 10 && this.targetProgress < 85) {
                const newTarget = Math.min(this.targetProgress + 1, 85);
                this.setTargetProgress(newTarget);
            }
        }, 1000); // Toutes les secondes
    }

    stopSimulatedProgress() {
        /**
         * Arrête la simulation de progrès.
         * Appelé quand le serveur envoie une vraie mise à jour (90%, 100%, etc.)
         */
        if (this.simulatedProgressTimer) {
            console.log('Stopping simulated progress');
            clearInterval(this.simulatedProgressTimer);
            this.simulatedProgressTimer = null;
        }
    }

    updatePhase(phase) {
        const phases = {
            metadata: 'Extraction métadonnées',
            analysis: 'Analyse des paquets',
            finalize: 'Finalisation',
            completed: 'Terminé',
            failed: 'Échec',
            pending: 'En attente'
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
            },
            expired: {
                class: 'badge-expired',
                icon: 'fas fa-hourglass-end',
                text: 'Expiré'
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

        // Stop timers
        if (this.elapsedTimer) {
            clearInterval(this.elapsedTimer);
        }
        if (this.fallbackTimer) {
            clearInterval(this.fallbackTimer);
        }
        if (this.smoothProgressTimer) {
            clearInterval(this.smoothProgressTimer);
            this.smoothProgressTimer = null;
        }
        this.stopSimulatedProgress();

        // Show success message
        window.toast.success('Analyse terminée avec succès !', 10000);

        // Update progress to 100%
        this.updateProgress(100);

        // Update packets count if available
        if (data.total_packets) {
            this.updatePackets(data.total_packets, data.total_packets);
        }

        // Update analyzer to show completion
        this.currentAnalyzer.textContent = 'Terminé';

        // Update message to show completion
        this.currentMessage.textContent = 'Analyse terminée avec succès';

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

        // Stop timers
        if (this.elapsedTimer) {
            clearInterval(this.elapsedTimer);
        }
        if (this.fallbackTimer) {
            clearInterval(this.fallbackTimer);
        }
        if (this.smoothProgressTimer) {
            clearInterval(this.smoothProgressTimer);
            this.smoothProgressTimer = null;
        }
        this.stopSimulatedProgress();

        // Show error message
        const errorMsg = data.message || 'Erreur lors de l\'analyse';
        window.toast.error('❌ ' + errorMsg, 15000);

        // Update progress to 0%
        this.updateProgress(0);

        // Update analyzer to show failure
        this.currentAnalyzer.textContent = 'Échec';

        // Update current message with error
        this.currentMessage.textContent = errorMsg;
        this.currentMessage.className = 'text-center text-red-600 dark:text-red-400 font-medium';

        // Add error log
        this.addLogEvent(`✗ ${errorMsg}`, 'error');

        // Show error box with detailed message
        this.actionButtons.innerHTML = `
            <div class="card glass">
                <div class="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 mb-4 rounded">
                    <div class="flex items-start">
                        <i class="fas fa-exclamation-triangle text-red-500 mt-1 mr-3"></i>
                        <div>
                            <h3 class="text-sm font-semibold text-red-800 dark:text-red-300 mb-1">
                                Analyse échouée
                            </h3>
                            <p class="text-sm text-red-700 dark:text-red-400">
                                ${errorMsg}
                            </p>
                        </div>
                    </div>
                </div>
                <a href="/" class="btn btn-primary w-full">
                    <i class="fas fa-upload mr-2"></i>
                    Réessayer avec un autre fichier
                </a>
            </div>
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

    startFallbackPolling() {
        /**
         * Polling de fallback pour vérifier le statut de la tâche.
         * Utile si SSE ne fonctionne pas correctement ou se ferme prématurément.
         * Vérifie toutes les 3 secondes si la tâche est terminée.
         */
        this.fallbackTimer = setInterval(async () => {
            try {
                const response = await fetch(`/api/status/${this.taskId}`);
                if (!response.ok) return;

                const taskData = await response.json();

                // Si la tâche est terminée et qu'on a déjà affiché la complétion, skip
                if (taskData.status === 'completed' && !this.actionButtons.classList.contains('hidden')) {
                    // Les boutons sont déjà visibles, on a déjà traité la complétion
                    return;
                }

                // Si la tâche est terminée et qu'on n'a PAS encore affiché la complétion
                if (taskData.status === 'completed' && this.actionButtons.classList.contains('hidden')) {
                    console.log('Fallback polling detected completion (SSE missed it)');
                    this.handleCompletion(taskData);
                } else if (taskData.status === 'failed') {
                    console.log('Fallback polling detected failure');
                    this.handleFailure(taskData);
                }
            } catch (error) {
                console.error('Fallback polling error:', error);
            }
        }, 3000);
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
