/**
 * PCAP Analyzer - Upload Page
 * Gestion du drag & drop et upload de fichiers PCAP
 */

class UploadManager {
    constructor() {
        this.dropzone = document.getElementById('dropzone');
        this.fileInput = document.getElementById('file-input');
        this.browseBtn = document.getElementById('browse-btn');
        this.uploadBtn = document.getElementById('upload-btn');
        this.clearBtn = document.getElementById('clear-btn');
        this.cancelBtn = document.getElementById('cancel-btn');

        this.dropzoneDefault = document.getElementById('dropzone-default');
        this.dropzoneLoading = document.getElementById('dropzone-loading');
        this.fileInfo = document.getElementById('file-info');

        this.selectedFile = null;
        this.maxFileSize = 500 * 1024 * 1024; // 500 MB
        this.allowedExtensions = ['.pcap', '.pcapng'];

        // Check authentication before initializing
        this.checkAuthentication().then(isAuth => {
            if (isAuth) {
                this.init();
                this.loadQueueStatus();
            }
        });
    }

    async checkAuthentication() {
        const token = localStorage.getItem('access_token');
        console.log('CheckAuth - Token présent:', !!token);
        console.log('CheckAuth - Token length:', token ? token.length : 0);

        if (!token) {
            // No token, redirect to login
            console.log('CheckAuth - No token, redirecting to login');
            window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            return false;
        }

        // Verify token is still valid
        try {
            console.log('CheckAuth - Verifying token with /api/users/me');
            const response = await fetch('/api/users/me', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            console.log('CheckAuth - /api/users/me response status:', response.status);

            if (!response.ok) {
                // Token invalid or expired
                console.log('CheckAuth - Token invalid, clearing and redirecting');
                localStorage.removeItem('access_token');
                localStorage.removeItem('token_type');
                localStorage.removeItem('current_user');
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
                return false;
            }

            console.log('CheckAuth - Token valid, initializing page');
            return true;
        } catch (error) {
            console.error('CheckAuth - Error:', error);
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

    init() {
        // Click sur dropzone
        this.dropzone.addEventListener('click', (e) => {
            if (e.target.id !== 'upload-btn' && e.target.id !== 'clear-btn' && e.target.id !== 'cancel-btn') {
                this.fileInput.click();
            }
        });

        // Browse button
        this.browseBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.fileInput.click();
        });

        // File input change
        this.fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFile(e.target.files[0]);
            }
        });

        // Drag & drop events
        this.dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.dropzone.classList.add('dragover');
        });

        this.dropzone.addEventListener('dragleave', () => {
            this.dropzone.classList.remove('dragover');
        });

        this.dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            this.dropzone.classList.remove('dragover');

            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.handleFile(files[0]);
            }
        });

        // Buttons
        this.uploadBtn.addEventListener('click', () => this.uploadFile());
        this.clearBtn.addEventListener('click', () => this.clearFile());
        this.cancelBtn.addEventListener('click', () => this.clearFile());

        // Refresh queue status every 5 seconds
        setInterval(() => this.loadQueueStatus(), 5000);
    }

    handleFile(file) {
        // Validation extension
        const ext = '.' + file.name.split('.').pop().toLowerCase();
        if (!this.allowedExtensions.includes(ext)) {
            window.toast.error(`Extension non autorisée. Formats acceptés: ${this.allowedExtensions.join(', ')}`);
            this.dropzone.classList.add('error');
            setTimeout(() => this.dropzone.classList.remove('error'), 2000);
            return;
        }

        // Validation taille
        if (file.size > this.maxFileSize) {
            window.toast.error(`Fichier trop volumineux. Taille maximale: ${window.utils.formatFileSize(this.maxFileSize)}`);
            this.dropzone.classList.add('error');
            setTimeout(() => this.dropzone.classList.remove('error'), 2000);
            return;
        }

        // Fichier valide
        this.selectedFile = file;
        this.showFileInfo(file);
    }

    showFileInfo(file) {
        // Afficher les infos du fichier
        document.getElementById('file-name').textContent = file.name;
        document.getElementById('file-size').textContent = window.utils.formatFileSize(file.size);

        // Extraire l'extension et la mettre en majuscules
        const ext = file.name.split('.').pop().toUpperCase();
        document.getElementById('file-extension').textContent = ext;

        // Afficher la date de modification ou "Aujourd'hui"
        const fileDate = new Date(file.lastModified);
        const today = new Date();
        const isToday = fileDate.toDateString() === today.toDateString();

        if (isToday) {
            document.getElementById('file-date').textContent = 'Aujourd\'hui';
        } else {
            const options = { day: 'numeric', month: 'short', year: 'numeric' };
            document.getElementById('file-date').textContent = fileDate.toLocaleDateString('fr-FR', options);
        }

        // Masquer complètement la dropzone et afficher la preview card avec animation
        this.dropzone.classList.add('hidden');
        this.fileInfo.classList.remove('hidden');

        window.toast.success('Fichier sélectionné. Cliquez sur "Lancer l\'analyse" pour continuer.');
    }

    clearFile() {
        this.selectedFile = null;
        this.fileInput.value = '';
        this.fileInfo.classList.add('hidden');
        this.dropzone.classList.remove('hidden');
        this.dropzoneDefault.classList.remove('hidden');
        this.dropzoneLoading.classList.add('hidden');
        this.dropzone.classList.remove('error');
        // Hide validation error display if visible
        const errorDisplay = document.getElementById('pcap-validation-error');
        if (errorDisplay) {
            errorDisplay.classList.add('hidden');
        }
    }

    displayPCAPValidationError(validationDetails) {
        const errorContainer = document.getElementById('pcap-validation-error');
        if (!errorContainer) return;

        // Populate content
        document.getElementById('error-title').textContent = validationDetails.title;
        document.getElementById('error-description').textContent = validationDetails.description;

        // Populate issues list
        const issuesList = document.getElementById('error-issues');
        issuesList.innerHTML = '';
        validationDetails.detected_issues.forEach(issue => {
            const li = document.createElement('li');
            li.className = 'flex items-start';
            li.innerHTML = `
                <svg class="h-4 w-4 text-red-500 mt-0.5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                </svg>
                <span>${issue}</span>
            `;
            issuesList.appendChild(li);
        });

        // Populate suggestions list
        const suggestionsList = document.getElementById('error-suggestions');
        suggestionsList.innerHTML = '';
        validationDetails.suggestions.forEach(suggestion => {
            const li = document.createElement('li');
            li.className = 'flex items-start';
            li.innerHTML = `
                <svg class="h-4 w-4 text-green-500 mt-0.5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                </svg>
                <span>${suggestion}</span>
            `;
            suggestionsList.appendChild(li);
        });

        // Update Wireshark link
        document.getElementById('wireshark-link').href = validationDetails.wireshark_link;

        // Setup retry button (clear existing listeners by cloning)
        const retryBtn = document.getElementById('retry-upload-btn');
        const newRetryBtn = retryBtn.cloneNode(true);
        retryBtn.parentNode.replaceChild(newRetryBtn, retryBtn);
        newRetryBtn.addEventListener('click', () => {
            errorContainer.classList.add('hidden');
            // Reset to initial state
            this.clearFile();
        });

        // Show error container
        errorContainer.classList.remove('hidden');

        // Scroll to error
        errorContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    async uploadFile() {
        if (!this.selectedFile) {
            window.toast.error('Aucun fichier sélectionné');
            return;
        }

        // Check if we have a token
        const token = localStorage.getItem('access_token');
        console.log('Upload - Token présent:', !!token);
        console.log('Upload - Token length:', token ? token.length : 0);

        if (!token) {
            window.toast.error('Session expirée. Reconnexion requise...');
            setTimeout(() => {
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            }, 1500);
            return;
        }

        // Afficher loading overlay au centre
        window.loadingOverlay.show(
            '📤 Upload en cours...',
            `Téléversement de ${this.selectedFile.name}`
        );

        // Afficher aussi l'état loading dans la dropzone
        this.fileInfo.classList.add('hidden');
        this.dropzoneDefault.classList.add('hidden');
        this.dropzoneLoading.classList.remove('hidden');

        const formData = new FormData();
        formData.append('file', this.selectedFile);

        // Get CSRF headers and merge with auth headers
        const csrfHeaders = await window.csrfManager.getHeaders();
        const headers = {
            ...this.getAuthHeaders(),
            ...csrfHeaders
        };
        console.log('Upload - Headers:', headers);

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: headers,
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                // Upload réussi - mettre à jour l'overlay
                window.loadingOverlay.update(
                    '✅ Upload réussi !',
                    'Redirection vers l\'analyse...'
                );

                // Toast de succès plus visible
                window.toast.success('✅ Fichier uploadé avec succès ! Démarrage de l\'analyse...', 3000);

                // Rediriger vers la page de progression après 1.5 secondes
                setTimeout(() => {
                    window.location.href = `/progress/${data.task_id}`;
                }, 1500);
            } else if (response.status === 401) {
                // Not authenticated - redirect to login
                localStorage.removeItem('access_token');
                localStorage.removeItem('token_type');
                localStorage.removeItem('current_user');
                window.csrfManager.clear();
                window.loadingOverlay.hide();
                window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
            } else if (response.status === 403) {
                // CSRF validation failed
                window.loadingOverlay.hide();
                window.toast.error('❌ Erreur de sécurité CSRF. Veuillez rafraîchir la page.', 5000);
                // Revenir à l'état initial
                this.clearFile();
            } else if (response.status === 400 && data.validation_details) {
                // PCAP validation failed - display detailed error
                window.loadingOverlay.hide();
                this.displayPCAPValidationError(data.validation_details);
            } else {
                // Erreur
                throw new Error(data.detail || 'Erreur lors de l\'upload');
            }
        } catch (error) {
            console.error('Upload error:', error);

            // Masquer l'overlay
            window.loadingOverlay.hide();

            // Toast d'erreur plus visible
            window.toast.error('❌ ' + (error.message || 'Erreur lors de l\'upload'), 5000);

            // Revenir à l'état initial
            this.clearFile();
        }
    }

    async loadQueueStatus() {
        try {
            const response = await fetch('/api/queue/status', {
                headers: this.getAuthHeaders()
            });

            if (!response.ok) {
                // If not authenticated, redirect to login
                if (response.status === 401) {
                    window.location.href = '/login?returnUrl=' + encodeURIComponent(window.location.pathname);
                    return;
                }
                throw new Error(`HTTP ${response.status}`);
            }

            const data = await response.json();

            // Mettre à jour les stats
            document.getElementById('queue-size').textContent = data.queue_size;
            document.getElementById('queue-available').textContent = data.queue_available;
            document.getElementById('tasks-completed').textContent = data.tasks_completed;
            document.getElementById('tasks-processing').textContent = data.tasks_processing;

            // Si queue pleine, afficher un avertissement
            if (data.queue_available === 0) {
                window.toast.warning('Serveur occupé. La file d\'attente est pleine. Réessayez dans quelques instants.', 10000);
            }
        } catch (error) {
            console.error('Failed to load queue status:', error);
        }
    }
}

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    window.uploadManager = new UploadManager();
    console.log('Upload manager initialized');
});
