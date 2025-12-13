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

        this.init();
        this.loadQueueStatus();
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
    }

    async uploadFile() {
        if (!this.selectedFile) {
            window.toast.error('Aucun fichier sélectionné');
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

        try {
            const response = await fetch('/api/upload', {
                method: 'POST',
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
            const response = await fetch('/api/queue/status');
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
