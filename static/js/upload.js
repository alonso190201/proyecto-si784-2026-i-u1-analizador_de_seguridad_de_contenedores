/**
 * upload.js - Handles drag & drop, file selection, and queues.
 */

let selectedFiles = [];

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');

    // Drag events
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    // Handle drops
    dropZone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    });

    // Handle browse click
    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });

    function handleFiles(files) {
        const newFiles = Array.from(files);
        // Basic filtering (optional, server also validates)
        selectedFiles = [...selectedFiles, ...newFiles];
        updateQueueUI();
    }

    function updateQueueUI() {
        const queueContainer = document.getElementById('uploadQueue');
        queueContainer.innerHTML = '';
        
        if (selectedFiles.length === 0) {
            analyzeBtn.disabled = true;
            return;
        }

        analyzeBtn.disabled = false;

        selectedFiles.forEach((file, index) => {
            const size = (file.size / 1024).toFixed(1);
            const item = document.createElement('div');
            item.className = 'd-flex justify-content-between align-items-center bg-dark p-2 rounded mb-2 border border-secondary';
            item.innerHTML = `
                <div class="text-truncate me-3" style="max-width: 80%;">
                    <i class="fa-regular fa-file-code text-cyan me-2"></i>
                    <span class="small">${file.name}</span>
                    <span class="text-muted" style="font-size:10px; margin-left:8px;">${size} KB</span>
                </div>
                <button class="btn btn-sm text-danger remove-file" data-index="${index}">
                    <i class="fa-solid fa-xmark"></i>
                </button>
            `;
            queueContainer.appendChild(item);
        });

        // Add remove listeners
        document.querySelectorAll('.remove-file').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = e.currentTarget.getAttribute('data-index');
                selectedFiles.splice(idx, 1);
                updateQueueUI();
            });
        });
    }

    // Export function to get files for analyzer.js
    window.getSelectedFiles = () => selectedFiles;
    window.clearSelectedFiles = () => {
        selectedFiles = [];
        updateQueueUI();
        fileInput.value = ''; // reset input
    };
});
