/**
 * upload.js - Drag/drop and upload queue handling.
 */

let selectedFiles = [];

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const analyzeBtn = document.getElementById('analyzeBtn');

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'), false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'), false);
    });

    dropZone.addEventListener('drop', event => handleFiles(event.dataTransfer.files));
    dropZone.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            fileInput.click();
        }
    });
    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });

    function preventDefaults(event) {
        event.preventDefault();
        event.stopPropagation();
    }

    function handleFiles(files) {
        const incoming = Array.from(files);
        const seen = new Set(selectedFiles.map(fileKey));
        incoming.forEach(file => {
            if (!seen.has(fileKey(file))) selectedFiles.push(file);
        });
        updateQueueUI();
    }

    function updateQueueUI() {
        const queueContainer = document.getElementById('uploadQueue');
        queueContainer.replaceChildren();
        analyzeBtn.disabled = selectedFiles.length === 0;

        selectedFiles.forEach((file, index) => {
            const item = document.createElement('div');
            item.className = 'queue-item';

            const nameWrap = document.createElement('div');
            nameWrap.className = 'queue-name';

            const icon = document.createElement('i');
            icon.className = 'fa-regular fa-file-code text-primary';
            const name = document.createElement('span');
            name.textContent = file.name;
            const size = document.createElement('small');
            size.className = 'queue-size';
            size.textContent = `${(file.size / 1024).toFixed(1)} KB`;

            nameWrap.append(icon, name, size);

            const remove = document.createElement('button');
            remove.className = 'btn btn-sm btn-outline-danger';
            remove.type = 'button';
            remove.title = 'Quitar archivo';
            remove.innerHTML = '<i class="fa-solid fa-xmark"></i>';
            remove.addEventListener('click', () => {
                selectedFiles.splice(index, 1);
                updateQueueUI();
            });

            item.append(nameWrap, remove);
            queueContainer.appendChild(item);
        });
    }

    function fileKey(file) {
        return `${file.name}:${file.size}:${file.lastModified}`;
    }

    window.getSelectedFiles = () => selectedFiles;
    window.clearSelectedFiles = () => {
        selectedFiles = [];
        updateQueueUI();
        fileInput.value = '';
    };
});
