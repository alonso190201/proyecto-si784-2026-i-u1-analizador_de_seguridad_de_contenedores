/**
 * analyzer.js - API communication and result rendering.
 */

window.currentAnalysisData = null; // Store for export

document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const analyzeSpinner = document.getElementById('analyzeSpinner');
    const exportBtn = document.getElementById('exportBtn');
    
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultsContent = document.getElementById('resultsContent');

    analyzeBtn.addEventListener('click', async () => {
        const files = window.getSelectedFiles();
        if (!files || files.length === 0) return;

        // UI Loading State
        analyzeBtn.disabled = true;
        analyzeSpinner.classList.remove('d-none');
        emptyState.classList.add('d-none');
        resultsContent.classList.add('d-none');
        loadingState.classList.remove('d-none');
        exportBtn.classList.add('d-none');

        const formData = new FormData();
        files.forEach(f => formData.append('files', f));

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errData = await response.json();
                throw new Error(errData.error || `Error del servidor: ${response.status}`);
            }

            const results = await response.json();
            window.currentAnalysisData = results;
            renderResults(results);
            window.updateDashboardStats(results);
            window.clearSelectedFiles();

        } catch (error) {
            console.error('Analysis error:', error);
            alert(`Error en el análisis: ${error.message}`);
            
            // Reset UI on error
            loadingState.classList.add('d-none');
            emptyState.classList.remove('d-none');
        } finally {
            analyzeBtn.disabled = window.getSelectedFiles().length === 0;
            analyzeSpinner.classList.add('d-none');
        }
    });

    exportBtn.addEventListener('click', async () => {
        if (!window.currentAnalysisData || window.currentAnalysisData.length === 0) return;
        
        // Export the currently viewed tab (or the first file if single)
        const activeTab = document.querySelector('.custom-tabs .nav-link.active');
        const idx = activeTab ? parseInt(activeTab.getAttribute('data-idx')) : 0;
        const dataToExport = window.currentAnalysisData[idx];

        if(dataToExport.error) {
            alert("No se puede exportar un archivo con errores.");
            return;
        }

        try {
            const response = await fetch('/api/export', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(dataToExport)
            });
            
            if (!response.ok) throw new Error('Falló la exportación');
            
            // Trigger download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `reporte_${dataToExport.filename.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.html`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        } catch (error) {
            console.error(error);
            alert("Error al exportar el reporte.");
        }
    });
});

function renderResults(resultsArray) {
    const loadingState = document.getElementById('loadingState');
    const resultsContent = document.getElementById('resultsContent');
    const fileTabs = document.getElementById('fileTabs');
    const tabContent = document.getElementById('findingsTabContent');
    const exportBtn = document.getElementById('exportBtn');

    loadingState.classList.add('d-none');
    resultsContent.classList.remove('d-none');
    exportBtn.classList.remove('d-none');

    fileTabs.innerHTML = '';
    tabContent.innerHTML = '';

    if (resultsArray.length === 0) return;

    resultsArray.forEach((result, idx) => {
        // Tab Nav
        const isActive = idx === 0 ? 'active' : '';
        const icon = getFileIcon(result.file_type);
        
        const li = document.createElement('li');
        li.className = 'nav-item';
        li.role = 'presentation';
        li.innerHTML = `
            <button class="nav-link ${isActive}" id="tab-${idx}" data-bs-toggle="tab" 
                data-bs-target="#pane-${idx}" type="button" role="tab" data-idx="${idx}">
                <i class="${icon} me-1"></i> ${escapeHtml(result.filename)}
            </button>
        `;
        fileTabs.appendChild(li);

        // Tab Content
        const pane = document.createElement('div');
        pane.className = `tab-pane fade ${isActive ? 'show active' : ''}`;
        pane.id = `pane-${idx}`;
        pane.role = 'tabpanel';
        
        if (result.error) {
            pane.innerHTML = `
                <div class="alert alert-danger bg-danger-subtle text-danger border-0">
                    <i class="fa-solid fa-triangle-exclamation me-2"></i>
                    ${escapeHtml(result.error)}
                </div>`;
        } else {
            // Render Findings
            pane.innerHTML = buildFindingsHtml(result.findings);
        }
        tabContent.appendChild(pane);
    });

    // Handle tab change to update charts
    const triggerTabList = document.querySelectorAll('#fileTabs button');
    triggerTabList.forEach(triggerEl => {
        triggerEl.addEventListener('shown.bs.tab', event => {
            const idx = event.target.getAttribute('data-idx');
            const res = resultsArray[idx];
            if (!res.error && res.summary) {
                window.updateCharts(res.summary);
            }
        });
    });

    // Initial chart load
    if (!resultsArray[0].error && resultsArray[0].summary) {
        window.updateCharts(resultsArray[0].summary);
    }
}

function buildFindingsHtml(findings) {
    if (!findings || findings.length === 0) {
        return `
            <div class="text-center p-5">
                <i class="fa-solid fa-shield-check fa-4x text-success mb-3"></i>
                <h5>No se detectaron problemas de seguridad</h5>
                <p class="text-muted small">Esta configuración pasó todas las pruebas de análisis estático.</p>
            </div>
        `;
    }

    const severityMap = {
        'critical': 'Crítico',
        'high': 'Alto',
        'medium': 'Medio',
        'low': 'Bajo',
        'info': 'Info'
    };

    let html = '';
    findings.forEach(f => {
        const ln = f.line_number ? `Línea ${f.line_number}` : '';
        const lc = f.line_content ? `<div class="finding-code mt-2">${escapeHtml(f.line_content)}</div>` : '';
        const severityStr = severityMap[f.severity] || f.severity.toUpperCase();
        
        html += `
            <div class="finding-item finding-${f.severity}">
                <div class="finding-header">
                    <h6 class="finding-title">${escapeHtml(f.title)}</h6>
                    <span class="badge badge-${f.severity}">${severityStr.toUpperCase()}</span>
                </div>
                <div class="finding-desc">${escapeHtml(f.description)}</div>
                ${ln ? `<span class="badge bg-secondary mb-2">${ln}</span>` : ''}
                ${lc}
                <div class="finding-rec">
                    <i class="fa-solid fa-lightbulb me-1"></i> ${escapeHtml(f.recommendation)}
                </div>
            </div>
        `;
    });
    return html;
}

function getFileIcon(type) {
    const icons = {
        'dockerfile': 'fa-brands fa-docker text-primary',
        'compose': 'fa-solid fa-cubes-stacked text-info',
        'kubernetes': 'fa-solid fa-dharmachakra text-primary',
        'env': 'fa-solid fa-key text-warning',
        'unknown': 'fa-regular fa-file-code'
    };
    return icons[type] || icons['unknown'];
}

function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe
         .toString()
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
