/**
 * analyzer.js - API communication, filtering, exports, and result rendering.
 */

window.currentAnalysisData = null;
window.currentSeverityFilter = 'all';

document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyzeBtn');
    const analyzeSpinner = document.getElementById('analyzeSpinner');
    const exportBtn = document.getElementById('exportBtn');
    const exportFormat = document.getElementById('exportFormat');
    const exportGroup = document.getElementById('exportGroup');
    const emptyState = document.getElementById('emptyState');
    const loadingState = document.getElementById('loadingState');
    const resultsContent = document.getElementById('resultsContent');

    analyzeBtn.addEventListener('click', async () => {
        const files = window.getSelectedFiles();
        if (!files || files.length === 0) return;

        setLoading(true);
        const formData = new FormData();
        files.forEach(file => formData.append('files', file));

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: window.getApiHeaders(),
                body: formData
            });

            const payload = await response.json();
            if (!response.ok) throw new Error(payload.error || `Error del servidor: ${response.status}`);

            window.currentAnalysisData = payload;
            renderResults(payload);
            window.updateDashboardStats(payload);
            window.clearSelectedFiles();
            window.showToast('Analisis completado.', 'success');
        } catch (error) {
            console.error('Analysis error:', error);
            window.showToast(`Error: ${error.message}`, 'danger');
            loadingState.classList.add('d-none');
            emptyState.classList.remove('d-none');
        } finally {
            setLoading(false);
        }
    });

    exportBtn.addEventListener('click', async () => {
        if (!window.currentAnalysisData || window.currentAnalysisData.length === 0) return;

        const activeTab = document.querySelector('.file-tabs .nav-link.active');
        const idx = activeTab ? parseInt(activeTab.getAttribute('data-idx'), 10) : 0;
        const dataToExport = window.currentAnalysisData[idx];
        if (!dataToExport || dataToExport.error) {
            window.showToast('No se puede exportar este resultado.', 'warning');
            return;
        }
        if (!dataToExport.findings) {
            window.showToast('No hay hallazgos disponibles para exportar en este registro del historial.', 'warning');
            return;
        }

        try {
            const format = exportFormat.value;
            const response = await fetch('/api/export', {
                method: 'POST',
                headers: window.getApiHeaders({ 'Content-Type': 'application/json' }),
                body: JSON.stringify(Object.assign({}, dataToExport, { format }))
            });

            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                throw new Error(payload.error || 'Fallo la exportacion');
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.style.display = 'none';
            link.href = url;
            link.download = `reporte_${safeFilename(dataToExport.filename)}.${format === 'sarif' ? 'sarif' : format}`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);
            window.showToast('Reporte exportado.', 'success');
        } catch (error) {
            console.error(error);
            window.showToast(`Error al exportar: ${error.message}`, 'danger');
        }
    });

    document.querySelectorAll('[data-filter-severity]').forEach(button => {
        button.addEventListener('click', () => {
            document.querySelectorAll('[data-filter-severity]').forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            window.currentSeverityFilter = button.getAttribute('data-filter-severity');
            if (window.currentAnalysisData) renderResults(window.currentAnalysisData, { keepActiveTab: true });
        });
    });

    function setLoading(isLoading) {
        analyzeBtn.disabled = isLoading || window.getSelectedFiles().length === 0;
        analyzeSpinner.classList.toggle('d-none', !isLoading);
        loadingState.classList.toggle('d-none', !isLoading);
        if (isLoading) {
            emptyState.classList.add('d-none');
            resultsContent.classList.add('d-none');
            exportGroup.classList.add('d-none');
        }
    }
});

function renderResults(resultsArray, options = {}) {
    const loadingState = document.getElementById('loadingState');
    const resultsContent = document.getElementById('resultsContent');
    const fileTabs = document.getElementById('fileTabs');
    const tabContent = document.getElementById('findingsTabContent');
    const exportGroup = document.getElementById('exportGroup');

    const previousActive = options.keepActiveTab
        ? document.querySelector('.file-tabs .nav-link.active')?.getAttribute('data-idx')
        : null;

    loadingState.classList.add('d-none');
    resultsContent.classList.remove('d-none');
    exportGroup.classList.remove('d-none');
    fileTabs.replaceChildren();
    tabContent.replaceChildren();

    if (!resultsArray || resultsArray.length === 0) return;

    resultsArray.forEach((result, idx) => {
        const isActive = previousActive ? String(idx) === previousActive : idx === 0;
        const tab = document.createElement('li');
        tab.className = 'nav-item';
        tab.role = 'presentation';
        tab.innerHTML = `
            <button class="nav-link ${isActive ? 'active' : ''}" id="tab-${idx}" data-bs-toggle="tab"
                data-bs-target="#pane-${idx}" type="button" role="tab" data-idx="${idx}">
                <i class="${getFileIcon(result.file_type)} me-1"></i>${escapeHtml(result.filename)}
            </button>
        `;
        fileTabs.appendChild(tab);

        const pane = document.createElement('div');
        pane.className = `tab-pane fade ${isActive ? 'show active' : ''}`;
        pane.id = `pane-${idx}`;
        pane.role = 'tabpanel';

        if (result.error) {
            pane.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fa-solid fa-triangle-exclamation me-2"></i>${escapeHtml(result.error)}
                </div>`;
        } else if (!result.findings) {
            pane.innerHTML = `
                <div class="alert alert-info">
                    Este historial fue guardado sin hallazgos completos. Activa STORE_FULL_HISTORY para conservar detalle sanitizado.
                </div>`;
        } else {
            pane.innerHTML = buildFindingsHtml(result.findings);
        }
        tabContent.appendChild(pane);
    });

    document.querySelectorAll('#fileTabs button').forEach(triggerEl => {
        triggerEl.addEventListener('shown.bs.tab', event => {
            const idx = event.target.getAttribute('data-idx');
            const result = resultsArray[idx];
            if (!result.error && result.summary) {
                window.updateCharts(result.summary);
            } else {
                window.clearCharts();
            }
        });
    });

    const activeResult = resultsArray[previousActive || 0] || resultsArray[0];
    if (activeResult && !activeResult.error && activeResult.summary) {
        window.updateCharts(activeResult.summary);
    } else {
        window.clearCharts();
    }
}

function buildFindingsHtml(findings) {
    const filtered = filterFindings(findings || []);
    if (filtered.length === 0) {
        return `
            <div class="empty-state">
                <i class="fa-solid fa-circle-check"></i>
                <h3>Sin hallazgos para el filtro</h3>
                <p>Cambia la severidad seleccionada.</p>
            </div>
        `;
    }

    const severityMap = {
        critical: 'Critico',
        high: 'Alto',
        medium: 'Medio',
        low: 'Bajo',
        info: 'Info'
    };

    return filtered.map(finding => {
        const line = finding.line_number ? `<span class="badge text-bg-secondary mb-2">Linea ${finding.line_number}</span>` : '';
        const code = finding.line_content ? `<div class="finding-code">${escapeHtml(finding.line_content)}</div>` : '';
        const standards = finding.standards && finding.standards.length
            ? `<div class="finding-standards"><i class="fa-solid fa-scale-balanced me-1"></i>${finding.standards.map(escapeHtml).join(', ')}</div>`
            : '';
        const severity = severityMap[finding.severity] || finding.severity.toUpperCase();
        return `
            <article class="finding-item finding-${finding.severity}" data-severity="${finding.severity}">
                <div class="finding-header">
                    <h3 class="finding-title">${escapeHtml(finding.title)}</h3>
                    <span class="badge badge-${finding.severity}">${severity.toUpperCase()}</span>
                </div>
                <div class="finding-desc">${escapeHtml(finding.description)}</div>
                ${line}
                ${code}
                ${standards}
                <div class="finding-rec">
                    <i class="fa-solid fa-lightbulb me-1"></i>${escapeHtml(finding.recommendation)}
                </div>
            </article>
        `;
    }).join('');
}

function filterFindings(findings) {
    if (window.currentSeverityFilter === 'all') return findings;
    return findings.filter(finding => finding.severity === window.currentSeverityFilter);
}

function getFileIcon(type) {
    const icons = {
        dockerfile: 'fa-brands fa-docker text-primary',
        compose: 'fa-solid fa-cubes-stacked text-info',
        kubernetes: 'fa-solid fa-dharmachakra text-primary',
        env: 'fa-solid fa-key text-warning',
        unknown: 'fa-regular fa-file-code'
    };
    return icons[type] || icons.unknown;
}

function safeFilename(filename) {
    return String(filename || 'unknown').replace(/[^a-z0-9]/gi, '_').toLowerCase();
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
