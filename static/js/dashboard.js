/**
 * dashboard.js - Charts, aggregate counters, and history modal.
 */

let severityChartObj = null;
let totalScans = 0;
let totalCritical = 0;
let totalHigh = 0;
let sumScore = 0;
let scoreCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    loadInitialStats();

    const historyModal = document.getElementById('historyModal');
    if (historyModal) historyModal.addEventListener('show.bs.modal', loadHistory);

    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/history', {
                    method: 'DELETE',
                    headers: window.getApiHeaders()
                });
                if (!response.ok) throw new Error('No se pudo borrar el historial');
                document.getElementById('historyContainer').innerHTML = '<div class="p-4 text-center text-muted">Historial borrado.</div>';
                
                // Reset local statistics counters and UI
                totalScans = 0;
                totalCritical = 0;
                totalHigh = 0;
                sumScore = 0;
                scoreCount = 0;
                document.getElementById('statTotalScans').innerText = 0;
                document.getElementById('statCritical').innerText = 0;
                document.getElementById('statHigh').innerText = 0;
                document.getElementById('statAvgScore').innerText = '--';

                window.showToast('Historial borrado.', 'success');
            } catch (error) {
                window.showToast(error.message, 'danger');
            }
        });
    }
});

async function loadInitialStats() {
    try {
        const response = await fetch('/api/history', { headers: window.getApiHeaders() });
        if (!response.ok) throw new Error('No se pudo cargar las estadísticas iniciales');
        const history = await response.json();
        if (history && history.length > 0) {
            window.updateDashboardStats(history);
        }
    } catch (e) {
        console.error("Error al cargar estadísticas iniciales:", e);
    }
}

function initChart() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    severityChartObj = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critico', 'Alto', 'Medio', 'Bajo', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#2563eb', '#64748b'],
                borderWidth: 0,
                cutout: '72%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#334155', boxWidth: 12, font: { family: 'Inter' } }
                }
            }
        }
    });
}

window.updateCharts = function(summary) {
    const scoreVal = document.getElementById('scoreValue');
    const badge = document.getElementById('gradeBadge');
    const explanation = document.getElementById('scoreExplanation');

    scoreVal.innerText = summary.score;
    scoreVal.style.color = summary.grade_color;
    badge.innerText = `Grado ${summary.grade}`;
    badge.style.backgroundColor = summary.grade_color;
    explanation.innerText = summary.score_explanation || '';

    if (severityChartObj) {
        const counts = summary.counts || {};
        severityChartObj.data.datasets[0].data = [
            counts.critical || 0,
            counts.high || 0,
            counts.medium || 0,
            counts.low || 0,
            counts.info || 0
        ];
        severityChartObj.update();
    }
};

window.clearCharts = function() {
    const scoreVal = document.getElementById('scoreValue');
    const badge = document.getElementById('gradeBadge');
    const explanation = document.getElementById('scoreExplanation');

    if (scoreVal) {
        scoreVal.innerText = '--';
        scoreVal.style.color = 'var(--muted)';
    }
    if (badge) {
        badge.innerText = 'ERROR';
        badge.style.backgroundColor = 'var(--red)';
    }
    if (explanation) {
        explanation.innerText = 'El análisis de este archivo falló o no contiene resultados válidos.';
    }

    if (severityChartObj) {
        severityChartObj.data.datasets[0].data = [0, 0, 0, 0, 0];
        severityChartObj.update();
    }
};

window.updateDashboardStats = function(resultsArray) {
    resultsArray.forEach(result => {
        if (!result.error && result.summary) {
            totalScans++;
            totalCritical += result.summary.counts.critical || 0;
            totalHigh += result.summary.counts.high || 0;
            sumScore += result.summary.score || 0;
            scoreCount++;
        }
    });

    document.getElementById('statTotalScans').innerText = totalScans;
    document.getElementById('statCritical').innerText = totalCritical;
    document.getElementById('statHigh').innerText = totalHigh;
    document.getElementById('statAvgScore').innerText = scoreCount > 0 ? Math.round(sumScore / scoreCount) : '--';
};

async function loadHistory() {
    const container = document.getElementById('historyContainer');
    container.innerHTML = '<div class="p-4 text-center text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Cargando...</div>';

    try {
        const response = await fetch('/api/history', { headers: window.getApiHeaders() });
        const history = await response.json();
        if (!response.ok) throw new Error(history.error || 'No se pudo cargar el historial');

        if (history.length === 0) {
            container.innerHTML = '<div class="p-4 text-center text-muted">No hay historial disponible.</div>';
            return;
        }

        container.replaceChildren();
        history.forEach(item => container.appendChild(buildHistoryItem(item)));
    } catch (error) {
        container.innerHTML = `<div class="p-4 text-center text-danger">${escapeHtml(error.message)}</div>`;
    }
}

function buildHistoryItem(item) {
    const wrapper = document.createElement('div');
    wrapper.className = 'history-item';

    const date = item.timestamp ? new Date(item.timestamp) : null;
    const dateText = date ? `${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : '';
    const grade = item.summary ? `${item.summary.grade} - ${item.summary.score}/100` : 'Sin score';
    const gradeColor = item.summary ? item.summary.grade_color : '#64748b';

    wrapper.innerHTML = `
        <div class="history-title">
            <strong><i class="fa-regular fa-file me-2"></i>${escapeHtml(item.filename)}</strong>
            <small class="text-muted">${escapeHtml(dateText)}</small>
        </div>
        <div class="d-flex justify-content-between align-items-center gap-3">
            <div>
                <small class="text-muted text-uppercase d-block">${escapeHtml(item.file_type || 'unknown')}</small>
                <span class="badge" style="background:${gradeColor}">${escapeHtml(grade)}</span>
            </div>
            <button class="btn btn-sm btn-outline-primary" type="button">
                <i class="fa-solid fa-eye"></i>
                Ver
            </button>
        </div>
    `;

    wrapper.querySelector('button').addEventListener('click', () => loadAndRenderHistoryEntry(item.id));
    return wrapper;
}

async function loadAndRenderHistoryEntry(id) {
    try {
        const modalEl = document.getElementById('historyModal');
        const modalIns = bootstrap.Modal.getInstance(modalEl);
        if (modalIns) modalIns.hide();

        document.getElementById('emptyState').classList.add('d-none');
        document.getElementById('resultsContent').classList.add('d-none');
        document.getElementById('loadingState').classList.remove('d-none');
        document.querySelector('.analyzer-status').innerText = 'Cargando historial';

        const response = await fetch(`/api/history/${id}`, { headers: window.getApiHeaders() });
        const entryData = await response.json();
        if (!response.ok) throw new Error(entryData.error || 'No se pudo cargar el analisis');

        window.currentAnalysisData = [entryData];
        renderResults([entryData]);
    } catch (error) {
        console.error(error);
        window.showToast(`Error: ${error.message}`, 'danger');
        document.getElementById('loadingState').classList.add('d-none');
        document.getElementById('emptyState').classList.remove('d-none');
    }
}
