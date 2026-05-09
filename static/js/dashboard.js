/**
 * dashboard.js - Handles charts, top-level stats, and history polling.
 */

let severityChartObj = null;

// Global stats
let totalScans = 0;
let totalCritical = 0;
let totalHigh = 0;
let sumScore = 0;
let scoreCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    
    // Load history on modal open
    const historyModal = document.getElementById('historyModal');
    if (historyModal) {
        historyModal.addEventListener('show.bs.tab', loadHistory); // if tabbed
        historyModal.addEventListener('show.bs.modal', loadHistory); // if modal
    }

    const clearBtn = document.getElementById('clearHistoryBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            try {
                await fetch('/api/history', { method: 'DELETE' });
                document.getElementById('historyContainer').innerHTML = '<div class="p-4 text-center text-muted">Historial borrado.</div>';
            } catch (e) {
                console.error(e);
            }
        });
    }
});

function initChart() {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;

    severityChartObj = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Crítico', 'Alto', 'Medio', 'Bajo', 'Info'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#6b7280'],
                borderWidth: 0,
                cutout: '75%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { color: '#94a3b8', boxWidth: 12 } }
            }
        }
    });
}

window.updateCharts = function(summary) {
    // Update Score Circle
    const scoreVal = document.getElementById('scoreValue');
    const badge = document.getElementById('gradeBadge');
    
    scoreVal.innerText = summary.score;
    badge.innerText = `Grado: ${summary.grade}`;
    badge.style.backgroundColor = summary.grade_color;

    let color = summary.grade_color;
    document.getElementById('scoreCircle').style.borderColor = color;
    scoreVal.style.color = color;

    // Update Chart
    if (severityChartObj) {
        const c = summary.counts;
        severityChartObj.data.datasets[0].data = [
            c.critical || 0,
            c.high || 0,
            c.medium || 0,
            c.low || 0,
            c.info || 0
        ];
        severityChartObj.update();
    }
};

window.updateDashboardStats = function(resultsArray) {
    resultsArray.forEach(res => {
        if (!res.error && res.summary) {
            totalScans++;
            totalCritical += res.summary.counts.critical || 0;
            totalHigh += res.summary.counts.high || 0;
            sumScore += res.summary.score || 0;
            scoreCount++;
        }
    });

    document.getElementById('statTotalScans').innerText = totalScans;
    document.getElementById('statCritical').innerText = totalCritical;
    document.getElementById('statHigh').innerText = totalHigh;
    
    if (scoreCount > 0) {
        const avg = Math.round(sumScore / scoreCount);
        document.getElementById('statAvgScore').innerText = avg;
    }
};

async function loadHistory() {
    const container = document.getElementById('historyContainer');
    container.innerHTML = '<div class="p-4 text-center"><i class="fa-solid fa-spinner fa-spin text-cyan"></i> Cargando...</div>';
    
    try {
        const res = await fetch('/api/history');
        if (!res.ok) throw new Error("Failed to load");
        const history = await res.json();
        
        if (history.length === 0) {
            container.innerHTML = '<div class="p-4 text-center text-muted">No hay historial disponible.</div>';
            return;
        }

        let html = '';
        history.forEach(item => {
            const d = new Date(item.timestamp);
            const timeStr = d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            const dateStr = d.toLocaleDateString();
            
            let badge = '';
            if (item.summary) {
                badge = `<span class="badge" style="background:${item.summary.grade_color}">${item.summary.grade} - ${item.summary.score}/100</span>`;
            }

            html += `
                <div class="list-group-item bg-transparent text-light border-secondary">
                    <div class="d-flex w-100 justify-content-between align-items-center mb-1">
                        <h6 class="mb-0 text-truncate" style="max-width: 60%;"><i class="fa-regular fa-file me-2"></i>${item.filename}</h6>
                        <small class="text-muted">${dateStr} ${timeStr}</small>
                    </div>
                    <div class="d-flex justify-content-between align-items-end">
                        <div>
                            <small class="text-muted text-uppercase d-block mb-1">${item.file_type}</small>
                            ${badge}
                        </div>
                        <button class="btn btn-sm btn-outline-cyan view-history-btn" data-id="${item.id}">
                            <i class="fa-solid fa-eye"></i> Ver
                        </button>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;

        // Add event listeners for the "View" buttons
        document.querySelectorAll('.view-history-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const id = e.currentTarget.getAttribute('data-id');
                if (id) await loadAndRenderHistoryEntry(id);
            });
        });

    } catch (e) {
        console.error(e);
        container.innerHTML = '<div class="p-4 text-center text-danger">Error al cargar el historial.</div>';
    }
}

async function loadAndRenderHistoryEntry(id) {
    try {
        // Close modal
        const modalEl = document.getElementById('historyModal');
        const modalIns = bootstrap.Modal.getInstance(modalEl);
        if (modalIns) modalIns.hide();

        // Show loading state on main dashboard
        document.getElementById('emptyState').classList.add('d-none');
        document.getElementById('resultsContent').classList.add('d-none');
        document.getElementById('loadingState').classList.remove('d-none');
        document.querySelector('.analyzer-status').innerText = "Cargando análisis desde historial...";

        // Fetch data
        const res = await fetch(`/api/history/${id}`);
        if (!res.ok) throw new Error("No se pudo cargar el análisis");
        const entryData = await res.json();

        // Pass to analyzer.js rendering pipeline as an array (since it expects multiple files)
        window.currentAnalysisData = [entryData]; // Ensure export works
        
        // Hide loading and use renderResults (assumes renderResults is global)
        if (typeof renderResults === 'function') {
            renderResults([entryData]);
        } else {
            console.error("renderResults function not found in scope");
        }

    } catch (e) {
        console.error(e);
        alert(`Error al cargar el análisis: ${e.message}`);
        
        document.getElementById('loadingState').classList.add('d-none');
        document.getElementById('emptyState').classList.remove('d-none');
    }
}
