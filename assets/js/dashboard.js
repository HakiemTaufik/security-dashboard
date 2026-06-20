/**
 * Security Dashboard - Chart.js initialization
 */

const COLORS = {
    accent:   '#06b6d4',
    accent2:  '#3b82f6',
    success:  '#10b981',
    warning:  '#f59e0b',
    danger:   '#ef4444',
    purple:   '#a855f7',
    pink:     '#ec4899',
    text:     '#9ca3af',
    grid:     'rgba(45, 55, 72, 0.5)',
};

Chart.defaults.color = COLORS.text;
Chart.defaults.borderColor = COLORS.grid;
Chart.defaults.font.family = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

let charts = {};

async function loadData() {
    try {
        const res = await fetch('/api/chart-data.php', { credentials: 'same-origin' });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return await res.json();
    } catch (e) {
        console.error('Chart data fetch failed:', e);
        return null;
    }
}

function destroyChart(key) {
    if (charts[key]) { charts[key].destroy(); charts[key] = null; }
}

function renderTimeline(data) {
    const ctx = document.getElementById('chartTimeline');
    if (!ctx) return;
    destroyChart('timeline');
    charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.timeline.labels,
            datasets: [
                {
                    label: 'Successful',
                    data: data.timeline.success,
                    borderColor: COLORS.success,
                    backgroundColor: COLORS.success + '20',
                    tension: 0.35,
                    fill: true,
                    pointRadius: 3,
                    borderWidth: 2,
                },
                {
                    label: 'Failed',
                    data: data.timeline.failed,
                    borderColor: COLORS.danger,
                    backgroundColor: COLORS.danger + '20',
                    tension: 0.35,
                    fill: true,
                    pointRadius: 3,
                    borderWidth: 2,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'top', align: 'end' },
            },
            scales: {
                x: { grid: { color: COLORS.grid } },
                y: { beginAtZero: true, grid: { color: COLORS.grid }, ticks: { precision: 0 } },
            },
        },
    });
}

function renderEvents(data) {
    const ctx = document.getElementById('chartEvents');
    if (!ctx) return;
    destroyChart('events');
    const colorMap = {
        login_success: COLORS.success,
        login_failed:  COLORS.danger,
        login_locked:  COLORS.warning,
        logout:        COLORS.accent,
        password_reset: COLORS.accent2,
        admin_action:  COLORS.purple,
        session_expired: COLORS.text,
    };
    const labels = data.events.map(e => e.label);
    const values = data.events.map(e => e.value);
    const colors = data.events.map(e => colorMap[e.label] || COLORS.text);

    charts.events = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderColor: '#0b0f17',
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: { position: 'right', labels: { font: { size: 12 } } },
            },
        },
    });
}

function renderIps(data) {
    const ctx = document.getElementById('chartIps');
    if (!ctx) return;
    destroyChart('ips');
    charts.ips = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.ips.map(i => i.label),
            datasets: [{
                label: 'Events',
                data: data.ips.map(i => i.value),
                backgroundColor: COLORS.accent,
                borderColor: COLORS.accent,
                borderWidth: 1,
            }],
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, grid: { color: COLORS.grid }, ticks: { precision: 0 } },
                y: { grid: { display: false } },
            },
        },
    });
}

function renderThreats(data) {
    const ctx = document.getElementById('chartThreats');
    if (!ctx) return;
    destroyChart('threats');
    const palette = {
        brute_force: COLORS.danger,
        rapid_fire: COLORS.warning,
        off_hours: COLORS.accent2,
        insider: COLORS.purple,
        geo_anomaly: COLORS.pink,
    };
    if (!data.threats.length) {
        // Empty-state message
        const c = ctx.getContext('2d');
        ctx.height = 280;
        c.clearRect(0, 0, ctx.width, ctx.height);
        c.fillStyle = COLORS.text;
        c.font = '14px sans-serif';
        c.textAlign = 'center';
        c.fillText('No threats detected in the last 7 days ✓', ctx.width / 2, ctx.height / 2);
        return;
    }
    charts.threats = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.threats.map(t => t.label.replace('_', ' ')),
            datasets: [{
                label: 'Occurrences',
                data: data.threats.map(t => t.value),
                backgroundColor: data.threats.map(t => palette[t.label] || COLORS.text),
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, grid: { color: COLORS.grid }, ticks: { precision: 0 } },
            },
        },
    });
}

async function refresh() {
    const data = await loadData();
    if (!data) return;
    renderTimeline(data);
    renderEvents(data);
    renderIps(data);
    renderThreats(data);
}

document.addEventListener('DOMContentLoaded', () => {
    refresh();
    // Auto-refresh every 30 seconds
    setInterval(refresh, 30000);
});
