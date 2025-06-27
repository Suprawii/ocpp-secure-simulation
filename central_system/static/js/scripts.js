// Improved Socket.IO Dashboard Script for OCPP Security Dashboard

// Initialize Socket.IO connection
const socket = io();

// DOM Elements
const dashboardContent = document.getElementById('dashboard-content');

// Dashboard views
const views = {
    dashboard: `
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="card text-white bg-primary">
                    <div class="card-body">
                        <h5 class="card-title">Connected Charge Points</h5>
                        <h2 id="connected-count" class="card-text">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-white bg-success">
                    <div class="card-body">
                        <h5 class="card-title">Active Sessions</h5>
                        <h2 id="active-sessions" class="card-text">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Security Alerts</h5>
                        <h2 id="security-alerts" class="card-text">0</h2>
                    </div>
                </div>
            </div>
        </div>
        <div class="card mb-4">
            <div class="card-header">
                <h5>Connection Statistics</h5>
            </div>
            <div class="card-body">
                <canvas id="connectionChart" height="100"></canvas>
            </div>
        </div>
    `,
    chargePoints: `
        <div class="card mb-4">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5>Charge Points</h5>
                <button class="btn btn-sm btn-primary" onclick="showAddCPModal()">Add Charge Point</button>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Status</th>
                                <th>Model</th>
                                <th>Last Seen</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody id="charge-points-table">
                            <!-- Will be populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `,
    securityEvents: `
        <div class="card mb-4">
            <div class="card-header">
                <h5>Security Events</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Charge Point</th>
                                <th>Event Type</th>
                                <th>Severity</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody id="security-events-table">
                            <!-- Will be populated dynamically -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    `
};

// Helper: format ISO datetime string as local time
function formatTime(isoString) {
    if (!isoString) return "";
    return new Date(isoString).toLocaleTimeString();
}

// Navigation for dashboard views
function showDashboard() {
    dashboardContent.innerHTML = views.dashboard;
    initConnectionChart();
}
function showChargePoints() {
    dashboardContent.innerHTML = views.chargePoints;
    // Fetch/refresh CP list if needed
    socket.emit('request_charge_points');
}
function showSecurityEvents() {
    dashboardContent.innerHTML = views.securityEvents;
    // Fetch/refresh events if needed
    socket.emit('request_security_events');
}

// Chart
let chart;
function initConnectionChart() {
    const ctx = document.getElementById('connectionChart').getContext('2d');
    chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Connections',
                data: [],
                borderColor: 'rgb(75, 192, 192)',
                tension: 0.1
            }]
        },
        options: {
            responsive: true,
            scales: { y: { beginAtZero: true } }
        }
    });
}

// Update charge points table
function updateChargePointsTable(data) {
    const tbody = document.getElementById('charge-points-table');
    if (!tbody) return;
    tbody.innerHTML = '';
    data.forEach(cp => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${cp.charge_point_id}</td>
            <td class="${cp.status === 'Connected' ? 'status-connected' : 'status-disconnected'}">${cp.status}</td>
            <td>${cp.model || '-'}</td>
            <td>${formatTime(cp.last_activity)}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="disconnectCP('${cp.charge_point_id}')">Disconnect</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

// Add security event to table
function addSecurityEvent(event) {
    const tbody = document.getElementById('security-events-table');
    if (!tbody) return;

    let severityClass = '';
    if (event.severity === 'Critical') severityClass = 'security-critical';
    else if (event.severity === 'High') severityClass = 'security-high';
    else severityClass = 'security-info';

    const row = document.createElement('tr');
    row.className = severityClass;
    row.innerHTML = `
        <td>${formatTime(event.timestamp)}</td>
        <td>${event.charge_point_id || 'System'}</td>
        <td>${event.event_type}</td>
        <td>
            <span class="badge bg-${event.severity === 'Critical' ? 'danger' :
                                   event.severity === 'High' ? 'warning' : 'info'}">
                ${event.severity}
            </span>
        </td>
        <td>${event.details || event.detail || ''}</td>
    `;
    tbody.insertBefore(row, tbody.firstChild);
    if (tbody.children.length > 20) tbody.removeChild(tbody.lastChild);
}

// Example: disconnect charge point action
function disconnectCP(cpId) {
    socket.emit('disconnect_cp', { cp_id: cpId });
}

// Example: add charge point modal
function showAddCPModal() {
    alert('Feature not implemented yet. Add charge point logic goes here.');
}

// Socket.IO event listeners
socket.on('connect', () => {
    console.log('Connected to dashboard server');
});

socket.on('disconnect', () => {
    console.log('Disconnected from dashboard server');
});

socket.on('connection_stats', (data) => {
    if (!chart) return;
    chart.data.labels.push(new Date().toLocaleTimeString());
    chart.data.datasets[0].data.push(data.connections);
    if (chart.data.labels.length > 15) {
        chart.data.labels.shift();
        chart.data.datasets[0].data.shift();
    }
    chart.update();
    const countElem = document.getElementById('connected-count');
    if (countElem) countElem.textContent = data.connections;
});

socket.on('charge_point_update', (data) => {
    if (document.getElementById('charge-points-table')) updateChargePointsTable(data);
    // Update active sessions count
    const activeElem = document.getElementById('active-sessions');
    if (activeElem) activeElem.textContent = data.filter(cp => cp.status === "Connected").length;
});

socket.on('security_event', (event) => {
    if (document.getElementById('security-events-table')) addSecurityEvent(event);
    // Update security alerts counter for critical/high
    if (event.severity === 'Critical' || event.severity === 'High') {
        const alertsElement = document.getElementById('security-alerts');
        if (alertsElement) alertsElement.textContent = parseInt(alertsElement.textContent) + 1;
    }
});

// Navigation - example if you want view switching buttons
// document.getElementById('nav-dashboard').onclick = showDashboard;
// document.getElementById('nav-cps').onclick = showChargePoints;
// document.getElementById('nav-security').onclick = showSecurityEvents;

// Initialize the dashboard when the page loads
document.addEventListener('DOMContentLoaded', showDashboard);