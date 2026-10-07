/**
 * dashboard.js - Client-side helpers
 * VPN Health & Security Monitor
 */

// Auto-refresh dashboard stats every 60 seconds (if on dashboard page)
if (window.location.pathname === '/' || window.location.pathname === '/dashboard') {
    setInterval(function () {
        fetch('/api/dashboard')
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.status !== 'success') return;
                var d = data.data;
                // Update stat counters silently
                var el;
                el = document.getElementById('stat-total-servers');
                if (el && d.servers) el.textContent = d.servers.total;
                el = document.getElementById('stat-online');
                if (el && d.servers) el.textContent = d.servers.online;
                el = document.getElementById('stat-offline');
                if (el && d.servers) el.textContent = d.servers.offline;
                el = document.getElementById('stat-total-logins');
                if (el && d.logs) el.textContent = d.logs.total;
            })
            .catch(function () {
                // Silent fail - don't alert on auto-refresh errors
            });
    }, 60000);
}
