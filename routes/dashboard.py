"""
routes/dashboard.py - Dashboard page routes
VPN Health and Security Monitor
"""

from flask import Blueprint, render_template
from models.vpn_server import get_server_stats
from models.vpn_log import get_log_stats, get_logs_last_n_days
from models.alert import get_alert_stats, get_recent_alerts

dashboard_bp = Blueprint('dashboard', __name__)


@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
def dashboard():
    """Render the main dashboard page."""
    server_stats = get_server_stats()
    log_stats = get_log_stats()
    alert_stats = get_alert_stats()
    recent_alerts = get_recent_alerts(limit=5)
    daily_data = get_logs_last_n_days(days=7)

    # Calculate VPN availability (online servers / total * 100)
    total = server_stats.get('total', 0)
    online = server_stats.get('online', 0)
    availability = round((online / total * 100), 1) if total > 0 else 0

    return render_template(
        'dashboard.html',
        server_stats=server_stats,
        log_stats=log_stats,
        alert_stats=alert_stats,
        recent_alerts=recent_alerts,
        daily_data=daily_data,
        availability=availability,
    )
