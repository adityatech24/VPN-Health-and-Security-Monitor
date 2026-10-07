"""
routes/alerts.py - Security Alert management routes
VPN Health and Security Monitor
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from models.alert import (
    get_all_alerts, get_alert_by_id,
    acknowledge_alert, resolve_alert, get_alert_stats
)

alerts_bp = Blueprint('alerts', __name__)

SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low']
STATUS_OPTIONS = ['open', 'acknowledged', 'resolved']

# Recommended actions for each alert type
RECOMMENDED_ACTIONS = {
    'repeated_failed_login': (
        "Review the source IP activity in the logs. "
        "Consider blocking the IP if attempts are unauthorized. "
        "Verify with the user whether they were having login trouble."
    ),
    'multi_username_from_ip': (
        "Investigate the source IP for possible account enumeration. "
        "Check whether all attempted usernames are valid. "
        "Review access control policies."
    ),
    'unusual_login_time': (
        "Contact the user to verify whether the login was authorized. "
        "If unexpected, consider resetting their credentials. "
        "Enable multi-factor authentication if not already active."
    ),
    'server_downtime': (
        "Check the VPN server status and network connectivity. "
        "Restart the VPN service if needed. "
        "Notify affected users of temporary unavailability."
    ),
    'repeated_server_failure': (
        "Investigate the root cause of repeated server failures. "
        "Review server logs for hardware or software issues. "
        "Escalate to the infrastructure team if necessary."
    ),
}


@alerts_bp.route('/alerts')
def alerts():
    """Display all security alerts with filters."""
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('status', '')

    alert_list, total = get_all_alerts(
        severity_filter=severity_filter or None,
        status_filter=status_filter or None,
        page=page,
        per_page=50,
    )
    stats = get_alert_stats()
    total_pages = max(1, (total + 49) // 50)

    return render_template(
        'alerts.html',
        alerts=alert_list,
        stats=stats,
        total=total,
        page=page,
        total_pages=total_pages,
        severity_filter=severity_filter,
        status_filter=status_filter,
        severity_levels=SEVERITY_LEVELS,
        status_options=STATUS_OPTIONS,
    )


@alerts_bp.route('/alerts/<int:alert_id>')
def alert_detail(alert_id):
    """Show full details for a single alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts.alerts'))

    recommended = RECOMMENDED_ACTIONS.get(alert['alert_type'], 'Review the alert and investigate the activity.')
    return render_template('alert_detail.html', alert=alert, recommended=recommended)


@alerts_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge(alert_id):
    """Acknowledge an alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts.alerts'))

    acknowledge_alert(alert_id)
    flash(f'Alert #{alert_id} acknowledged.', 'info')

    # Return to detail page if came from there
    if request.referrer and f'/alerts/{alert_id}' in request.referrer:
        return redirect(url_for('alerts.alert_detail', alert_id=alert_id))
    return redirect(url_for('alerts.alerts'))


@alerts_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def resolve(alert_id):
    """Resolve an alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts.alerts'))

    resolve_alert(alert_id)
    flash(f'Alert #{alert_id} marked as resolved.', 'success')

    if request.referrer and f'/alerts/{alert_id}' in request.referrer:
        return redirect(url_for('alerts.alert_detail', alert_id=alert_id))
    return redirect(url_for('alerts.alerts'))


@alerts_bp.route('/analytics')
def analytics():
    """Analytics page with statistics and charts."""
    from database.database import get_db_connection

    conn = get_db_connection()

    # Most active source IPs
    top_ips = conn.execute("""
        SELECT source_ip, COUNT(*) as count
        FROM vpn_logs
        WHERE source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Most targeted servers
    top_servers = conn.execute("""
        SELECT server_name, COUNT(*) as count
        FROM vpn_logs
        WHERE server_name IS NOT NULL
        GROUP BY server_name
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Failure reasons
    failure_reasons = conn.execute("""
        SELECT reason, COUNT(*) as count
        FROM vpn_logs
        WHERE status = 'FAILED' AND reason IS NOT NULL AND reason != ''
        GROUP BY reason
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    # Alert types breakdown
    alert_types = conn.execute("""
        SELECT alert_type, severity, COUNT(*) as count
        FROM alerts
        GROUP BY alert_type, severity
        ORDER BY count DESC
    """).fetchall()

    # Login stats
    login_stats = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status='SUCCESS' THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) as failed
        FROM vpn_logs
    """).fetchone()

    # Daily login trend (last 14 days)
    daily_trend = conn.execute("""
        SELECT DATE(timestamp) as day,
               SUM(CASE WHEN status='SUCCESS' THEN 1 ELSE 0 END) as success,
               SUM(CASE WHEN status='FAILED' THEN 1 ELSE 0 END) as failed
        FROM vpn_logs
        WHERE timestamp >= datetime('now', '-14 days')
        GROUP BY day
        ORDER BY day
    """).fetchall()

    conn.close()

    return render_template(
        'analytics.html',
        top_ips=[dict(r) for r in top_ips],
        top_servers=[dict(r) for r in top_servers],
        failure_reasons=[dict(r) for r in failure_reasons],
        alert_types=[dict(r) for r in alert_types],
        login_stats=dict(login_stats) if login_stats else {},
        daily_trend=[dict(r) for r in daily_trend],
    )
