"""
models/alert.py - Security Alert model
VPN Health and Security Monitor
"""

from database.database import get_db_connection
import logging

logger = logging.getLogger(__name__)


def create_alert(timestamp, severity, alert_type, description,
                 source_ip=None, username=None, server_name=None, details=None):
    """Insert a new security alert into the database."""
    conn = get_db_connection()
    cursor = conn.execute(
        """INSERT INTO alerts
           (timestamp, severity, alert_type, source_ip, username, server_name, description, details, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
        (timestamp, severity, alert_type, source_ip, username, server_name, description, details)
    )
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.info(f"Created alert: [{severity}] {alert_type}")
    return alert_id


def get_all_alerts(severity_filter=None, status_filter=None, page=1, per_page=50):
    """Return paginated alerts with optional severity/status filters."""
    conn = get_db_connection()

    conditions = []
    params = []

    if severity_filter:
        conditions.append("severity = ?")
        params.append(severity_filter)

    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    total = conn.execute(
        f"SELECT COUNT(*) FROM alerts {where_clause}", params
    ).fetchone()[0]

    offset = (page - 1) * per_page
    rows = conn.execute(
        f"SELECT * FROM alerts {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    conn.close()
    return [dict(r) for r in rows], total


def get_alert_by_id(alert_id):
    """Return a single alert by ID."""
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged."""
    conn = get_db_connection()
    conn.execute(
        "UPDATE alerts SET status = 'acknowledged', updated_at = datetime('now') WHERE id = ?",
        (alert_id,)
    )
    conn.commit()
    conn.close()
    logger.info(f"Alert {alert_id} acknowledged.")


def resolve_alert(alert_id):
    """Mark an alert as resolved."""
    conn = get_db_connection()
    conn.execute(
        "UPDATE alerts SET status = 'resolved', updated_at = datetime('now') WHERE id = ?",
        (alert_id,)
    )
    conn.commit()
    conn.close()
    logger.info(f"Alert {alert_id} resolved.")


def get_alert_stats():
    """Return summary counts for dashboard: total, open, by severity."""
    conn = get_db_connection()
    row = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) AS low
        FROM alerts
    """).fetchone()
    conn.close()
    return dict(row) if row else {
        'total': 0, 'open_count': 0,
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0
    }


def get_recent_alerts(limit=5):
    """Return the most recent open/acknowledged alerts."""
    conn = get_db_connection()
    rows = conn.execute(
        """SELECT * FROM alerts WHERE status != 'resolved'
           ORDER BY timestamp DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_all_alerts():
    """Delete all alerts (used before loading demo data)."""
    conn = get_db_connection()
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
