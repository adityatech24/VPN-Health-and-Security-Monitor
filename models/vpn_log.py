"""
models/vpn_log.py - VPN Log model
VPN Health and Security Monitor
"""

from database.database import get_db_connection
import logging

logger = logging.getLogger(__name__)


def add_log(timestamp, username, source_ip, server_name,
            event_type, status, reason=None, location=None, session_id=None):
    """Insert a single VPN log entry into the database."""
    conn = get_db_connection()
    cursor = conn.execute(
        """INSERT INTO vpn_logs
           (timestamp, username, source_ip, server_name, event_type, status, reason, location, session_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (timestamp, username, source_ip, server_name,
         event_type, status, reason, location, session_id)
    )
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id


def add_logs_bulk(log_list):
    """Insert multiple log entries at once (faster than one-by-one)."""
    if not log_list:
        return 0
    conn = get_db_connection()
    cursor = conn.executemany(
        """INSERT INTO vpn_logs
           (timestamp, username, source_ip, server_name, event_type, status, reason, location, session_id)
           VALUES (:timestamp, :username, :source_ip, :server_name, :event_type, :status, :reason, :location, :session_id)""",
        log_list
    )
    count = cursor.rowcount  # Total rows inserted by executemany
    conn.commit()
    conn.close()
    logger.info(f"Bulk inserted {count} log entries.")
    return count


def get_logs(page=1, per_page=50, search=None, status_filter=None,
             event_filter=None, server_filter=None):
    """Return paginated VPN logs with optional filters."""
    conn = get_db_connection()

    # Build WHERE clauses dynamically
    conditions = []
    params = []

    if search:
        conditions.append(
            "(username LIKE ? OR source_ip LIKE ? OR server_name LIKE ? OR reason LIKE ?)"
        )
        term = f"%{search}%"
        params.extend([term, term, term, term])

    if status_filter:
        conditions.append("status = ?")
        params.append(status_filter)

    if event_filter:
        conditions.append("event_type = ?")
        params.append(event_filter)

    if server_filter:
        conditions.append("server_name = ?")
        params.append(server_filter)

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Count total matching records
    total = conn.execute(
        f"SELECT COUNT(*) FROM vpn_logs {where_clause}", params
    ).fetchone()[0]

    # Fetch the page
    offset = (page - 1) * per_page
    rows = conn.execute(
        f"SELECT * FROM vpn_logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    conn.close()
    return [dict(r) for r in rows], total


def get_all_logs_for_analysis():
    """Return all logs for security analysis (no pagination)."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM vpn_logs ORDER BY timestamp"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_log_stats():
    """Return summary counts for the dashboard."""
    conn = get_db_connection()
    row = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS successful,
            SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed
        FROM vpn_logs
    """).fetchone()
    conn.close()
    return dict(row) if row else {'total': 0, 'successful': 0, 'failed': 0}


def get_logs_last_n_days(days=7):
    """Return login counts per day for the last N days (for charts)."""
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT
            DATE(timestamp) AS log_date,
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END) AS successful,
            SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed
        FROM vpn_logs
        WHERE timestamp >= datetime('now', ?)
        GROUP BY log_date
        ORDER BY log_date
    """, (f"-{days} days",)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_all_logs():
    """Delete all logs (used before loading demo data)."""
    conn = get_db_connection()
    conn.execute("DELETE FROM vpn_logs")
    conn.commit()
    conn.close()


def get_distinct_servers():
    """Return list of distinct server names from logs."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT DISTINCT server_name FROM vpn_logs WHERE server_name IS NOT NULL ORDER BY server_name"
    ).fetchall()
    conn.close()
    return [r['server_name'] for r in rows]
