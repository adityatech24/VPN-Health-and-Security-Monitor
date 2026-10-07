"""
services/health_monitor.py - VPN Server Health Monitoring
VPN Health and Security Monitor

For academic/demo purposes, this module simulates health checks
using randomized results based on server status stored in the database.
It does NOT connect to real external VPN servers.
"""

import logging
import random
from datetime import datetime
from database.database import get_db_connection
from models.vpn_server import update_server_status, get_all_servers
from services.analyzer import detect_server_downtime, detect_repeated_server_failures

logger = logging.getLogger(__name__)


def simulate_health_check(server):
    """
    Simulate a health check for a VPN server.
    In a real application this would do an actual ping/port check.
    For demo: returns 'online' 80% of the time, 'warning' 10%, 'offline' 10%.
    """
    rand = random.random()
    if rand < 0.80:
        status = 'online'
        response_ms = random.randint(10, 150)
        notes = 'Simulated check: server responding normally.'
    elif rand < 0.90:
        status = 'warning'
        response_ms = random.randint(300, 800)
        notes = 'Simulated check: high response time.'
    else:
        status = 'offline'
        response_ms = None
        notes = 'Simulated check: no response.'

    return status, response_ms, notes


def run_health_check_for_server(server_id, server_name, force_status=None):
    """
    Run a health check for a single server and record the result.
    force_status: override the simulated result (used by demo data loader).
    """
    servers = get_all_servers()
    server = next((s for s in servers if s['id'] == server_id), None)

    if not server:
        logger.warning(f"Server ID {server_id} not found.")
        return

    if force_status:
        status = force_status
        response_ms = random.randint(10, 120) if status == 'online' else None
        notes = f"Forced status: {status}"
    else:
        status, response_ms, notes = simulate_health_check(server)

    # Save the health check record
    conn = get_db_connection()
    conn.execute(
        """INSERT INTO health_checks (server_id, server_name, status, response_ms, notes)
           VALUES (?, ?, ?, ?, ?)""",
        (server_id, server_name, status, response_ms, notes)
    )
    conn.commit()
    conn.close()

    # Update the server's current status
    update_server_status(server_id, status)

    # Trigger downtime/repeated failure alerts if needed
    if status == 'offline':
        detect_server_downtime(server_id, server_name)
        # Count recent failures
        failure_count = count_recent_failures(server_id, hours=24)
        detect_repeated_server_failures(server_name, failure_count)

    logger.info(f"Health check for '{server_name}': {status} ({response_ms}ms)")
    return {'status': status, 'response_ms': response_ms, 'notes': notes}


def run_health_checks_all():
    """Run health checks for all servers in the database."""
    servers = get_all_servers()
    results = []
    for server in servers:
        result = run_health_check_for_server(server['id'], server['name'])
        results.append({
            'server': server['name'],
            'result': result
        })
    return results


def count_recent_failures(server_id, hours=24):
    """Count how many offline health checks a server had in the last N hours."""
    conn = get_db_connection()
    row = conn.execute(
        """SELECT COUNT(*) as cnt FROM health_checks
           WHERE server_id = ? AND status = 'offline'
           AND checked_at >= datetime('now', ?)""",
        (server_id, f'-{hours} hours')
    ).fetchone()
    conn.close()
    return row['cnt'] if row else 0


def get_server_availability(server_id, days=7):
    """
    Calculate availability percentage for a server over the last N days.
    Returns a float (0.0 to 100.0).
    """
    conn = get_db_connection()
    row = conn.execute(
        """SELECT
               COUNT(*) as total,
               SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online_count
           FROM health_checks
           WHERE server_id = ?
           AND checked_at >= datetime('now', ?)""",
        (server_id, f'-{days} days')
    ).fetchone()
    conn.close()

    if row and row['total'] > 0:
        return round((row['online_count'] / row['total']) * 100, 1)
    return 100.0  # No checks = assume 100% if just added


def get_health_timeline(server_id, limit=30):
    """Return recent health check records for a server (for chart)."""
    conn = get_db_connection()
    rows = conn.execute(
        """SELECT status, checked_at, response_ms
           FROM health_checks
           WHERE server_id = ?
           ORDER BY checked_at DESC LIMIT ?""",
        (server_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_health_summary_all():
    """
    Return health summary for all servers including availability %.
    """
    servers = get_all_servers()
    summary = []
    conn = get_db_connection()

    for server in servers:
        # Last check info
        last_check = conn.execute(
            """SELECT status, checked_at, response_ms, notes FROM health_checks
               WHERE server_id = ? ORDER BY checked_at DESC LIMIT 1""",
            (server['id'],)
        ).fetchone()

        # Total failures
        failures = conn.execute(
            """SELECT COUNT(*) as cnt FROM health_checks
               WHERE server_id = ? AND status = 'offline'""",
            (server['id'],)
        ).fetchone()

        # Last successful check
        last_success = conn.execute(
            """SELECT checked_at FROM health_checks
               WHERE server_id = ? AND status = 'online'
               ORDER BY checked_at DESC LIMIT 1""",
            (server['id'],)
        ).fetchone()

        availability = get_server_availability(server['id'], days=7)

        summary.append({
            'id': server['id'],
            'name': server['name'],
            'hostname': server['hostname'],
            'vpn_type': server['vpn_type'],
            'location': server['location'],
            'current_status': server['status'],
            'last_checked': last_check['checked_at'] if last_check else None,
            'last_check_status': last_check['status'] if last_check else None,
            'response_ms': last_check['response_ms'] if last_check else None,
            'total_failures': failures['cnt'] if failures else 0,
            'last_success': last_success['checked_at'] if last_success else None,
            'availability_7d': availability,
        })

    conn.close()
    return summary
