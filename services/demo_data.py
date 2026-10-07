"""
services/demo_data.py - Load realistic demo data for presentation
VPN Health and Security Monitor
"""

import logging
import random
from datetime import datetime, timedelta

from database.database import get_db_connection
from models.vpn_server import add_server, get_all_servers
from models.vpn_log import add_logs_bulk, clear_all_logs
from models.alert import clear_all_alerts
from services.analyzer import run_full_analysis
from services.health_monitor import run_health_check_for_server

logger = logging.getLogger(__name__)

# Base timestamp: 7 days ago so data spreads over a week
BASE_TIME = datetime.now() - timedelta(days=7)


def dt(days_offset, hour, minute=0):
    """Helper: create a timestamp string offset from BASE_TIME."""
    return (BASE_TIME + timedelta(days=days_offset, hours=hour, minutes=minute)).strftime('%Y-%m-%d %H:%M:%S')


def load_demo_data():
    """
    Load realistic demo data:
    - 3 VPN servers
    - 80+ log entries covering all scenario types
    - Run analysis to auto-generate alerts
    Returns a summary dict.
    """
    logger.info("Loading demo data...")

    # --- Clear existing data ---
    clear_all_logs()
    clear_all_alerts()
    _clear_health_checks()

    # --- Add/ensure VPN servers ---
    server_ids = _ensure_demo_servers()

    # --- Insert demo logs ---
    logs = _generate_demo_logs()
    inserted = add_logs_bulk(logs)
    logger.info(f"Inserted {inserted} demo log entries.")

    # --- Simulate health checks ---
    _simulate_demo_health_checks(server_ids)

    # --- Run full analysis to generate alerts ---
    analysis = run_full_analysis()

    return {
        'servers': len(server_ids),
        'logs': inserted,
        'alerts': analysis['alerts_created'],
        'message': (
            f"Demo data loaded: {len(server_ids)} servers, {inserted} logs. "
            f"{analysis['alerts_created']} security alerts generated."
        )
    }


def _clear_health_checks():
    """Delete all health check records."""
    conn = get_db_connection()
    conn.execute("DELETE FROM health_checks")
    conn.commit()
    conn.close()


def _ensure_demo_servers():
    """Add demo VPN servers if not already present. Return list of (id, name)."""
    demo_servers = [
        {'name': 'VPN-Server-01', 'hostname': '10.0.1.10', 'vpn_type': 'OpenVPN',
         'location': 'Mumbai, India', 'port': 1194},
        {'name': 'VPN-Server-02', 'hostname': '10.0.1.20', 'vpn_type': 'WireGuard',
         'location': 'Delhi, India', 'port': 51820},
        {'name': 'VPN-Server-03', 'hostname': '10.0.1.30', 'vpn_type': 'IPsec',
         'location': 'Bangalore, India', 'port': 500},
    ]

    existing = {s['name']: s['id'] for s in get_all_servers()}
    server_ids = []

    for s in demo_servers:
        if s['name'] in existing:
            server_ids.append({'id': existing[s['name']], 'name': s['name']})
        else:
            sid = add_server(
                name=s['name'], hostname=s['hostname'],
                vpn_type=s['vpn_type'], location=s['location'],
                port=s['port'], status='online'
            )
            server_ids.append({'id': sid, 'name': s['name']})

    return server_ids


def _simulate_demo_health_checks(server_ids):
    """Insert realistic health check history for demo servers."""
    if not server_ids:
        return

    conn = get_db_connection()
    health_rows = []

    for entry in server_ids:
        sid = entry['id']
        sname = entry['name']
        # 20 health checks over 7 days, mostly online
        for i in range(20):
            check_time = (BASE_TIME + timedelta(hours=i * 8)).strftime('%Y-%m-%d %H:%M:%S')
            # Server-03 goes offline a few times (for demo)
            if sname == 'VPN-Server-03' and i in (5, 10, 15):
                status = 'offline'
                resp = None
            elif sname == 'VPN-Server-02' and i == 12:
                status = 'warning'
                resp = random.randint(300, 600)
            else:
                status = 'online'
                resp = random.randint(8, 120)

            health_rows.append((sid, sname, status, check_time, resp,
                                 f'Simulated check: {status}'))

    conn.executemany(
        """INSERT INTO health_checks (server_id, server_name, status, checked_at, response_ms, notes)
           VALUES (?, ?, ?, ?, ?, ?)""",
        health_rows
    )
    conn.commit()

    # Update current server statuses
    conn.execute("UPDATE vpn_servers SET status='online' WHERE name='VPN-Server-01'")
    conn.execute("UPDATE vpn_servers SET status='online' WHERE name='VPN-Server-02'")
    conn.execute("UPDATE vpn_servers SET status='offline' WHERE name='VPN-Server-03'")
    conn.commit()
    conn.close()

    # Generate downtime alerts for Server-03
    from services.analyzer import detect_server_downtime, detect_repeated_server_failures
    server_03 = next((s for s in get_all_servers() if s['name'] == 'VPN-Server-03'), None)
    if server_03:
        detect_server_downtime(server_03['id'], server_03['name'])
        detect_repeated_server_failures(server_03['name'], 3)


def _generate_demo_logs():
    """
    Generate 85 realistic VPN log entries covering all detection scenarios.
    """
    logs = []

    # Normal working-hour logins (success) - various users
    normal_users = [
        ('user01', '192.168.1.10', 'Patna'),
        ('user02', '192.168.1.11', 'Mumbai'),
        ('user03', '192.168.1.12', 'Delhi'),
        ('user04', '192.168.1.13', 'Kolkata'),
        ('admin01', '192.168.1.1', 'Mumbai'),
    ]
    for day in range(7):
        for user, ip, loc in normal_users:
            # Morning login
            logs.append(_log(dt(day, random.randint(9, 11), random.randint(0, 59)),
                             user, ip, 'VPN-Server-01', 'LOGIN', 'SUCCESS', None, loc))
            # Evening disconnect
            logs.append(_log(dt(day, random.randint(18, 20), random.randint(0, 59)),
                             user, ip, 'VPN-Server-01', 'DISCONNECT', 'SUCCESS', None, loc))

    # --- Scenario A: Repeated failed logins from attacker IP ---
    # 8 failures within 5 minutes from 203.0.113.50
    attack_ip = '203.0.113.50'
    for i in range(8):
        logs.append(_log(dt(3, 14, i),
                         'admin', attack_ip, 'VPN-Server-01',
                         'LOGIN', 'FAILED', 'Invalid credentials', 'Unknown'))

    # More failed attempts from another IP
    attack_ip2 = '198.51.100.77'
    for i in range(6):
        logs.append(_log(dt(5, 16, i * 2),
                         'vpnadmin', attack_ip2, 'VPN-Server-02',
                         'LOGIN', 'FAILED', 'Authentication failure', 'Unknown'))

    # --- Scenario B: Multiple usernames from one IP ---
    # 5 different usernames from 10.10.10.99 within 8 minutes
    probe_ip = '10.10.10.99'
    probe_users = ['admin', 'root', 'vpnuser', 'testuser', 'sysadmin']
    for i, uname in enumerate(probe_users):
        logs.append(_log(dt(4, 10, i + 1),
                         uname, probe_ip, 'VPN-Server-02',
                         'LOGIN', 'FAILED', 'Unknown user', 'Unknown'))

    # --- Scenario C: Unusual login times (outside 08:00-22:00) ---
    # Successful logins at 2 AM and 4 AM
    logs.append(_log(dt(2, 2, 15),
                     'user02', '192.168.1.11', 'VPN-Server-01',
                     'LOGIN', 'SUCCESS', None, 'Mumbai'))
    logs.append(_log(dt(4, 4, 30),
                     'user03', '192.168.1.12', 'VPN-Server-02',
                     'LOGIN', 'SUCCESS', None, 'Delhi'))
    logs.append(_log(dt(6, 23, 45),
                     'admin01', '192.168.1.1', 'VPN-Server-01',
                     'LOGIN', 'SUCCESS', None, 'Mumbai'))

    # --- Server 2 successful connections ---
    for day in range(3, 7):
        logs.append(_log(dt(day, random.randint(9, 17)),
                         'user05', '192.168.1.15', 'VPN-Server-02',
                         'LOGIN', 'SUCCESS', None, 'Chennai'))
        logs.append(_log(dt(day, random.randint(9, 17)),
                         'user06', '192.168.1.16', 'VPN-Server-02',
                         'LOGIN', 'SUCCESS', None, 'Hyderabad'))

    # --- Some failed logins spread over days (legitimate typos) ---
    casual_failed = [
        ('user01', '192.168.1.10', 'Patna', 'VPN-Server-01'),
        ('user04', '192.168.1.13', 'Kolkata', 'VPN-Server-01'),
        ('user02', '192.168.1.11', 'Mumbai', 'VPN-Server-02'),
    ]
    for day in range(7):
        for user, ip, loc, srv in casual_failed:
            if random.random() < 0.3:
                logs.append(_log(dt(day, random.randint(8, 20)),
                                 user, ip, srv, 'LOGIN', 'FAILED',
                                 'Wrong password', loc))

    # --- VPN Server-03 downtime events ---
    # (Health checks handle this, but add matching logs)
    logs.append(_log(dt(2, 12),
                     'user03', '192.168.1.12', 'VPN-Server-03',
                     'CONNECT', 'FAILED', 'Server unreachable', 'Delhi'))
    logs.append(_log(dt(3, 20),
                     'user04', '192.168.1.13', 'VPN-Server-03',
                     'CONNECT', 'FAILED', 'Server unreachable', 'Kolkata'))

    # --- Server 3 occasional success ---
    logs.append(_log(dt(1, 9),
                     'user07', '192.168.1.17', 'VPN-Server-03',
                     'LOGIN', 'SUCCESS', None, 'Bangalore'))
    logs.append(_log(dt(6, 15),
                     'user07', '192.168.1.17', 'VPN-Server-03',
                     'LOGIN', 'SUCCESS', None, 'Bangalore'))

    return logs


def _log(timestamp, username, source_ip, server_name,
          event_type, status, reason=None, location=None):
    """Helper to build a log dict."""
    return {
        'timestamp': timestamp,
        'username': username,
        'source_ip': source_ip,
        'server_name': server_name,
        'event_type': event_type,
        'status': status,
        'reason': reason,
        'location': location,
        'session_id': f"SID-{random.randint(10000, 99999)}",
    }
