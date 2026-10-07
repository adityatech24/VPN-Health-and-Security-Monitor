"""
services/analyzer.py - Security Analysis Engine
VPN Health and Security Monitor

Analyzes VPN log data to detect:
  A) Repeated failed login attempts from the same IP
  B) Multiple usernames from one IP (account enumeration)
  C) Logins outside normal working hours
  D) VPN server downtime
  E) Repeated server failures
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict

from database.database import get_db_connection, get_setting
from models.alert import create_alert, get_all_alerts
from models.vpn_log import get_all_logs_for_analysis

logger = logging.getLogger(__name__)


def get_thresholds():
    """Load analysis thresholds from the database settings."""
    return {
        'failed_threshold': int(get_setting('failed_login_threshold', 5)),
        'time_window': int(get_setting('detection_time_window', 10)),
        'login_start': get_setting('normal_login_start', '08:00'),
        'login_end': get_setting('normal_login_end', '22:00'),
        'multi_username': int(get_setting('multi_username_threshold', 3)),
        'server_fail_threshold': int(get_setting('server_failure_threshold', 3)),
    }


def run_full_analysis():
    """
    Run all detection rules on all logs in the database.
    Returns a summary dict with counts of alerts created.
    """
    logger.info("Starting full security analysis...")
    logs = get_all_logs_for_analysis()

    if not logs:
        logger.info("No logs to analyze.")
        return {'alerts_created': 0, 'message': 'No logs found to analyze.'}

    thresholds = get_thresholds()
    total_created = 0

    total_created += detect_repeated_failed_logins(logs, thresholds)
    total_created += detect_multi_username_from_ip(logs, thresholds)
    total_created += detect_unusual_login_times(logs, thresholds)

    logger.info(f"Analysis complete. {total_created} new alert(s) created.")
    return {'alerts_created': total_created, 'message': f'{total_created} new alert(s) generated.'}


def detect_repeated_failed_logins(logs, thresholds):
    """
    Detection Rule A:
    If an IP has more than N failed logins within M minutes -> HIGH alert.
    """
    failed_threshold = thresholds['failed_threshold']
    window_minutes = thresholds['time_window']
    alerts_created = 0

    # Group failed logs by source IP
    failed_by_ip = defaultdict(list)
    for log in logs:
        if log.get('status', '').upper() == 'FAILED':
            ts = parse_ts(log['timestamp'])
            if ts:
                failed_by_ip[log['source_ip']].append({
                    'ts': ts,
                    'username': log.get('username'),
                    'server': log.get('server_name'),
                    'log_time': log['timestamp'],
                })

    window = timedelta(minutes=window_minutes)

    for ip, attempts in failed_by_ip.items():
        # Sort by time
        attempts.sort(key=lambda x: x['ts'])
        # Sliding window count
        for i, attempt in enumerate(attempts):
            window_attempts = [
                a for a in attempts
                if attempt['ts'] <= a['ts'] <= attempt['ts'] + window
            ]
            if len(window_attempts) >= failed_threshold:
                # Check if alert already exists for this IP in this window
                if not alert_exists('repeated_failed_login', ip, attempt['log_time']):
                    usernames = list({a['username'] for a in window_attempts if a['username']})
                    servers = list({a['server'] for a in window_attempts if a['server']})
                    details = (
                        f"Failed Attempts: {len(window_attempts)} | "
                        f"Time Window: {window_minutes} min | "
                        f"Usernames: {', '.join(usernames)} | "
                        f"Servers: {', '.join(servers)}"
                    )
                    create_alert(
                        timestamp=attempt['log_time'],
                        severity='high',
                        alert_type='repeated_failed_login',
                        source_ip=ip,
                        username=usernames[0] if usernames else None,
                        server_name=servers[0] if servers else None,
                        description=(
                            f"Multiple failed VPN login attempts detected from {ip}. "
                            f"{len(window_attempts)} failures within {window_minutes} minutes."
                        ),
                        details=details
                    )
                    alerts_created += 1
                break  # One alert per IP is enough per analysis run

    return alerts_created


def detect_multi_username_from_ip(logs, thresholds):
    """
    Detection Rule B:
    If the same IP tries multiple different usernames within time window -> MEDIUM alert.
    """
    window_minutes = thresholds['time_window']
    multi_threshold = thresholds['multi_username']
    alerts_created = 0

    # Collect all logs (not just failed) grouped by IP
    by_ip = defaultdict(list)
    for log in logs:
        ts = parse_ts(log['timestamp'])
        if ts and log.get('source_ip'):
            by_ip[log['source_ip']].append({
                'ts': ts,
                'username': log.get('username', ''),
                'server': log.get('server_name'),
                'log_time': log['timestamp'],
            })

    window = timedelta(minutes=window_minutes)

    for ip, events in by_ip.items():
        events.sort(key=lambda x: x['ts'])
        for i, event in enumerate(events):
            window_events = [
                e for e in events
                if event['ts'] <= e['ts'] <= event['ts'] + window
            ]
            unique_usernames = {e['username'] for e in window_events if e['username']}
            if len(unique_usernames) >= multi_threshold:
                if not alert_exists('multi_username_from_ip', ip, event['log_time']):
                    servers = list({e['server'] for e in window_events if e['server']})
                    details = (
                        f"Unique Usernames: {len(unique_usernames)} | "
                        f"Time Window: {window_minutes} min | "
                        f"Usernames: {', '.join(list(unique_usernames)[:10])} | "
                        f"Servers: {', '.join(servers)}"
                    )
                    create_alert(
                        timestamp=event['log_time'],
                        severity='medium',
                        alert_type='multi_username_from_ip',
                        source_ip=ip,
                        username=None,
                        server_name=servers[0] if servers else None,
                        description=(
                            f"Multiple account login attempts detected from {ip}. "
                            f"{len(unique_usernames)} different usernames tried within {window_minutes} minutes."
                        ),
                        details=details
                    )
                    alerts_created += 1
                break

    return alerts_created


def detect_unusual_login_times(logs, thresholds):
    """
    Detection Rule C:
    Login events outside configured normal hours -> MEDIUM alert.
    """
    login_start = thresholds['login_start']  # e.g. "08:00"
    login_end = thresholds['login_end']      # e.g. "22:00"
    alerts_created = 0

    try:
        start_h, start_m = [int(x) for x in login_start.split(':')]
        end_h, end_m = [int(x) for x in login_end.split(':')]
    except ValueError:
        logger.error("Invalid login time format in settings.")
        return 0

    start_time = timedelta(hours=start_h, minutes=start_m)
    end_time = timedelta(hours=end_h, minutes=end_m)

    # Track (ip, username, date) tuples already alerted this run to avoid duplicates
    seen_combos = set()

    for log in logs:
        if log.get('event_type', '').upper() not in ('LOGIN', 'CONNECT', 'AUTH'):
            continue
        if log.get('status', '').upper() != 'SUCCESS':
            continue  # Only flag successful unusual logins

        ts = parse_ts(log['timestamp'])
        if not ts:
            continue

        login_tod = timedelta(hours=ts.hour, minutes=ts.minute)
        if login_tod < start_time or login_tod > end_time:
            # Deduplicate: one alert per (source_ip, username, date)
            dedup_key = (
                log.get('source_ip', ''),
                log.get('username', ''),
                ts.strftime('%Y-%m-%d'),
            )
            if dedup_key in seen_combos:
                continue
            if not alert_exists('unusual_login_time', log.get('source_ip'), log['timestamp'],
                                check_recent_minutes=1440):  # 24h window per IP
                seen_combos.add(dedup_key)
                create_alert(
                    timestamp=log['timestamp'],
                    severity='medium',
                    alert_type='unusual_login_time',
                    source_ip=log.get('source_ip'),
                    username=log.get('username'),
                    server_name=log.get('server_name'),
                    description=(
                        f"VPN login detected outside normal working hours "
                        f"({login_start} - {login_end}) by {log.get('username')} "
                        f"from {log.get('source_ip')} at {ts.strftime('%H:%M')}."
                    ),
                    details=(
                        f"Login Time: {log['timestamp']} | "
                        f"Normal Hours: {login_start} to {login_end} | "
                        f"Location: {log.get('location', 'Unknown')}"
                    )
                )
                alerts_created += 1

    return alerts_created


def detect_server_downtime(server_id, server_name):
    """
    Detection Rule D:
    Called when a health check marks a server offline -> LOW alert.
    """
    if not alert_exists('server_downtime', None, None, server_name=server_name, check_recent_minutes=30):
        create_alert(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            severity='low',
            alert_type='server_downtime',
            source_ip=None,
            username=None,
            server_name=server_name,
            description=f"VPN server '{server_name}' is currently unavailable.",
            details=f"Server ID: {server_id} | Detected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        logger.info(f"Server downtime alert created for: {server_name}")


def detect_repeated_server_failures(server_name, failure_count):
    """
    Detection Rule E:
    If server has failed N+ times -> HIGH alert.
    """
    threshold = int(get_setting('server_failure_threshold', 3))
    if failure_count >= threshold:
        if not alert_exists('repeated_server_failure', None, None, server_name=server_name, check_recent_minutes=60):
            create_alert(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                severity='high',
                alert_type='repeated_server_failure',
                source_ip=None,
                username=None,
                server_name=server_name,
                description=(
                    f"VPN server '{server_name}' has been unavailable "
                    f"{failure_count} times recently."
                ),
                details=f"Failure Count: {failure_count} | Threshold: {threshold}"
            )
            logger.info(f"Repeated server failure alert for: {server_name}")


def alert_exists(alert_type, source_ip, timestamp_str,
                 server_name=None, check_recent_minutes=60):
    """
    Check if a similar alert already exists recently to avoid duplicates.
    Looks back `check_recent_minutes` minutes from the given timestamp.
    """
    conn = get_db_connection()
    try:
        if timestamp_str:
            ref_time = parse_ts(timestamp_str)
        else:
            ref_time = datetime.now()

        if ref_time is None:
            ref_time = datetime.now()

        cutoff = (ref_time - timedelta(minutes=check_recent_minutes)).strftime('%Y-%m-%d %H:%M:%S')

        if source_ip:
            row = conn.execute(
                """SELECT id FROM alerts
                   WHERE alert_type = ? AND source_ip = ? AND timestamp >= ?""",
                (alert_type, source_ip, cutoff)
            ).fetchone()
        elif server_name:
            row = conn.execute(
                """SELECT id FROM alerts
                   WHERE alert_type = ? AND server_name = ? AND timestamp >= ?""",
                (alert_type, server_name, cutoff)
            ).fetchone()
        else:
            row = None

        return row is not None
    finally:
        conn.close()


def parse_ts(ts_str):
    """Parse timestamp string to datetime object."""
    if not ts_str:
        return None
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M',
    ]
    for fmt in formats:
        try:
            return datetime.strptime(str(ts_str).strip(), fmt)
        except ValueError:
            continue
    return None
