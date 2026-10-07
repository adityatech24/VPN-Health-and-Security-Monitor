"""
routes/api.py - REST API endpoints
VPN Health and Security Monitor
"""

from flask import Blueprint, jsonify, request
from models.vpn_server import get_all_servers, add_server, get_server_stats
from models.vpn_log import get_logs, get_log_stats, get_logs_last_n_days
from models.alert import get_all_alerts, get_alert_stats, get_recent_alerts, acknowledge_alert, resolve_alert, get_alert_by_id
from services.health_monitor import get_health_summary_all, run_health_checks_all
from services.analyzer import run_full_analysis
from services.demo_data import load_demo_data
from services.log_parser import parse_csv, parse_json
from models.vpn_log import add_logs_bulk
from database.database import get_setting, set_setting

api_bp = Blueprint('api', __name__, url_prefix='/api')


def success(data=None, message='OK'):
    """Helper: return a success JSON response."""
    resp = {'status': 'success', 'message': message}
    if data is not None:
        resp['data'] = data
    return jsonify(resp)


def error(message, code=400):
    """Helper: return an error JSON response."""
    return jsonify({'status': 'error', 'message': message}), code


# ------------------------------------------------------------------
# GET /api/dashboard
# ------------------------------------------------------------------
@api_bp.route('/dashboard', methods=['GET'])
def api_dashboard():
    """Return all dashboard statistics."""
    server_stats = get_server_stats()
    log_stats = get_log_stats()
    alert_stats = get_alert_stats()
    recent_alerts = get_recent_alerts(limit=5)
    daily_data = get_logs_last_n_days(days=7)

    total = server_stats.get('total', 0)
    online = server_stats.get('online', 0)
    availability = round((online / total * 100), 1) if total > 0 else 0

    return success({
        'servers': server_stats,
        'logs': log_stats,
        'alerts': alert_stats,
        'recent_alerts': recent_alerts,
        'daily_data': daily_data,
        'availability': availability,
    })


# ------------------------------------------------------------------
# GET /api/servers
# POST /api/servers
# ------------------------------------------------------------------
@api_bp.route('/servers', methods=['GET'])
def api_get_servers():
    """Return all VPN servers."""
    return success(get_all_servers())


@api_bp.route('/servers', methods=['POST'])
def api_add_server():
    """Add a new VPN server via JSON API."""
    data = request.get_json(silent=True)
    if not data:
        return error('Request body must be JSON.')

    name = str(data.get('name', '')).strip()
    hostname = str(data.get('hostname', '')).strip()
    vpn_type = str(data.get('vpn_type', 'OpenVPN')).strip()
    location = str(data.get('location', '')).strip()
    port = data.get('port', 1194)

    if not name or not hostname:
        return error('Server name and hostname are required.')

    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return error('Port must be an integer between 1 and 65535.')

    server_id = add_server(name, hostname, vpn_type, location, port)
    return success({'id': server_id}, f'Server "{name}" added.'), 201


# ------------------------------------------------------------------
# GET /api/logs
# ------------------------------------------------------------------
@api_bp.route('/logs', methods=['GET'])
def api_get_logs():
    """Return paginated logs."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)
    search = request.args.get('search')
    status_filter = request.args.get('status')
    event_filter = request.args.get('event')
    server_filter = request.args.get('server')

    log_list, total = get_logs(
        page=page, per_page=per_page,
        search=search, status_filter=status_filter,
        event_filter=event_filter, server_filter=server_filter,
    )
    return success({
        'logs': log_list,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': max(1, (total + per_page - 1) // per_page),
    })


# ------------------------------------------------------------------
# POST /api/logs/upload
# ------------------------------------------------------------------
@api_bp.route('/logs/upload', methods=['POST'])
def api_upload_logs():
    """Upload logs via file (CSV or JSON)."""
    if 'logfile' not in request.files:
        return error('No file provided. Use field name "logfile".')

    file = request.files['logfile']
    if not file.filename:
        return error('Empty filename.')

    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ('csv', 'json'):
        return error('Only CSV and JSON files are supported.')

    content = file.read()
    if not content:
        return error('File is empty.')

    if ext == 'csv':
        parsed, errors = parse_csv(content)
    else:
        parsed, errors = parse_json(content)

    if not parsed:
        return error(f'No valid entries found. {errors[0] if errors else ""}')

    count = add_logs_bulk(parsed)
    return success({
        'imported': count,
        'errors': len(errors),
        'error_samples': errors[:3],
    }, f'{count} log entries imported.')


# ------------------------------------------------------------------
# GET /api/alerts
# ------------------------------------------------------------------
@api_bp.route('/alerts', methods=['GET'])
def api_get_alerts():
    """Return paginated alerts."""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity')
    status = request.args.get('status')
    alert_list, total = get_all_alerts(
        severity_filter=severity, status_filter=status, page=page, per_page=50
    )
    return success({'alerts': alert_list, 'total': total, 'page': page})


# ------------------------------------------------------------------
# POST /api/alerts/<id>/acknowledge
# POST /api/alerts/<id>/resolve
# ------------------------------------------------------------------
@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def api_acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    if not get_alert_by_id(alert_id):
        return error(f'Alert {alert_id} not found.', 404)
    acknowledge_alert(alert_id)
    return success(message=f'Alert {alert_id} acknowledged.')


@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert(alert_id):
    """Resolve an alert."""
    if not get_alert_by_id(alert_id):
        return error(f'Alert {alert_id} not found.', 404)
    resolve_alert(alert_id)
    return success(message=f'Alert {alert_id} resolved.')


# ------------------------------------------------------------------
# GET /api/health
# POST /api/health/check-all
# ------------------------------------------------------------------
@api_bp.route('/health', methods=['GET'])
def api_health():
    """Return health summary for all servers."""
    return success(get_health_summary_all())


@api_bp.route('/health/check-all', methods=['POST'])
def api_check_all():
    """Run health checks for all servers."""
    results = run_health_checks_all()
    return success(results, 'Health checks completed.')


# ------------------------------------------------------------------
# POST /api/analyze
# ------------------------------------------------------------------
@api_bp.route('/analyze', methods=['POST'])
def api_analyze():
    """Run security analysis on all logs."""
    result = run_full_analysis()
    return success(result)


# ------------------------------------------------------------------
# POST /api/demo/load
# ------------------------------------------------------------------
@api_bp.route('/demo/load', methods=['POST'])
def api_load_demo():
    """Load demo data and run analysis."""
    result = load_demo_data()
    return success(result)


# ------------------------------------------------------------------
# GET /api/settings
# POST /api/settings
# ------------------------------------------------------------------
@api_bp.route('/settings', methods=['GET'])
def api_get_settings():
    """Return current settings."""
    keys = [
        'failed_login_threshold', 'detection_time_window',
        'normal_login_start', 'normal_login_end',
        'multi_username_threshold', 'server_failure_threshold',
    ]
    settings = {k: get_setting(k) for k in keys}
    return success(settings)


@api_bp.route('/settings', methods=['POST'])
def api_update_settings():
    """Update settings."""
    data = request.get_json(silent=True)
    if not data:
        return error('Request body must be JSON.')

    allowed_keys = {
        'failed_login_threshold', 'detection_time_window',
        'normal_login_start', 'normal_login_end',
        'multi_username_threshold', 'server_failure_threshold',
    }
    updated = []
    for key, value in data.items():
        if key in allowed_keys:
            set_setting(key, value)
            updated.append(key)

    return success({'updated': updated})
