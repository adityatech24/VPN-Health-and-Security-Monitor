"""
routes/logs.py - VPN Log management and upload routes
VPN Health and Security Monitor
"""

import os
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from models.vpn_log import get_logs, add_logs_bulk, get_distinct_servers
from services.log_parser import parse_csv, parse_json

logs_bp = Blueprint('logs', __name__)

ALLOWED_EXTENSIONS = {'csv', 'json'}


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@logs_bp.route('/logs')
def logs():
    """Display VPN logs with search, filter, pagination."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    status_filter = request.args.get('status', '')
    event_filter = request.args.get('event', '')
    server_filter = request.args.get('server', '')

    per_page = 50
    log_list, total = get_logs(
        page=page,
        per_page=per_page,
        search=search or None,
        status_filter=status_filter or None,
        event_filter=event_filter or None,
        server_filter=server_filter or None,
    )

    total_pages = max(1, (total + per_page - 1) // per_page)
    server_names = get_distinct_servers()

    return render_template(
        'logs.html',
        logs=log_list,
        total=total,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        search=search,
        status_filter=status_filter,
        event_filter=event_filter,
        server_filter=server_filter,
        server_names=server_names,
    )


@logs_bp.route('/logs/upload', methods=['POST'])
def upload_logs():
    """Handle CSV or JSON log file upload."""
    if 'logfile' not in request.files:
        flash('No file selected.', 'danger')
        return redirect(url_for('logs.logs'))

    file = request.files['logfile']

    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('logs.logs'))

    if not allowed_file(file.filename):
        flash('Only CSV and JSON files are allowed.', 'danger')
        return redirect(url_for('logs.logs'))

    # Read file content (size checked by Flask MAX_CONTENT_LENGTH)
    content = file.read()

    if not content:
        flash('Uploaded file is empty.', 'danger')
        return redirect(url_for('logs.logs'))

    ext = file.filename.rsplit('.', 1)[1].lower()

    if ext == 'csv':
        parsed_logs, errors = parse_csv(content)
    else:
        parsed_logs, errors = parse_json(content)

    if not parsed_logs and errors:
        flash(f'Could not parse file: {errors[0]}', 'danger')
        return redirect(url_for('logs.logs'))

    if parsed_logs:
        count = add_logs_bulk(parsed_logs)
        msg = f'Successfully imported {count} log entries.'
        if errors:
            msg += f' ({len(errors)} rows skipped due to errors.)'
        flash(msg, 'success')
    else:
        flash('No valid log entries found in the file.', 'warning')

    return redirect(url_for('logs.logs'))
