"""
routes/settings_route.py - Settings page route
VPN Health and Security Monitor
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for
from database.database import get_setting, set_setting

settings_bp = Blueprint('settings', __name__)

SETTINGS_META = [
    {
        'key': 'failed_login_threshold',
        'label': 'Failed Login Threshold',
        'description': 'Number of failed logins from the same IP within the time window to trigger a HIGH alert.',
        'type': 'number',
        'min': 1,
        'max': 100,
    },
    {
        'key': 'detection_time_window',
        'label': 'Detection Time Window (minutes)',
        'description': 'Time window in minutes used for detecting repeated failures.',
        'type': 'number',
        'min': 1,
        'max': 1440,
    },
    {
        'key': 'normal_login_start',
        'label': 'Normal Login Start Time',
        'description': 'Logins before this time will trigger an unusual-time alert. Format: HH:MM (24-hour).',
        'type': 'time',
    },
    {
        'key': 'normal_login_end',
        'label': 'Normal Login End Time',
        'description': 'Logins after this time will trigger an unusual-time alert. Format: HH:MM (24-hour).',
        'type': 'time',
    },
    {
        'key': 'multi_username_threshold',
        'label': 'Multi-Username Threshold',
        'description': 'Number of different usernames from one IP within the time window to trigger a MEDIUM alert.',
        'type': 'number',
        'min': 2,
        'max': 50,
    },
    {
        'key': 'server_failure_threshold',
        'label': 'Server Failure Threshold',
        'description': 'Number of offline health checks before generating a HIGH repeated-failure alert.',
        'type': 'number',
        'min': 1,
        'max': 50,
    },
]


@settings_bp.route('/settings')
def settings():
    """Display settings page."""
    current = {meta['key']: get_setting(meta['key'], '') for meta in SETTINGS_META}
    return render_template('settings.html', settings_meta=SETTINGS_META, current=current)


@settings_bp.route('/settings', methods=['POST'])
def save_settings():
    """Save updated settings."""
    errors = []

    for meta in SETTINGS_META:
        key = meta['key']
        value = request.form.get(key, '').strip()

        if not value:
            errors.append(f"{meta['label']} cannot be empty.")
            continue

        # Validate numeric fields
        if meta['type'] == 'number':
            try:
                num = int(value)
                min_val = meta.get('min', 1)
                max_val = meta.get('max', 9999)
                if not (min_val <= num <= max_val):
                    errors.append(f"{meta['label']} must be between {min_val} and {max_val}.")
                    continue
            except ValueError:
                errors.append(f"{meta['label']} must be a valid number.")
                continue

        # Validate time fields (HH:MM format)
        if meta['type'] == 'time':
            parts = value.split(':')
            if len(parts) != 2:
                errors.append(f"{meta['label']} must be in HH:MM format.")
                continue
            try:
                h, m = int(parts[0]), int(parts[1])
                if not (0 <= h <= 23 and 0 <= m <= 59):
                    raise ValueError
            except ValueError:
                errors.append(f"{meta['label']} is not a valid time.")
                continue

        set_setting(key, value)

    if errors:
        for err in errors:
            flash(err, 'danger')
    else:
        flash('Settings saved successfully.', 'success')

    return redirect(url_for('settings.settings'))
