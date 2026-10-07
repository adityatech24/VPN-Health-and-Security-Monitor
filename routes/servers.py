"""
routes/servers.py - VPN Server management routes
VPN Health and Security Monitor
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.vpn_server import get_all_servers, add_server, get_server_by_id, delete_server
from services.health_monitor import run_health_check_for_server, get_health_summary_all

servers_bp = Blueprint('servers', __name__)

VALID_VPN_TYPES = ['OpenVPN', 'WireGuard', 'IPsec', 'L2TP', 'PPTP', 'Other']


@servers_bp.route('/servers')
def servers():
    """Display all VPN servers with health summary."""
    health_summary = get_health_summary_all()
    return render_template('servers.html', servers=health_summary,
                           vpn_types=VALID_VPN_TYPES)


@servers_bp.route('/servers/add', methods=['POST'])
def add_server_route():
    """Handle adding a new VPN server."""
    name = request.form.get('name', '').strip()
    hostname = request.form.get('hostname', '').strip()
    vpn_type = request.form.get('vpn_type', 'OpenVPN').strip()
    location = request.form.get('location', '').strip()
    port_str = request.form.get('port', '1194').strip()

    # Validation
    if not name or not hostname:
        flash('Server name and hostname are required.', 'danger')
        return redirect(url_for('servers.servers'))

    if vpn_type not in VALID_VPN_TYPES:
        flash('Invalid VPN type selected.', 'danger')
        return redirect(url_for('servers.servers'))

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
    except ValueError:
        flash('Port must be a number between 1 and 65535.', 'danger')
        return redirect(url_for('servers.servers'))

    server_id = add_server(name, hostname, vpn_type, location, port)
    # Run initial health check
    run_health_check_for_server(server_id, name)
    flash(f'VPN server "{name}" added successfully.', 'success')
    return redirect(url_for('servers.servers'))


@servers_bp.route('/servers/<int:server_id>/check', methods=['POST'])
def check_server(server_id):
    """Run a health check for a specific server."""
    server = get_server_by_id(server_id)
    if not server:
        flash('Server not found.', 'danger')
        return redirect(url_for('servers.servers'))

    result = run_health_check_for_server(server_id, server['name'])
    if result:
        flash(f'Health check complete for "{server["name"]}": {result["status"].upper()}', 'info')
    return redirect(url_for('servers.servers'))


@servers_bp.route('/servers/<int:server_id>/delete', methods=['POST'])
def delete_server_route(server_id):
    """Delete a VPN server."""
    server = get_server_by_id(server_id)
    if not server:
        flash('Server not found.', 'danger')
        return redirect(url_for('servers.servers'))

    delete_server(server_id)
    flash(f'Server "{server["name"]}" deleted.', 'warning')
    return redirect(url_for('servers.servers'))


@servers_bp.route('/health')
def health():
    """VPN Health monitoring page."""
    health_summary = get_health_summary_all()
    return render_template('health.html', servers=health_summary)
