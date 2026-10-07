"""
models/vpn_server.py - VPN Server model
VPN Health and Security Monitor
"""

from database.database import get_db_connection
import logging

logger = logging.getLogger(__name__)


def get_all_servers():
    """Return all VPN servers from the database."""
    conn = get_db_connection()
    servers = conn.execute(
        "SELECT * FROM vpn_servers ORDER BY name"
    ).fetchall()
    conn.close()
    return [dict(s) for s in servers]


def get_server_by_id(server_id):
    """Return a single VPN server by ID."""
    conn = get_db_connection()
    server = conn.execute(
        "SELECT * FROM vpn_servers WHERE id = ?", (server_id,)
    ).fetchone()
    conn.close()
    return dict(server) if server else None


def add_server(name, hostname, vpn_type, location, port, status='unknown'):
    """Add a new VPN server to the database."""
    conn = get_db_connection()
    cursor = conn.execute(
        """INSERT INTO vpn_servers (name, hostname, vpn_type, location, port, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (name, hostname, vpn_type, location, port, status)
    )
    server_id = cursor.lastrowid
    conn.commit()
    conn.close()
    logger.info(f"Added VPN server: {name} ({hostname})")
    return server_id


def update_server_status(server_id, status):
    """Update the status of a VPN server."""
    conn = get_db_connection()
    conn.execute(
        "UPDATE vpn_servers SET status = ?, updated_at = datetime('now') WHERE id = ?",
        (status, server_id)
    )
    conn.commit()
    conn.close()


def delete_server(server_id):
    """Delete a VPN server by ID."""
    conn = get_db_connection()
    conn.execute("DELETE FROM vpn_servers WHERE id = ?", (server_id,))
    conn.commit()
    conn.close()
    logger.info(f"Deleted VPN server with ID: {server_id}")


def get_server_stats():
    """Return summary counts: total, online, offline, warning."""
    conn = get_db_connection()
    row = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) AS online,
            SUM(CASE WHEN status = 'offline' THEN 1 ELSE 0 END) AS offline,
            SUM(CASE WHEN status = 'warning' THEN 1 ELSE 0 END) AS warning
        FROM vpn_servers
    """).fetchone()
    conn.close()
    return dict(row) if row else {'total': 0, 'online': 0, 'offline': 0, 'warning': 0}
