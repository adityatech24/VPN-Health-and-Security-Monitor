"""
tests/test_analyzer.py - Unit tests for the security analysis engine
VPN Health and Security Monitor

Run with: python -m pytest tests/ -v
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock


# ============================================================
# Tests for log_parser
# ============================================================
class TestLogParser:
    """Test CSV and JSON log parsing."""

    def test_parse_valid_csv(self):
        from services.log_parser import parse_csv
        csv_content = (
            "timestamp,username,source_ip,server_name,event_type,status\n"
            "2026-10-01 09:00:00,user01,192.168.1.10,VPN-Server-01,LOGIN,SUCCESS\n"
        )
        logs, errors = parse_csv(csv_content.encode())
        assert len(logs) == 1
        assert logs[0]['username'] == 'user01'
        assert logs[0]['status'] == 'SUCCESS'
        assert len(errors) == 0

    def test_parse_csv_missing_required_field(self):
        from services.log_parser import parse_csv
        csv_content = (
            "timestamp,username,source_ip\n"
            "2026-10-01 09:00:00,user01,192.168.1.10\n"
        )
        logs, errors = parse_csv(csv_content.encode())
        assert len(logs) == 0  # Missing required fields
        assert len(errors) > 0

    def test_parse_valid_json(self):
        from services.log_parser import parse_json
        json_content = b'[{"timestamp": "2026-10-01 09:00:00", "username": "user01", "source_ip": "192.168.1.10", "server_name": "VPN-Server-01", "event_type": "LOGIN", "status": "SUCCESS"}]'
        logs, errors = parse_json(json_content)
        assert len(logs) == 1
        assert logs[0]['username'] == 'user01'

    def test_parse_invalid_json(self):
        from services.log_parser import parse_json
        logs, errors = parse_json(b'not valid json')
        assert len(logs) == 0
        assert len(errors) > 0

    def test_parse_json_not_list(self):
        from services.log_parser import parse_json
        logs, errors = parse_json(b'{"key": "value"}')
        assert len(logs) == 0
        assert "list" in errors[0].lower()

    def test_parse_empty_csv(self):
        from services.log_parser import parse_csv
        logs, errors = parse_csv(b'')
        assert len(logs) == 0

    def test_invalid_timestamp(self):
        from services.log_parser import parse_csv
        csv_content = (
            "timestamp,username,source_ip,server_name,event_type,status\n"
            "not-a-date,user01,192.168.1.10,VPN-Server-01,LOGIN,SUCCESS\n"
        )
        logs, errors = parse_csv(csv_content.encode())
        assert len(logs) == 0

    def test_parse_timestamp_formats(self):
        from services.log_parser import parse_timestamp
        assert parse_timestamp("2026-10-01 09:00:00") == "2026-10-01 09:00:00"
        assert parse_timestamp("2026-10-01T09:00:00") == "2026-10-01 09:00:00"
        assert parse_timestamp("invalid") is None


# ============================================================
# Tests for analyzer (using in-memory logic, no DB)
# ============================================================
class TestAnalyzer:
    """Test the security detection logic."""

    def test_parse_ts_valid(self):
        from services.analyzer import parse_ts
        ts = parse_ts("2026-10-01 09:00:00")
        assert isinstance(ts, datetime)
        assert ts.hour == 9

    def test_parse_ts_invalid(self):
        from services.analyzer import parse_ts
        assert parse_ts("not-a-date") is None
        assert parse_ts(None) is None

    def test_repeated_failed_login_detection(self):
        """
        Test that 6 failed logins from same IP in 10 min triggers a HIGH alert.
        """
        import sqlite3
        import tempfile

        # Create a temporary database for testing
        db_path = tempfile.mktemp(suffix='.db')
        os.environ['DATABASE_PATH_OVERRIDE'] = db_path

        from database.database import init_db, get_db_connection
        from config import config

        # Temporarily override db path
        original_path = config.DATABASE_PATH
        config.DATABASE_PATH = db_path

        try:
            init_db()

            # Insert 6 failed logins from same IP within 5 minutes
            base_time = datetime(2026, 10, 1, 14, 0, 0)
            logs = []
            for i in range(6):
                ts = (base_time + timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S')
                logs.append({
                    'timestamp': ts,
                    'username': 'admin',
                    'source_ip': '203.0.113.50',
                    'server_name': 'VPN-Server-01',
                    'event_type': 'LOGIN',
                    'status': 'FAILED',
                    'reason': 'Invalid credentials',
                    'location': 'Unknown',
                    'session_id': f'SID-{i}',
                })

            from models.vpn_log import add_logs_bulk
            add_logs_bulk(logs)

            from services.analyzer import detect_repeated_failed_logins, get_thresholds
            thresholds = get_thresholds()
            alerts_created = detect_repeated_failed_logins(logs, thresholds)

            assert alerts_created >= 1

            # Verify alert is in DB
            conn = get_db_connection()
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_type = 'repeated_failed_login'"
            ).fetchone()
            conn.close()
            assert row is not None
            assert row['severity'] == 'high'
            assert row['source_ip'] == '203.0.113.50'

        finally:
            config.DATABASE_PATH = original_path
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_unusual_login_time_detection(self):
        """
        Test that a login at 2 AM triggers an unusual login time alert.
        """
        import tempfile
        db_path = tempfile.mktemp(suffix='.db')
        from config import config
        original_path = config.DATABASE_PATH
        config.DATABASE_PATH = db_path

        try:
            from database.database import init_db, get_db_connection
            init_db()

            # One successful login at 2 AM
            logs = [{
                'timestamp': '2026-10-01 02:15:00',
                'username': 'user01',
                'source_ip': '192.168.1.10',
                'server_name': 'VPN-Server-01',
                'event_type': 'LOGIN',
                'status': 'SUCCESS',
                'reason': None,
                'location': 'Mumbai',
                'session_id': 'SID-99',
            }]

            from services.analyzer import detect_unusual_login_times, get_thresholds
            thresholds = get_thresholds()
            alerts_created = detect_unusual_login_times(logs, thresholds)

            assert alerts_created >= 1

            conn = get_db_connection()
            row = conn.execute(
                "SELECT * FROM alerts WHERE alert_type = 'unusual_login_time'"
            ).fetchone()
            conn.close()
            assert row is not None
            assert row['severity'] == 'medium'

        finally:
            config.DATABASE_PATH = original_path
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_no_alert_for_normal_login(self):
        """
        Test that a normal working-hours login does NOT trigger an unusual-time alert.
        """
        import tempfile
        db_path = tempfile.mktemp(suffix='.db')
        from config import config
        original_path = config.DATABASE_PATH
        config.DATABASE_PATH = db_path

        try:
            from database.database import init_db
            init_db()

            logs = [{
                'timestamp': '2026-10-01 09:30:00',
                'username': 'user01',
                'source_ip': '192.168.1.10',
                'server_name': 'VPN-Server-01',
                'event_type': 'LOGIN',
                'status': 'SUCCESS',
                'reason': None,
                'location': 'Patna',
                'session_id': 'SID-1',
            }]

            from services.analyzer import detect_unusual_login_times, get_thresholds
            thresholds = get_thresholds()
            alerts_created = detect_unusual_login_times(logs, thresholds)
            assert alerts_created == 0

        finally:
            config.DATABASE_PATH = original_path
            if os.path.exists(db_path):
                os.remove(db_path)


# ============================================================
# Tests for database
# ============================================================
class TestDatabase:
    """Test database initialization and settings."""

    def test_init_db_creates_tables(self):
        import tempfile
        from config import config
        original_path = config.DATABASE_PATH
        db_path = tempfile.mktemp(suffix='.db')
        config.DATABASE_PATH = db_path

        try:
            from database.database import init_db, get_db_connection
            init_db()

            conn = get_db_connection()
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = [t['name'] for t in tables]
            conn.close()

            assert 'vpn_servers' in table_names
            assert 'vpn_logs' in table_names
            assert 'alerts' in table_names
            assert 'health_checks' in table_names
            assert 'settings' in table_names

        finally:
            config.DATABASE_PATH = original_path
            if os.path.exists(db_path):
                os.remove(db_path)

    def test_get_set_setting(self):
        import tempfile
        from config import config
        original_path = config.DATABASE_PATH
        db_path = tempfile.mktemp(suffix='.db')
        config.DATABASE_PATH = db_path

        try:
            from database.database import init_db, get_setting, set_setting
            init_db()

            set_setting('test_key', 'test_value')
            val = get_setting('test_key')
            assert val == 'test_value'

            # Default for non-existent key
            assert get_setting('nonexistent', 'default_val') == 'default_val'

        finally:
            config.DATABASE_PATH = original_path
            if os.path.exists(db_path):
                os.remove(db_path)
