"""
services/log_parser.py - Parse VPN logs from CSV or JSON files
VPN Health and Security Monitor
"""

import csv
import json
import io
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Required fields that every log entry should have
REQUIRED_FIELDS = ['timestamp', 'username', 'source_ip', 'server_name', 'event_type', 'status']

# Optional fields with default None
OPTIONAL_FIELDS = ['reason', 'location', 'session_id']


def normalize_log_entry(raw):
    """
    Normalize a raw dict (from CSV/JSON) into a clean log dict.
    Returns a dict or None if validation fails.
    """
    # Accept both lower and upper case field names
    entry = {k.lower().strip(): str(v).strip() if v else '' for k, v in raw.items()}

    # Map alternate column names
    aliases = {
        'ip': 'source_ip',
        'src_ip': 'source_ip',
        'server': 'server_name',
        'vpn_server': 'server_name',
        'type': 'event_type',
        'action': 'event_type',
        'user': 'username',
        'time': 'timestamp',
        'datetime': 'timestamp',
        'date': 'timestamp',
        'message': 'reason',
        'msg': 'reason',
        'city': 'location',
        'session': 'session_id',
    }
    for alias, canonical in aliases.items():
        if alias in entry and canonical not in entry:
            entry[canonical] = entry[alias]

    # Validate required fields
    for field in REQUIRED_FIELDS:
        if field not in entry or not entry[field]:
            logger.warning(f"Skipping log entry missing required field '{field}': {raw}")
            return None

    # Validate and normalize timestamp
    timestamp = parse_timestamp(entry['timestamp'])
    if timestamp is None:
        logger.warning(f"Skipping log entry with invalid timestamp: {entry.get('timestamp')}")
        return None

    # Normalize status to uppercase SUCCESS/FAILED/CONNECTED/DISCONNECTED
    status = entry['status'].upper()
    if status not in ('SUCCESS', 'FAILED', 'CONNECTED', 'DISCONNECTED', 'ERROR', 'WARNING'):
        status = entry['status'].upper()  # keep as-is if unknown

    # Normalize event_type to uppercase
    event_type = entry['event_type'].upper()

    return {
        'timestamp': timestamp,
        'username': entry['username'],
        'source_ip': entry['source_ip'],
        'server_name': entry['server_name'],
        'event_type': event_type,
        'status': status,
        'reason': entry.get('reason') or None,
        'location': entry.get('location') or None,
        'session_id': entry.get('session_id') or None,
    }


def parse_timestamp(ts_str):
    """Try to parse a timestamp string into a normalized ISO format string."""
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y/%m/%d %H:%M:%S',
        '%d-%m-%Y %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%f',
    ]
    ts_str = str(ts_str).strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            continue
    return None


def parse_csv(file_content):
    """
    Parse VPN logs from CSV content (bytes or string).
    Returns (list of valid log dicts, list of error messages).
    """
    logs = []
    errors = []

    try:
        if isinstance(file_content, bytes):
            file_content = file_content.decode('utf-8', errors='replace')

        reader = csv.DictReader(io.StringIO(file_content))
        if not reader.fieldnames:
            return [], ["CSV file is empty or has no header row."]

        for row_num, row in enumerate(reader, start=2):  # start=2 because row 1 is header
            entry = normalize_log_entry(dict(row))
            if entry:
                logs.append(entry)
            else:
                errors.append(f"Row {row_num}: Invalid or incomplete data.")

    except Exception as e:
        logger.exception("Error parsing CSV")
        errors.append(f"CSV parsing error: {str(e)}")

    return logs, errors


def parse_json(file_content):
    """
    Parse VPN logs from JSON content (bytes or string).
    Accepts a JSON array of log objects.
    Returns (list of valid log dicts, list of error messages).
    """
    logs = []
    errors = []

    try:
        if isinstance(file_content, bytes):
            file_content = file_content.decode('utf-8', errors='replace')

        data = json.loads(file_content)

        if not isinstance(data, list):
            return [], ["JSON file must contain a list (array) of log objects."]

        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                errors.append(f"Item {idx + 1}: Expected an object, got {type(item).__name__}.")
                continue
            entry = normalize_log_entry(item)
            if entry:
                logs.append(entry)
            else:
                errors.append(f"Item {idx + 1}: Invalid or incomplete data.")

    except json.JSONDecodeError as e:
        errors.append(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        logger.exception("Error parsing JSON")
        errors.append(f"JSON parsing error: {str(e)}")

    return logs, errors
