"""
config.py - Application Configuration
VPN Health and Security Monitor
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    """Application configuration settings."""

    # Flask secret key - used for session security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'vpn-monitor-dev-secret-key-2024')

    # Database path
    DATABASE_PATH = os.environ.get('DATABASE_PATH', 'vpn_monitor.db')

    # File upload settings
    MAX_UPLOAD_SIZE_MB = 16
    MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE_MB * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'csv', 'json'}

    # Security analysis thresholds (defaults - can be changed in Settings)
    FAILED_LOGIN_THRESHOLD = int(os.environ.get('FAILED_LOGIN_THRESHOLD', 5))
    DETECTION_TIME_WINDOW_MINUTES = int(os.environ.get('DETECTION_TIME_WINDOW_MINUTES', 10))
    NORMAL_LOGIN_START = os.environ.get('NORMAL_LOGIN_START', '08:00')
    NORMAL_LOGIN_END = os.environ.get('NORMAL_LOGIN_END', '22:00')

    # Multi-username detection: max different usernames from one IP in time window
    MULTI_USERNAME_THRESHOLD = int(os.environ.get('MULTI_USERNAME_THRESHOLD', 3))

    # Server failure threshold: how many times before HIGH alert
    SERVER_FAILURE_THRESHOLD = int(os.environ.get('SERVER_FAILURE_THRESHOLD', 3))

    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'vpn_monitor.log')

    # Application info
    APP_NAME = 'VPN Health & Security Monitor'
    APP_VERSION = '1.0.0'
    APP_AUTHOR = 'ICT Academy Project'


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False


# Use development config by default
config = DevelopmentConfig()
