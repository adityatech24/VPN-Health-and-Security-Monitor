"""
app.py - Main Flask application entry point
VPN Health and Security Monitor

Run this file to start the application:
    python app.py
Then open: http://127.0.0.1:5000
"""

import logging
import os
from flask import Flask, render_template
from config import config
from database.database import init_db

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(config.LOG_FILE, encoding='utf-8'),
    ]
)
logger = logging.getLogger(__name__)


def create_app():
    """Application factory: create and configure the Flask app."""
    app = Flask(__name__)

    # Load configuration
    app.secret_key = config.SECRET_KEY
    app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

    # Initialize database (creates tables if not present)
    init_db()

    # Register blueprints (page routes)
    from routes.dashboard import dashboard_bp
    from routes.servers import servers_bp
    from routes.logs import logs_bp
    from routes.alerts import alerts_bp
    from routes.settings_route import settings_bp
    from routes.api import api_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(servers_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(api_bp)

    # Custom error pages
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('error.html', code=404,
                               message='Page not found.'), 404

    @app.errorhandler(413)
    def file_too_large(e):
        return render_template('error.html', code=413,
                               message=f'File too large. Maximum size is {config.MAX_UPLOAD_SIZE_MB} MB.'), 413

    @app.errorhandler(500)
    def internal_error(e):
        logger.exception("Internal server error")
        return render_template('error.html', code=500,
                               message='Internal server error.'), 500

    # Template context: app name available in all templates
    @app.context_processor
    def inject_globals():
        return {
            'app_name': config.APP_NAME,
            'app_version': config.APP_VERSION,
        }

    logger.info(f"{config.APP_NAME} v{config.APP_VERSION} initialized.")
    return app


# Entry point
if __name__ == '__main__':
    app = create_app()
    logger.info("Starting VPN Health & Security Monitor on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)
