"""
app.py - Flask application factory and entry point.
"""
import os
from flask import Flask
from config import config_by_name


def create_app(config_name: str = None) -> Flask:
    """Create and configure the Flask application."""
    if config_name is None:
        config_name = os.environ.get("FLASK_ENV", "default")

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Register Blueprints
    from routes.main import main_bp
    from routes.api import api_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    # Security headers
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    return app


# Application instance (used by Gunicorn and Flask CLI)
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config.get("DEBUG", False))
