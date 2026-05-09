"""
config.py - Application configuration.
Loads settings from environment variables (.env file in development).
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration class."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production-please")
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    TESTING = False

    # Allowed file extensions for upload
    ALLOWED_EXTENSIONS = {
        "dockerfile",
        "yml",
        "yaml",
        "env",
        "txt",
        "cfg",
        "conf",
        "json",
        "toml",
    }

    # Maximum findings to keep in memory history
    HISTORY_MAX_SIZE = int(os.environ.get("HISTORY_MAX_SIZE", 50))


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


config_by_name = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
