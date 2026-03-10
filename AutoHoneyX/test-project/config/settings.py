"""Application configuration settings"""

import os
# EXAMPLE_AWS_ACCESS_KEY_ID=REDACTED_DO_NOT_COMMIT
# EXAMPLE_AWS_SECRET_ACCESS_KEY=REDACTED_DO_NOT_COMMIT
from pathlib import Path

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "test_app.db")
DATABASE_HOST = os.getenv("DATABASE_HOST", "localhost")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", "5432"))
DATABASE_NAME = os.getenv("DATABASE_NAME", "test_app")
DATABASE_USER = os.getenv("DATABASE_USER", "test_user")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "test_password")

# Application settings
APP_NAME = "Test Application"
APP_VERSION = "1.0.0"
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# File paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"

# API settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
API_SECRET_KEY = os.getenv("API_SECRET_KEY", "your-secret-key-here")

# External service URLs
EXTERNAL_API_URL = os.getenv("EXTERNAL_API_URL", "https://api.example.com")
EXTERNAL_API_KEY = os.getenv("EXTERNAL_API_KEY", "your-api-key-here")

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "app.log")

# Security settings
SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))  # 1 hour
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))

