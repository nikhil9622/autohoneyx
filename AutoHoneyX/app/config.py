"""Configuration management for AutoHoneyX"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Base configuration"""
    
    # Database - Default to SQLite for development, fall back to PostgreSQL for production
    ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
    
    if os.getenv("DATABASE_URL"):
        DATABASE_URL = os.getenv("DATABASE_URL")
    elif ENVIRONMENT == "production":
        # Production: PostgreSQL
        DATABASE_URL = f"postgresql://{os.getenv('DB_USER', 'autohoneyx')}:{os.getenv('DB_PASSWORD', 'password')}@{os.getenv('DB_HOST', 'localhost')}:{os.getenv('DB_PORT', '5432')}/{os.getenv('DB_NAME', 'autohoneyx_db')}"
    else:
        # Development: SQLite (no external dependencies)
        DATABASE_URL = f"sqlite:///{BASE_DIR}/autohoneyx_dev.db"
    
    # Application
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-production")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    # Email Alerts
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    ALERT_EMAIL = os.getenv("ALERT_EMAIL", "")
    
    # Slack
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    
    # Honeypot Ports
    SSH_HONEYPOT_PORT = int(os.getenv("SSH_HONEYPOT_PORT", "2222"))
    WEB_HONEYPOT_PORT = int(os.getenv("WEB_HONEYPOT_PORT", "8080"))
    DB_HONEYPOT_PORT = int(os.getenv("DB_HONEYPOT_PORT", "3307"))
    
    # AWS
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    
    # Dashboard
    DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "8501"))
    DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
    
    # Paths
    LOGS_DIR = BASE_DIR / "logs"
    HONEYPOT_DATA_DIR = BASE_DIR / "honeypot_data"
    
    @staticmethod
    def init_app(app):
        """Initialize application with config"""
        # Create necessary directories
        Config.LOGS_DIR.mkdir(exist_ok=True)
        Config.HONEYPOT_DATA_DIR.mkdir(exist_ok=True)

config = Config()

