"""
Production configuration for LeWAF.

This module provides environment-specific configurations.
"""

from __future__ import annotations

import os
from pathlib import Path

# Determine environment
ENV = os.getenv("ENV", "production")

# Base paths
BASE_DIR = Path(__file__).parent.parent.parent
RULES_DIR = BASE_DIR / "rules"
LOGS_DIR = Path("/var/log/lewaf") if ENV == "production" else BASE_DIR / "logs"

# Ensure logs directory exists
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# Base configuration
BASE_CONFIG = {
    "rule_files": [
        str(BASE_DIR / "coraza.conf"),  # Loads all 594 CRS rules
    ],
    "request_body_limit": 13107200,  # 12.5 MB
    "request_body_in_memory_limit": 131072,  # 128 KB
    "response_body_limit": 524288,  # 512 KB
    "regex_cache_size": 256,  # Increased for production
}

# Development configuration
DEVELOPMENT_CONFIG = {
    **BASE_CONFIG,
    "engine": "DetectionOnly",  # Log only, don't block
    "audit_log": str(LOGS_DIR / "audit-dev.log"),
    "debug": True,
    "custom_rules": [
        # More lenient rules for development
        'SecRule ARGS:debug "@streq true" "id:9999,phase:1,pass,msg:\'Debug mode\'"',
    ],
}

# Staging configuration
STAGING_CONFIG = {
    **BASE_CONFIG,
    "engine": "DetectionOnly",  # Still in detection mode
    "audit_log": str(LOGS_DIR / "audit-staging.log"),
    "debug": False,
    "custom_rules": [
        # Staging-specific rules
    ],
}

# Production configuration
PRODUCTION_CONFIG = {
    **BASE_CONFIG,
    "engine": "On",  # Blocking mode
    "audit_log": str(LOGS_DIR / "audit-prod.log"),
    "audit_log_parts": "ABIJDEFHZ",
    "debug": False,
    "custom_rules": [
        # Production-specific rules
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin parameter blocked\'"',
        'SecRule REQUEST_HEADERS:X-Admin "@rx ." "id:9002,phase:1,deny,msg:\'Admin header forbidden\'"',
    ],
}

# Configuration map
CONFIGS = {
    "development": DEVELOPMENT_CONFIG,
    "dev": DEVELOPMENT_CONFIG,
    "staging": STAGING_CONFIG,
    "stage": STAGING_CONFIG,
    "production": PRODUCTION_CONFIG,
    "prod": PRODUCTION_CONFIG,
}

# Get current configuration
WAF_CONFIG = CONFIGS.get(ENV.lower(), PRODUCTION_CONFIG)

# Logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        },
        "detailed": {
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "level": "INFO",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOGS_DIR / "app.log"),
            "formatter": "detailed",
            "maxBytes": 10_000_000,  # 10 MB
            "backupCount": 5,
            "level": "INFO",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["console", "file"],
    },
    "loggers": {
        "lewaf": {
            "level": "DEBUG" if WAF_CONFIG.get("debug") else "INFO",
            "handlers": ["console", "file"],
            "propagate": False,
        },
    },
}


def get_config():
    """Get current WAF configuration."""
    return WAF_CONFIG


def print_config():
    """Print current configuration (for debugging)."""
    print(f"Environment: {ENV}")
    print(f"Engine Mode: {WAF_CONFIG['engine']}")
    print(f"Rule Files: {WAF_CONFIG['rule_files']}")
    print(f"Audit Log: {WAF_CONFIG.get('audit_log', 'Not configured')}")
    print(f"Debug Mode: {WAF_CONFIG.get('debug', False)}")


if __name__ == "__main__":
    print_config()
