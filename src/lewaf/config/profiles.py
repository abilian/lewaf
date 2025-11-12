"""Environment-based configuration profiles."""

from __future__ import annotations

import os
from enum import Enum
from typing import Any

from lewaf.config.models import (
    WAFConfig,
)


class Environment(Enum):
    """Environment types."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

    @classmethod
    def detect(cls) -> Environment:
        """Auto-detect environment from environment variables.

        Checks (in order):
        1. ENV variable
        2. ENVIRONMENT variable
        3. DEBUG flag (if True, development)
        4. Defaults to production for safety

        Returns:
            Detected environment
        """
        # Check explicit environment variable
        env_str = os.getenv("ENV") or os.getenv("ENVIRONMENT")
        if env_str:
            env_lower = env_str.lower()
            if env_lower in ["dev", "development"]:
                return cls.DEVELOPMENT
            if env_lower in ["staging", "stage"]:
                return cls.STAGING
            if env_lower in ["prod", "production"]:
                return cls.PRODUCTION

        # Check DEBUG flag
        debug = os.getenv("DEBUG", "").lower() in ["1", "true", "yes"]
        if debug:
            return cls.DEVELOPMENT

        # Default to production for safety
        return cls.PRODUCTION


class ConfigProfile:
    """Configuration profile for different environments."""

    @staticmethod
    def get_development_defaults() -> dict[str, Any]:
        """Get development environment defaults.

        Development profile:
        - DetectionOnly mode (no blocking)
        - Verbose logging
        - Memory storage
        - Lower limits for faster testing
        """
        return {
            "engine": "DetectionOnly",
            "request_limits": {
                "body_limit": 1048576,  # 1 MB
                "header_limit": 4096,
                "request_line_limit": 4096,
            },
            "storage": {
                "backend": "memory",
                "ttl": 300,  # 5 minutes
            },
            "audit_logging": {
                "enabled": True,
                "format": "json",
                "mask_sensitive": False,  # Show full data in dev
                "level": "DEBUG",
            },
            "performance": {
                "regex_cache_size": 128,
                "worker_threads": 1,
            },
        }

    @staticmethod
    def get_staging_defaults() -> dict[str, Any]:
        """Get staging environment defaults.

        Staging profile:
        - DetectionOnly mode (no blocking, but close to production)
        - Production-like settings for testing
        - File or Redis storage
        """
        return {
            "engine": "DetectionOnly",
            "request_limits": {
                "body_limit": 13107200,  # 12.5 MB (production default)
                "header_limit": 8192,
                "request_line_limit": 8192,
            },
            "storage": {
                "backend": "file",
                "file_path": "/tmp/lewaf-staging.db",
                "ttl": 3600,  # 1 hour
            },
            "audit_logging": {
                "enabled": True,
                "format": "json",
                "mask_sensitive": True,
                "level": "INFO",
            },
            "performance": {
                "regex_cache_size": 256,
                "worker_threads": 2,
            },
        }

    @staticmethod
    def get_production_defaults() -> dict[str, Any]:
        """Get production environment defaults.

        Production profile:
        - On mode (blocking)
        - Full security settings
        - Redis storage
        - Optimized performance
        """
        return {
            "engine": "On",
            "request_limits": {
                "body_limit": 13107200,  # 12.5 MB
                "header_limit": 8192,
                "request_line_limit": 8192,
            },
            "storage": {
                "backend": "redis",
                "redis_host": "localhost",
                "redis_port": 6379,
                "redis_db": 0,
                "ttl": 3600,  # 1 hour
            },
            "audit_logging": {
                "enabled": True,
                "format": "json",
                "mask_sensitive": True,
                "level": "WARNING",
            },
            "performance": {
                "regex_cache_size": 512,
                "worker_threads": 4,
            },
        }

    @classmethod
    def get_defaults_for_environment(cls, env: Environment) -> dict[str, Any]:
        """Get default configuration for environment.

        Args:
            env: Environment type

        Returns:
            Default configuration dictionary
        """
        if env == Environment.DEVELOPMENT:
            return cls.get_development_defaults()
        if env == Environment.STAGING:
            return cls.get_staging_defaults()
        return cls.get_production_defaults()


def merge_configs(*configs: dict[str, Any]) -> dict[str, Any]:
    """Merge multiple configuration dictionaries with deep merge.

    Later configs override earlier ones. Supports nested dictionaries.

    Args:
        *configs: Configuration dictionaries to merge

    Returns:
        Merged configuration
    """
    result: dict[str, Any] = {}

    for config in configs:
        if not config:
            continue

        for key, value in config.items():
            if key not in result:
                result[key] = value
            elif isinstance(result[key], dict) and isinstance(value, dict):
                # Deep merge for nested dicts
                result[key] = merge_configs(result[key], value)
            else:
                # Override
                result[key] = value

    return result


def load_config_with_profile(
    config_file: str | None = None,
    environment: Environment | None = None,
    overrides: dict[str, Any] | None = None,
) -> WAFConfig:
    """Load configuration with environment profile support.

    Precedence (highest to lowest):
    1. overrides dict
    2. Environment variables (in config file)
    3. config_file content
    4. Environment profile defaults
    5. WAFConfig defaults

    Args:
        config_file: Optional path to config file
        environment: Environment (auto-detected if None)
        overrides: Optional override dictionary

    Returns:
        WAFConfig instance
    """
    from lewaf.config.loader import ConfigLoader

    # Detect environment if not specified
    if environment is None:
        environment = Environment.detect()

    # Start with environment profile defaults
    profile_defaults = ConfigProfile.get_defaults_for_environment(environment)

    # Load from file if specified
    file_config = {}
    if config_file:
        loader = ConfigLoader()
        waf_config = loader.load_from_file(config_file)
        file_config = waf_config.to_dict()

    # Merge: profile defaults < file config < overrides
    merged = merge_configs(
        profile_defaults,
        file_config,
        overrides or {},
    )

    return WAFConfig.from_dict(merged)
