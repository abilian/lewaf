"""Tests for environment-based configuration profiles."""

from __future__ import annotations

import tempfile
from pathlib import Path

from lewaf.config.profiles import (
    ConfigProfile,
    Environment,
    load_config_with_profile,
    merge_configs,
)


def test_environment_detect_from_env():
    """Test environment detection from ENV variable."""
    import os

    # Save original
    original = os.environ.get("ENV")

    try:
        os.environ["ENV"] = "development"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["ENV"] = "dev"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["ENV"] = "staging"
        assert Environment.detect() == Environment.STAGING

        os.environ["ENV"] = "stage"
        assert Environment.detect() == Environment.STAGING

        os.environ["ENV"] = "production"
        assert Environment.detect() == Environment.PRODUCTION

        os.environ["ENV"] = "prod"
        assert Environment.detect() == Environment.PRODUCTION
    finally:
        if original:
            os.environ["ENV"] = original
        else:
            os.environ.pop("ENV", None)


def test_environment_detect_from_environment():
    """Test environment detection from ENVIRONMENT variable."""
    import os

    original_env = os.environ.get("ENV")
    original_environment = os.environ.get("ENVIRONMENT")

    try:
        # Clear ENV
        os.environ.pop("ENV", None)

        os.environ["ENVIRONMENT"] = "development"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["ENVIRONMENT"] = "staging"
        assert Environment.detect() == Environment.STAGING

        os.environ["ENVIRONMENT"] = "production"
        assert Environment.detect() == Environment.PRODUCTION
    finally:
        if original_env:
            os.environ["ENV"] = original_env
        if original_environment:
            os.environ["ENVIRONMENT"] = original_environment
        else:
            os.environ.pop("ENVIRONMENT", None)


def test_environment_detect_from_debug():
    """Test environment detection from DEBUG flag."""
    import os

    original_env = os.environ.get("ENV")
    original_environment = os.environ.get("ENVIRONMENT")
    original_debug = os.environ.get("DEBUG")

    try:
        # Clear ENV and ENVIRONMENT
        os.environ.pop("ENV", None)
        os.environ.pop("ENVIRONMENT", None)

        os.environ["DEBUG"] = "1"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["DEBUG"] = "true"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["DEBUG"] = "yes"
        assert Environment.detect() == Environment.DEVELOPMENT

        os.environ["DEBUG"] = "0"
        assert Environment.detect() == Environment.PRODUCTION

        os.environ["DEBUG"] = "false"
        assert Environment.detect() == Environment.PRODUCTION
    finally:
        if original_env:
            os.environ["ENV"] = original_env
        if original_environment:
            os.environ["ENVIRONMENT"] = original_environment
        if original_debug:
            os.environ["DEBUG"] = original_debug
        else:
            os.environ.pop("DEBUG", None)


def test_environment_detect_default():
    """Test environment defaults to production."""
    import os

    original_env = os.environ.get("ENV")
    original_environment = os.environ.get("ENVIRONMENT")
    original_debug = os.environ.get("DEBUG")

    try:
        # Clear all environment variables
        os.environ.pop("ENV", None)
        os.environ.pop("ENVIRONMENT", None)
        os.environ.pop("DEBUG", None)

        # Should default to production
        assert Environment.detect() == Environment.PRODUCTION
    finally:
        if original_env:
            os.environ["ENV"] = original_env
        if original_environment:
            os.environ["ENVIRONMENT"] = original_environment
        if original_debug:
            os.environ["DEBUG"] = original_debug


def test_development_profile_defaults():
    """Test development profile has appropriate defaults."""
    defaults = ConfigProfile.get_development_defaults()

    assert defaults["engine"] == "DetectionOnly"
    assert defaults["storage"]["backend"] == "memory"
    assert defaults["audit_logging"]["enabled"] is True
    assert defaults["audit_logging"]["mask_sensitive"] is False  # Dev shows full data
    assert defaults["audit_logging"]["level"] == "DEBUG"
    assert defaults["request_limits"]["body_limit"] == 1048576  # 1 MB


def test_staging_profile_defaults():
    """Test staging profile has appropriate defaults."""
    defaults = ConfigProfile.get_staging_defaults()

    assert defaults["engine"] == "DetectionOnly"
    assert defaults["storage"]["backend"] == "file"
    assert defaults["audit_logging"]["enabled"] is True
    assert defaults["audit_logging"]["mask_sensitive"] is True
    assert defaults["audit_logging"]["level"] == "INFO"
    assert defaults["request_limits"]["body_limit"] == 13107200  # 12.5 MB


def test_production_profile_defaults():
    """Test production profile has appropriate defaults."""
    defaults = ConfigProfile.get_production_defaults()

    assert defaults["engine"] == "On"  # Blocking in production
    assert defaults["storage"]["backend"] == "redis"
    assert defaults["audit_logging"]["enabled"] is True
    assert defaults["audit_logging"]["mask_sensitive"] is True
    assert defaults["audit_logging"]["level"] == "WARNING"
    assert defaults["performance"]["regex_cache_size"] == 512


def test_get_defaults_for_environment():
    """Test getting defaults for specific environment."""
    dev_defaults = ConfigProfile.get_defaults_for_environment(Environment.DEVELOPMENT)
    assert dev_defaults["engine"] == "DetectionOnly"

    staging_defaults = ConfigProfile.get_defaults_for_environment(Environment.STAGING)
    assert staging_defaults["engine"] == "DetectionOnly"
    assert staging_defaults["storage"]["backend"] == "file"

    prod_defaults = ConfigProfile.get_defaults_for_environment(Environment.PRODUCTION)
    assert prod_defaults["engine"] == "On"


def test_merge_configs_simple():
    """Test simple config merging."""
    config1 = {"engine": "On", "rules": []}
    config2 = {"engine": "DetectionOnly"}

    result = merge_configs(config1, config2)

    # config2 should override config1
    assert result["engine"] == "DetectionOnly"
    assert result["rules"] == []


def test_merge_configs_nested():
    """Test nested config merging."""
    config1 = {
        "engine": "On",
        "storage": {
            "backend": "redis",
            "redis_host": "localhost",
            "redis_port": 6379,
        },
    }

    config2 = {
        "storage": {
            "redis_host": "redis-prod",
        },
    }

    result = merge_configs(config1, config2)

    assert result["engine"] == "On"
    assert result["storage"]["backend"] == "redis"
    assert result["storage"]["redis_host"] == "redis-prod"  # Overridden
    assert result["storage"]["redis_port"] == 6379  # Preserved


def test_merge_configs_multiple():
    """Test merging multiple configs with precedence."""
    config1 = {"engine": "Off", "rules": []}
    config2 = {"engine": "DetectionOnly"}
    config3 = {"engine": "On", "rules": ["rule1"]}

    result = merge_configs(config1, config2, config3)

    # Last config wins
    assert result["engine"] == "On"
    assert result["rules"] == ["rule1"]


def test_merge_configs_empty():
    """Test merging with empty configs."""
    config1 = {"engine": "On"}
    config2 = {}
    config3 = None

    result = merge_configs(config1, config2, config3)

    assert result["engine"] == "On"


def test_load_config_with_profile_development():
    """Test loading config with development profile."""
    import os

    original = os.environ.get("ENV")

    try:
        os.environ["ENV"] = "development"

        config = load_config_with_profile()

        assert config.engine == "DetectionOnly"
        assert config.storage.backend == "memory"
        assert config.audit_logging.level == "DEBUG"
        assert config.audit_logging.mask_sensitive is False
    finally:
        if original:
            os.environ["ENV"] = original
        else:
            os.environ.pop("ENV", None)


def test_load_config_with_profile_production():
    """Test loading config with production profile."""
    import os

    original = os.environ.get("ENV")

    try:
        os.environ["ENV"] = "production"

        config = load_config_with_profile()

        assert config.engine == "On"
        assert config.storage.backend == "redis"
        assert config.audit_logging.level == "WARNING"
    finally:
        if original:
            os.environ["ENV"] = original
        else:
            os.environ.pop("ENV", None)


def test_load_config_with_profile_explicit_environment():
    """Test loading config with explicit environment parameter."""
    config = load_config_with_profile(environment=Environment.STAGING)

    assert config.engine == "DetectionOnly"
    assert config.storage.backend == "file"


def test_load_config_with_profile_from_file():
    """Test loading config with profile and file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
engine: "On"
rules:
  - 'SecRule ARGS "@rx test" "id:1,deny"'
""")
        f.flush()
        temp_path = f.name

    try:
        config = load_config_with_profile(
            config_file=temp_path,
            environment=Environment.DEVELOPMENT,
        )

        # File overrides profile
        assert config.engine == "On"  # From file
        assert len(config.rules) == 1  # From file
        # But profile defaults are still used where not specified
        assert config.storage.backend == "memory"  # From dev profile
    finally:
        Path(temp_path).unlink()


def test_load_config_with_profile_with_overrides():
    """Test loading config with overrides."""
    config = load_config_with_profile(
        environment=Environment.DEVELOPMENT,
        overrides={
            "engine": "On",
            "performance": {"regex_cache_size": 1024},
        },
    )

    # Override wins
    assert config.engine == "On"
    assert config.performance.regex_cache_size == 1024

    # Profile defaults still apply where not overridden
    assert config.storage.backend == "memory"


def test_load_config_with_profile_precedence():
    """Test full precedence chain: overrides > file > profile > defaults."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
engine: "DetectionOnly"
storage:
  backend: redis
  redis_host: file-redis
""")
        f.flush()
        temp_path = f.name

    try:
        config = load_config_with_profile(
            config_file=temp_path,
            environment=Environment.PRODUCTION,  # Default: redis_host=localhost
            overrides={
                "storage": {
                    "redis_host": "override-redis",
                },
            },
        )

        # Check precedence
        assert config.engine == "DetectionOnly"  # From file
        assert config.storage.backend == "redis"  # From file
        assert config.storage.redis_host == "override-redis"  # From override
        assert config.storage.redis_port == 6379  # From production profile
    finally:
        Path(temp_path).unlink()


def test_profile_differences():
    """Test that profiles have meaningful differences."""
    dev_config = load_config_with_profile(environment=Environment.DEVELOPMENT)
    staging_config = load_config_with_profile(environment=Environment.STAGING)
    prod_config = load_config_with_profile(environment=Environment.PRODUCTION)

    # Engine modes
    assert dev_config.engine == "DetectionOnly"
    assert staging_config.engine == "DetectionOnly"
    assert prod_config.engine == "On"

    # Storage backends
    assert dev_config.storage.backend == "memory"
    assert staging_config.storage.backend == "file"
    assert prod_config.storage.backend == "redis"

    # Log levels
    assert dev_config.audit_logging.level == "DEBUG"
    assert staging_config.audit_logging.level == "INFO"
    assert prod_config.audit_logging.level == "WARNING"

    # Data masking
    assert dev_config.audit_logging.mask_sensitive is False
    assert staging_config.audit_logging.mask_sensitive is True
    assert prod_config.audit_logging.mask_sensitive is True


def test_merge_configs_deep_nesting():
    """Test merging deeply nested configurations."""
    config1 = {
        "level1": {
            "level2": {
                "level3": {
                    "value": "original",
                    "keep": "preserved",
                },
            },
        },
    }

    config2 = {
        "level1": {
            "level2": {
                "level3": {
                    "value": "overridden",
                },
            },
        },
    }

    result = merge_configs(config1, config2)

    assert result["level1"]["level2"]["level3"]["value"] == "overridden"
    assert result["level1"]["level2"]["level3"]["keep"] == "preserved"
