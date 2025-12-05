"""Tests for configuration loader."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import yaml

from lewaf.config.loader import ConfigLoader, load_config
from lewaf.config.models import WAFConfig


def test_config_loader_initialization():
    """Test ConfigLoader initialization."""
    loader = ConfigLoader()
    assert loader.env_vars is not None


def test_config_loader_with_custom_env():
    """Test ConfigLoader with custom environment variables."""
    env_vars = {"TEST_VAR": "test_value"}
    loader = ConfigLoader(env_vars=env_vars)
    assert loader.env_vars == env_vars


def test_substitute_env_vars_with_defaults():
    """Test environment variable substitution with default values."""
    loader = ConfigLoader(env_vars={})

    # Variable with default
    result = loader._substitute_env_vars("value: ${MISSING_VAR:-default_value}")
    assert result == "value: default_value"

    # Multiple variables with defaults
    result = loader._substitute_env_vars(
        "host: ${HOST:-localhost}, port: ${PORT:-8080}"
    )
    assert result == "host: localhost, port: 8080"


def test_substitute_env_vars_from_environment():
    """Test environment variable substitution from actual environment."""
    env_vars = {"MY_VAR": "my_value", "ANOTHER_VAR": "another_value"}
    loader = ConfigLoader(env_vars=env_vars)

    result = loader._substitute_env_vars("value: ${MY_VAR}")
    assert result == "value: my_value"

    result = loader._substitute_env_vars("${MY_VAR}-${ANOTHER_VAR}")
    assert result == "my_value-another_value"


def test_substitute_env_vars_override_default():
    """Test that environment variable overrides default value."""
    env_vars = {"MY_VAR": "actual_value"}
    loader = ConfigLoader(env_vars=env_vars)

    result = loader._substitute_env_vars("value: ${MY_VAR:-default_value}")
    assert result == "value: actual_value"


def test_substitute_env_vars_missing_required():
    """Test that missing required variable raises error."""
    loader = ConfigLoader(env_vars={})

    with pytest.raises(
        ValueError, match="Required environment variable not set: REQUIRED_VAR"
    ):
        loader._substitute_env_vars("value: ${REQUIRED_VAR}")


def test_load_from_yaml_file():
    """Test loading configuration from YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": ['SecRule ARGS "@rx test" "id:1,deny"'],
                "rule_files": ["rules/test.conf"],
            },
            f,
        )
        temp_path = f.name

    try:
        loader = ConfigLoader()
        config = loader.load_from_file(temp_path)

        assert isinstance(config, WAFConfig)
        assert config.engine == "On"
        assert len(config.rules) == 1
        assert config.rule_files == ["rules/test.conf"]
    finally:
        Path(temp_path).unlink()


def test_load_from_json_file():
    """Test loading configuration from JSON file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(
            {
                "engine": "DetectionOnly",
                "rules": ['SecRule ARGS "@rx attack" "id:2,deny"'],
            },
            f,
        )
        temp_path = f.name

    try:
        loader = ConfigLoader()
        config = loader.load_from_file(temp_path)

        assert isinstance(config, WAFConfig)
        assert config.engine == "DetectionOnly"
        assert len(config.rules) == 1
    finally:
        Path(temp_path).unlink()


def test_load_from_yaml_with_waf_key():
    """Test loading from YAML with nested 'waf' key."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "waf": {
                    "engine": "On",
                    "rules": [],
                }
            },
            f,
        )
        temp_path = f.name

    try:
        loader = ConfigLoader()
        config = loader.load_from_file(temp_path)

        assert config.engine == "On"
    finally:
        Path(temp_path).unlink()


def test_load_from_file_with_env_vars():
    """Test loading from file with environment variable substitution."""
    env_vars = {"WAF_ENGINE": "DetectionOnly", "LOG_PATH": "/custom/log/path"}
    loader = ConfigLoader(env_vars=env_vars)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        # Write YAML manually to avoid boolean conversion
        f.write("""
engine: "${WAF_ENGINE}"
audit_logging:
  output: "${LOG_PATH}"
""")
        f.flush()
        temp_path = f.name

    try:
        config = loader.load_from_file(temp_path)

        assert config.engine == "DetectionOnly"
        assert config.audit_logging.output == "/custom/log/path"
    finally:
        Path(temp_path).unlink()


def test_load_from_file_not_found():
    """Test loading from non-existent file raises error."""
    loader = ConfigLoader()

    with pytest.raises(FileNotFoundError):
        loader.load_from_file("/nonexistent/config.yaml")


def test_load_from_file_unsupported_format():
    """Test loading from unsupported file format raises error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("some content")
        temp_path = f.name

    try:
        loader = ConfigLoader()

        with pytest.raises(ValueError, match="Unsupported file format"):
            loader.load_from_file(temp_path)
    finally:
        Path(temp_path).unlink()


def test_load_from_file_invalid_yaml():
    """Test loading invalid YAML raises error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: content: [unclosed")
        temp_path = f.name

    try:
        loader = ConfigLoader()

        with pytest.raises(yaml.YAMLError):
            loader.load_from_file(temp_path)
    finally:
        Path(temp_path).unlink()


def test_load_from_file_invalid_json():
    """Test loading invalid JSON raises error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write('{"invalid": json, missing quotes}')
        temp_path = f.name

    try:
        loader = ConfigLoader()

        with pytest.raises(json.JSONDecodeError):
            loader.load_from_file(temp_path)
    finally:
        Path(temp_path).unlink()


def test_load_from_dict():
    """Test loading configuration from dictionary."""
    data = {
        "engine": "On",
        "rules": ['SecRule ARGS "@rx test" "id:1,deny"'],
    }

    loader = ConfigLoader()
    config = loader.load_from_dict(data)

    assert isinstance(config, WAFConfig)
    assert config.engine == "On"
    assert len(config.rules) == 1


def test_load_from_dict_with_env_vars():
    """Test loading from dict with environment variable substitution."""
    env_vars = {"ENGINE_MODE": "DetectionOnly"}
    loader = ConfigLoader(env_vars=env_vars)

    data = {
        "engine": "${ENGINE_MODE}",
        "rules": [],
    }

    config = loader.load_from_dict(data)
    assert config.engine == "DetectionOnly"


def test_load_config_convenience_function():
    """Test load_config convenience function."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"engine": "On", "rules": []}, f)
        temp_path = f.name

    try:
        config = load_config(temp_path)

        assert isinstance(config, WAFConfig)
        assert config.engine == "On"
    finally:
        Path(temp_path).unlink()


def test_env_var_pattern_matching():
    """Test environment variable pattern matching."""
    loader = ConfigLoader()

    # Test various patterns
    test_cases = [
        ("${VAR_NAME}", "VAR_NAME", None),
        ("${VAR_NAME:-default}", "VAR_NAME", "default"),
        ("${MY_VAR_123:-some default}", "MY_VAR_123", "some default"),
        ("prefix_${VAR}_suffix", "VAR", None),
    ]

    for pattern, expected_var, expected_default in test_cases:
        match = loader.ENV_VAR_PATTERN.search(pattern)
        assert match is not None, f"Pattern should match: {pattern}"
        assert match.group(1) == expected_var
        if expected_default:
            assert match.group(2) == expected_default


def test_complex_config_with_multiple_env_vars():
    """Test complex configuration with multiple environment variables."""
    env_vars = {
        "ENGINE": "DetectionOnly",
        "REDIS_HOST": "redis-prod",
        "REDIS_PORT": "6380",
        "LOG_LEVEL": "WARNING",
    }
    loader = ConfigLoader(env_vars=env_vars)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        # Write YAML manually to avoid boolean conversion issues
        f.write("""
engine: "${ENGINE:-DetectionOnly}"
storage:
  backend: redis
  redis_host: "${REDIS_HOST:-localhost}"
  redis_port: "${REDIS_PORT:-6379}"
audit_logging:
  enabled: true
  level: "${LOG_LEVEL:-INFO}"
""")
        f.flush()
        temp_path = f.name

    try:
        config = loader.load_from_file(temp_path)

        assert config.engine == "DetectionOnly"
        assert config.storage.redis_host == "redis-prod"
        assert config.storage.redis_port == 6380
        assert config.audit_logging.level == "WARNING"
    finally:
        Path(temp_path).unlink()
