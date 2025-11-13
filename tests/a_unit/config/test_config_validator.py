"""Tests for configuration validator."""

from __future__ import annotations

import tempfile
from pathlib import Path

from lewaf.config.models import (
    AuditLoggingConfig,
    PerformanceConfig,
    RequestLimits,
    StorageConfig,
    WAFConfig,
)
from lewaf.config.validator import ConfigValidator


def test_validator_initialization():
    """Test ConfigValidator initialization."""
    validator = ConfigValidator()
    assert validator.errors == []
    assert validator.warnings == []


def test_validate_valid_config():
    """Test validating a valid configuration."""
    config = WAFConfig(
        engine="On",
        rules=['SecRule ARGS "@rx test" "id:1,deny"'],
    )

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is True
    assert len(errors) == 0


def test_validate_invalid_engine():
    """Test validating invalid engine mode."""
    config = WAFConfig(engine="Invalid")

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("engine mode" in err.lower() for err in errors)


def test_validate_no_rules_warning():
    """Test warning when no rules are specified."""
    config = WAFConfig(rules=[], rule_files=[])

    validator = ConfigValidator()
    is_valid, _errors, warnings = validator.validate(config)

    assert is_valid is True  # Warning, not error
    assert any("no rules" in warn.lower() for warn in warnings)


def test_validate_rule_file_not_found():
    """Test error when rule file doesn't exist."""
    config = WAFConfig(rule_files=["/nonexistent/rules.conf"])

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("not found" in err.lower() for err in errors)


def test_validate_rule_file_glob_pattern():
    """Test validation of glob pattern parent directory."""
    config = WAFConfig(rule_files=["/nonexistent/dir/*.conf"])

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("parent directory not found" in err.lower() for err in errors)


def test_validate_invalid_body_limit():
    """Test validating invalid body limit."""
    config = WAFConfig(request_limits=RequestLimits(body_limit=-1))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("body_limit must be positive" in err.lower() for err in errors)


def test_validate_large_body_limit_warning():
    """Test warning for very large body limit."""
    config = WAFConfig(
        request_limits=RequestLimits(body_limit=200 * 1024 * 1024)  # 200 MB
    )

    validator = ConfigValidator()
    is_valid, _errors, warnings = validator.validate(config)

    assert is_valid is True
    assert any("very large" in warn.lower() for warn in warnings)


def test_validate_invalid_storage_backend():
    """Test validating invalid storage backend."""
    config = WAFConfig(storage=StorageConfig(backend="invalid"))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("storage backend" in err.lower() for err in errors)


def test_validate_file_storage_without_path():
    """Test error when file storage backend has no path."""
    config = WAFConfig(storage=StorageConfig(backend="file", file_path=None))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("file_path is required" in err.lower() for err in errors)


def test_validate_file_storage_nonexistent_parent():
    """Test error when file storage parent directory doesn't exist."""
    config = WAFConfig(
        storage=StorageConfig(backend="file", file_path="/nonexistent/dir/storage.db")
    )

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("parent directory not found" in err.lower() for err in errors)


def test_validate_invalid_redis_port():
    """Test validating invalid Redis port."""
    config = WAFConfig(storage=StorageConfig(backend="redis", redis_port=70000))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("redis_port" in err.lower() for err in errors)


def test_validate_negative_ttl_warning():
    """Test warning for non-positive TTL."""
    config = WAFConfig(storage=StorageConfig(ttl=-1))

    validator = ConfigValidator()
    is_valid, _errors, warnings = validator.validate(config)

    assert is_valid is True
    assert any("ttl" in warn.lower() for warn in warnings)


def test_validate_invalid_audit_format():
    """Test validating invalid audit log format."""
    config = WAFConfig(audit_logging=AuditLoggingConfig(format="invalid"))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("format" in err.lower() for err in errors)


def test_validate_invalid_audit_level():
    """Test validating invalid audit log level."""
    config = WAFConfig(audit_logging=AuditLoggingConfig(level="INVALID"))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("level" in err.lower() for err in errors)


def test_validate_audit_output_nonexistent_parent():
    """Test error when audit log parent directory doesn't exist."""
    config = WAFConfig(
        audit_logging=AuditLoggingConfig(output="/nonexistent/dir/audit.log")
    )

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("parent directory not found" in err.lower() for err in errors)


def test_validate_invalid_regex_cache_size():
    """Test validating invalid regex cache size."""
    config = WAFConfig(performance=PerformanceConfig(regex_cache_size=-1))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("regex_cache_size" in err.lower() for err in errors)


def test_validate_large_regex_cache_warning():
    """Test warning for very large regex cache size."""
    config = WAFConfig(performance=PerformanceConfig(regex_cache_size=20000))

    validator = ConfigValidator()
    is_valid, _errors, warnings = validator.validate(config)

    assert is_valid is True
    assert any("regex_cache_size" in warn.lower() for warn in warnings)


def test_validate_invalid_worker_threads():
    """Test validating invalid worker threads."""
    config = WAFConfig(performance=PerformanceConfig(worker_threads=0))

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert any("worker_threads" in err.lower() for err in errors)


def test_validate_high_worker_threads_warning():
    """Test warning for very high worker threads."""
    config = WAFConfig(performance=PerformanceConfig(worker_threads=64))

    validator = ConfigValidator()
    is_valid, _errors, warnings = validator.validate(config)

    assert is_valid is True
    assert any("worker_threads" in warn.lower() for warn in warnings)


def test_validate_multiple_errors():
    """Test collecting multiple validation errors."""
    config = WAFConfig(
        engine="Invalid",
        request_limits=RequestLimits(body_limit=-1, header_limit=-1),
        storage=StorageConfig(backend="invalid"),
    )

    validator = ConfigValidator()
    is_valid, errors, _warnings = validator.validate(config)

    assert is_valid is False
    assert len(errors) >= 3  # At least engine, body_limit, storage backend


def test_validate_with_existing_file():
    """Test validation passes with existing rule file."""
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as f:
        f.write('SecRule ARGS "@rx test" "id:1,deny"')
        temp_path = f.name

    try:
        config = WAFConfig(rule_files=[temp_path])

        validator = ConfigValidator()
        is_valid, errors, _warnings = validator.validate(config)

        assert is_valid is True
        assert len(errors) == 0
    finally:
        Path(temp_path).unlink()


def test_validate_with_existing_storage_directory():
    """Test validation passes with existing storage directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        storage_path = Path(temp_dir) / "storage.db"

        config = WAFConfig(
            storage=StorageConfig(backend="file", file_path=str(storage_path))
        )

        validator = ConfigValidator()
        is_valid, errors, _warnings = validator.validate(config)

        assert is_valid is True
        assert len(errors) == 0


def test_validate_with_existing_log_directory():
    """Test validation passes with existing log directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        log_path = Path(temp_dir) / "audit.log"

        config = WAFConfig(audit_logging=AuditLoggingConfig(output=str(log_path)))

        validator = ConfigValidator()
        is_valid, errors, _warnings = validator.validate(config)

        assert is_valid is True
        assert len(errors) == 0
