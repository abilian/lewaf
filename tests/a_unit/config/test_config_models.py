"""Tests for configuration data models."""

from __future__ import annotations

from lewaf.config.models import (
    AuditLoggingConfig,
    PerformanceConfig,
    RequestLimits,
    StorageConfig,
    WAFConfig,
)


def test_request_limits_defaults():
    """Test RequestLimits default values."""
    limits = RequestLimits()
    assert limits.body_limit == 13107200  # 12.5 MB
    assert limits.header_limit == 8192
    assert limits.request_line_limit == 8192


def test_storage_config_defaults():
    """Test StorageConfig default values."""
    storage = StorageConfig()
    assert storage.backend == "memory"
    assert storage.file_path is None
    assert storage.redis_host == "localhost"
    assert storage.redis_port == 6379
    assert storage.redis_db == 0
    assert storage.ttl == 3600


def test_audit_logging_config_defaults():
    """Test AuditLoggingConfig default values."""
    audit = AuditLoggingConfig()
    assert audit.enabled is False
    assert audit.format == "json"
    assert audit.mask_sensitive is True
    assert audit.output is None
    assert audit.level == "INFO"
    assert audit.additional_fields == {}


def test_performance_config_defaults():
    """Test PerformanceConfig default values."""
    perf = PerformanceConfig()
    assert perf.regex_cache_size == 256
    assert perf.worker_threads == 1


def test_waf_config_defaults():
    """Test WAFConfig default values."""
    config = WAFConfig()
    assert config.engine == "DetectionOnly"
    assert config.rules == []
    assert config.rule_files == []
    assert isinstance(config.request_limits, RequestLimits)
    assert isinstance(config.storage, StorageConfig)
    assert isinstance(config.audit_logging, AuditLoggingConfig)
    assert isinstance(config.performance, PerformanceConfig)
    assert "LeWAF" in config.component_signature


def test_waf_config_to_dict():
    """Test WAFConfig.to_dict() conversion."""
    config = WAFConfig(
        engine="On",
        rules=['SecRule ARGS "@rx attack" "id:1,deny"'],
        rule_files=["rules/crs.conf"],
    )

    result = config.to_dict()
    assert result["engine"] == "On"
    assert result["rules"] == ['SecRule ARGS "@rx attack" "id:1,deny"']
    assert result["rule_files"] == ["rules/crs.conf"]
    assert "request_limits" in result
    assert "storage" in result
    assert "audit_logging" in result
    assert "performance" in result


def test_waf_config_from_dict_minimal():
    """Test WAFConfig.from_dict() with minimal data."""
    data = {
        "engine": "On",
        "rules": ['SecRule ARGS "@rx test" "id:1,deny"'],
    }

    config = WAFConfig.from_dict(data)
    assert config.engine == "On"
    assert len(config.rules) == 1
    assert config.rule_files == []
    # Check defaults are applied
    assert config.request_limits.body_limit == 13107200
    assert config.storage.backend == "memory"


def test_waf_config_from_dict_complete():
    """Test WAFConfig.from_dict() with complete data."""
    data = {
        "engine": "DetectionOnly",
        "rules": [],
        "rule_files": ["rules/crs.conf"],
        "request_limits": {
            "body_limit": 10485760,  # 10 MB
            "header_limit": 4096,
            "request_line_limit": 4096,
        },
        "storage": {
            "backend": "redis",
            "redis_host": "redis-server",
            "redis_port": 6380,
            "redis_db": 1,
            "ttl": 7200,
        },
        "audit_logging": {
            "enabled": True,
            "format": "json",
            "mask_sensitive": True,
            "output": "/var/log/waf.log",
            "level": "WARNING",
            "additional_fields": {"app": "my-app"},
        },
        "performance": {
            "regex_cache_size": 512,
            "worker_threads": 4,
        },
        "component_signature": "CustomWAF/1.0",
    }

    config = WAFConfig.from_dict(data)

    assert config.engine == "DetectionOnly"
    assert config.rule_files == ["rules/crs.conf"]

    assert config.request_limits.body_limit == 10485760
    assert config.request_limits.header_limit == 4096

    assert config.storage.backend == "redis"
    assert config.storage.redis_host == "redis-server"
    assert config.storage.redis_port == 6380
    assert config.storage.redis_db == 1
    assert config.storage.ttl == 7200

    assert config.audit_logging.enabled is True
    assert config.audit_logging.format == "json"
    assert config.audit_logging.output == "/var/log/waf.log"
    assert config.audit_logging.level == "WARNING"
    assert config.audit_logging.additional_fields == {"app": "my-app"}

    assert config.performance.regex_cache_size == 512
    assert config.performance.worker_threads == 4

    assert config.component_signature == "CustomWAF/1.0"


def test_waf_config_roundtrip():
    """Test WAFConfig to_dict/from_dict roundtrip."""
    original = WAFConfig(
        engine="On",
        rules=['SecRule ARGS "@rx test" "id:1,deny"'],
        rule_files=["rules/test.conf"],
    )

    # Convert to dict and back
    data = original.to_dict()
    restored = WAFConfig.from_dict(data)

    assert restored.engine == original.engine
    assert restored.rules == original.rules
    assert restored.rule_files == original.rule_files
    assert restored.request_limits.body_limit == original.request_limits.body_limit
    assert restored.storage.backend == original.storage.backend
    assert restored.audit_logging.enabled == original.audit_logging.enabled
    assert (
        restored.performance.regex_cache_size == original.performance.regex_cache_size
    )
