"""Configuration data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RequestLimits:
    """Request size limits configuration."""

    body_limit: int = 13107200  # 12.5 MB (ModSecurity default)
    header_limit: int = 8192  # 8 KB
    request_line_limit: int = 8192  # 8 KB


@dataclass
class StorageConfig:
    """Persistent storage configuration."""

    backend: str = "memory"  # memory, file, redis
    file_path: str | None = None
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_db: int = 0
    ttl: int = 3600  # 1 hour default TTL


@dataclass
class AuditLoggingConfig:
    """Audit logging configuration."""

    enabled: bool = False
    format: str = "json"  # json or text
    mask_sensitive: bool = True
    output: str | None = None  # File path or None for stdout
    level: str = "INFO"
    additional_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceConfig:
    """Performance tuning configuration."""

    regex_cache_size: int = 256
    worker_threads: int = 1  # For future async support


@dataclass
class WAFConfig:
    """Complete WAF configuration."""

    # Engine mode: "On" (blocking), "DetectionOnly" (logging), "Off"
    engine: str = "DetectionOnly"

    # Rule configuration
    rules: list[str] = field(default_factory=list)  # Inline rules
    rule_files: list[str] = field(default_factory=list)  # Rule file paths

    # Request limits
    request_limits: RequestLimits = field(default_factory=RequestLimits)

    # Storage
    storage: StorageConfig = field(default_factory=StorageConfig)

    # Audit logging
    audit_logging: AuditLoggingConfig = field(default_factory=AuditLoggingConfig)

    # Performance
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)

    # Component signature (informational)
    component_signature: str = "LeWAF/1.2.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary.

        Returns:
            Dictionary representation of configuration
        """
        return {
            "engine": self.engine,
            "rules": self.rules,
            "rule_files": self.rule_files,
            "request_limits": {
                "body_limit": self.request_limits.body_limit,
                "header_limit": self.request_limits.header_limit,
                "request_line_limit": self.request_limits.request_line_limit,
            },
            "storage": {
                "backend": self.storage.backend,
                "file_path": self.storage.file_path,
                "redis_host": self.storage.redis_host,
                "redis_port": self.storage.redis_port,
                "redis_db": self.storage.redis_db,
                "ttl": self.storage.ttl,
            },
            "audit_logging": {
                "enabled": self.audit_logging.enabled,
                "format": self.audit_logging.format,
                "mask_sensitive": self.audit_logging.mask_sensitive,
                "output": self.audit_logging.output,
                "level": self.audit_logging.level,
                "additional_fields": self.audit_logging.additional_fields,
            },
            "performance": {
                "regex_cache_size": self.performance.regex_cache_size,
                "worker_threads": self.performance.worker_threads,
            },
            "component_signature": self.component_signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WAFConfig:
        """Create configuration from dictionary.

        Args:
            data: Dictionary with configuration data

        Returns:
            WAFConfig instance
        """
        # Extract nested configs
        request_limits_data = data.get("request_limits", {})
        storage_data = data.get("storage", {})
        audit_logging_data = data.get("audit_logging", {})
        performance_data = data.get("performance", {})

        return cls(
            engine=data.get("engine", "DetectionOnly"),
            rules=data.get("rules", []),
            rule_files=data.get("rule_files", []),
            request_limits=RequestLimits(
                body_limit=int(request_limits_data.get("body_limit", 13107200)),
                header_limit=int(request_limits_data.get("header_limit", 8192)),
                request_line_limit=int(
                    request_limits_data.get("request_line_limit", 8192)
                ),
            ),
            storage=StorageConfig(
                backend=storage_data.get("backend", "memory"),
                file_path=storage_data.get("file_path"),
                redis_host=storage_data.get("redis_host", "localhost"),
                redis_port=int(storage_data.get("redis_port", 6379)),
                redis_db=int(storage_data.get("redis_db", 0)),
                ttl=int(storage_data.get("ttl", 3600)),
            ),
            audit_logging=AuditLoggingConfig(
                enabled=audit_logging_data.get("enabled", False),
                format=audit_logging_data.get("format", "json"),
                mask_sensitive=audit_logging_data.get("mask_sensitive", True),
                output=audit_logging_data.get("output"),
                level=audit_logging_data.get("level", "INFO"),
                additional_fields=audit_logging_data.get("additional_fields", {}),
            ),
            performance=PerformanceConfig(
                regex_cache_size=int(performance_data.get("regex_cache_size", 256)),
                worker_threads=int(performance_data.get("worker_threads", 1)),
            ),
            component_signature=data.get("component_signature", "LeWAF/1.2.0"),
        )
