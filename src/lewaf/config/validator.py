"""Configuration validation."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from lewaf.config.models import WAFConfig


class ConfigValidator:
    """Validate WAF configuration."""

    VALID_ENGINES: ClassVar[list[str]] = ["On", "DetectionOnly", "Off"]
    VALID_STORAGE_BACKENDS: ClassVar[list[str]] = ["memory", "file", "redis"]
    VALID_LOG_FORMATS: ClassVar[list[str]] = ["json", "text"]
    VALID_LOG_LEVELS: ClassVar[list[str]] = [
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    ]

    def __init__(self):
        """Initialize validator."""
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def validate(self, config: WAFConfig) -> tuple[bool, list[str], list[str]]:
        """Validate configuration.

        Args:
            config: Configuration to validate

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        self.errors = []
        self.warnings = []

        self._validate_engine(config.engine)
        self._validate_rules(config)
        self._validate_request_limits(config)
        self._validate_storage(config)
        self._validate_audit_logging(config)
        self._validate_performance(config)

        is_valid = len(self.errors) == 0
        return is_valid, self.errors, self.warnings

    def _validate_engine(self, engine: str) -> None:
        """Validate engine mode."""
        if engine not in self.VALID_ENGINES:
            self.errors.append(
                f"Invalid engine mode '{engine}'. Must be one of: {', '.join(self.VALID_ENGINES)}"
            )

    def _validate_rules(self, config: WAFConfig) -> None:
        """Validate rule configuration."""
        # Check if at least one rule source is specified
        if not config.rules and not config.rule_files:
            self.warnings.append(
                "No rules or rule files specified. WAF will have no effect."
            )

        # Validate rule file paths exist
        for rule_file in config.rule_files:
            path = Path(rule_file)
            # Handle glob patterns
            if "*" in rule_file:
                # Check if parent directory exists
                parent = path.parent
                if not parent.exists():
                    self.errors.append(
                        f"Rule file pattern parent directory not found: {parent}"
                    )
            # Check if specific file exists
            elif not path.exists():
                self.errors.append(f"Rule file not found: {rule_file}")

    def _validate_request_limits(self, config: WAFConfig) -> None:
        """Validate request limits."""
        limits = config.request_limits

        if limits.body_limit <= 0:
            self.errors.append("request_limits.body_limit must be positive")
        elif limits.body_limit > 100 * 1024 * 1024:  # 100 MB
            self.warnings.append(
                f"request_limits.body_limit is very large ({limits.body_limit} bytes). "
                "Consider lowering to improve performance."
            )

        if limits.header_limit <= 0:
            self.errors.append("request_limits.header_limit must be positive")

        if limits.request_line_limit <= 0:
            self.errors.append("request_limits.request_line_limit must be positive")

    def _validate_storage(self, config: WAFConfig) -> None:
        """Validate storage configuration."""
        storage = config.storage

        if storage.backend not in self.VALID_STORAGE_BACKENDS:
            self.errors.append(
                f"Invalid storage backend '{storage.backend}'. "
                f"Must be one of: {', '.join(self.VALID_STORAGE_BACKENDS)}"
            )

        if storage.backend == "file":
            if not storage.file_path:
                self.errors.append(
                    "storage.file_path is required when backend is 'file'"
                )
            else:
                # Check if directory exists
                file_path = Path(storage.file_path)
                if not file_path.parent.exists():
                    self.errors.append(
                        f"Storage file parent directory not found: {file_path.parent}"
                    )

        if storage.backend == "redis":
            if storage.redis_port <= 0 or storage.redis_port > 65535:
                self.errors.append("storage.redis_port must be between 1 and 65535")

        if storage.ttl <= 0:
            self.warnings.append(
                "storage.ttl is non-positive. Sessions will not expire."
            )

    def _validate_audit_logging(self, config: WAFConfig) -> None:
        """Validate audit logging configuration."""
        audit = config.audit_logging

        if audit.format not in self.VALID_LOG_FORMATS:
            self.errors.append(
                f"Invalid audit_logging.format '{audit.format}'. "
                f"Must be one of: {', '.join(self.VALID_LOG_FORMATS)}"
            )

        if audit.level not in self.VALID_LOG_LEVELS:
            self.errors.append(
                f"Invalid audit_logging.level '{audit.level}'. "
                f"Must be one of: {', '.join(self.VALID_LOG_LEVELS)}"
            )

        if audit.output:
            # Check if directory exists
            output_path = Path(audit.output)
            if not output_path.parent.exists():
                self.errors.append(
                    f"Audit log parent directory not found: {output_path.parent}"
                )

    def _validate_performance(self, config: WAFConfig) -> None:
        """Validate performance configuration."""
        perf = config.performance

        if perf.regex_cache_size <= 0:
            self.errors.append("performance.regex_cache_size must be positive")
        elif perf.regex_cache_size > 10000:
            self.warnings.append(
                f"performance.regex_cache_size is very large ({perf.regex_cache_size}). "
                "This may consume significant memory."
            )

        if perf.worker_threads <= 0:
            self.errors.append("performance.worker_threads must be positive")
        elif perf.worker_threads > 32:
            self.warnings.append(
                f"performance.worker_threads is very high ({perf.worker_threads}). "
                "This may cause resource contention."
            )
