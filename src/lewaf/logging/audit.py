"""Audit logging for security events and compliance."""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from lewaf.logging.formatters import JSONFormatter
from lewaf.logging.masking import DataMasker

if TYPE_CHECKING:
    from lewaf.transaction import Transaction


class AuditLogger:
    """Audit logger for WAF security events."""

    def __init__(
        self,
        name: str = "lewaf.audit",
        level: str = "INFO",
        output_file: str | None = None,
        format_type: str = "json",
        mask_sensitive_data: bool = True,
        additional_fields: dict[str, Any] | None = None,
    ):
        """Initialize audit logger.

        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            output_file: Output file path (None for stdout)
            format_type: Format type ("json" or "text")
            mask_sensitive_data: Whether to mask sensitive data
            additional_fields: Additional fields for all logs
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.masker = DataMasker() if mask_sensitive_data else None
        self.additional_fields = additional_fields or {}

        # Configure handler
        handler: logging.Handler
        if output_file:
            handler = logging.FileHandler(output_file)
        else:
            handler = logging.StreamHandler()

        # Set formatter
        formatter: logging.Formatter
        if format_type == "json":
            formatter = JSONFormatter(additional_fields=self.additional_fields)
        else:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_security_event(
        self,
        event_type: str,
        transaction_id: str,
        source_ip: str | None = None,
        request: dict[str, Any] | None = None,
        rule: dict[str, Any] | None = None,
        action: str | None = None,
        processing_time_ms: float | None = None,
        level: str = "WARNING",
        **kwargs: Any,
    ) -> None:
        """Log security event.

        Args:
            event_type: Event type (attack_detected, request_blocked, etc.)
            transaction_id: Transaction ID
            source_ip: Source IP address
            request: Request information
            rule: Rule information
            action: Action taken (deny, allow, log)
            processing_time_ms: Processing time in milliseconds
            level: Log level
            **kwargs: Additional fields
        """
        # Mask sensitive data if enabled
        if self.masker:
            if request:
                request = self.masker.mask(request)
            if rule:
                rule = self.masker.mask(rule)

        # Create log record with extra fields
        extra: dict[str, Any] = {
            "event_type": event_type,
            "transaction_id": transaction_id,
        }

        if source_ip:
            extra["source_ip"] = source_ip
        if request:
            extra["request"] = request
        if rule:
            extra["rule"] = rule
        if action:
            extra["action"] = action
        if processing_time_ms is not None:
            extra["processing_time_ms"] = processing_time_ms

        # Add additional kwargs
        extra.update(kwargs)

        # Log message
        message = f"{event_type}: transaction {transaction_id}"
        if rule:
            message += f" - Rule {rule.get('id', 'unknown')}"

        log_level = getattr(logging, level.upper())
        self.logger.log(log_level, message, extra=extra)

    def log_attack_detected(
        self,
        transaction: Transaction,
        rule_id: int,
        rule_msg: str,
        processing_time_ms: float | None = None,
    ) -> None:
        """Log attack detection event.

        Args:
            transaction: Transaction object
            rule_id: Rule ID that matched
            rule_msg: Rule message
            processing_time_ms: Processing time in milliseconds
        """
        request_info = {
            "method": transaction.variables.request_method.get(),
            "uri": transaction.variables.request_uri.get(),
            "protocol": transaction.variables.request_protocol.get(),
        }

        rule_info = {
            "id": rule_id,
            "msg": rule_msg,
            "phase": transaction.current_phase,
        }

        self.log_security_event(
            event_type="attack_detected",
            transaction_id=transaction.id,
            request=request_info,
            rule=rule_info,
            action="deny",
            processing_time_ms=processing_time_ms,
            level="WARNING",
        )

    def log_request_allowed(
        self,
        transaction: Transaction,
        processing_time_ms: float | None = None,
    ) -> None:
        """Log allowed request (INFO level).

        Args:
            transaction: Transaction object
            processing_time_ms: Processing time in milliseconds
        """
        request_info = {
            "method": transaction.variables.request_method.get(),
            "uri": transaction.variables.request_uri.get(),
        }

        self.log_security_event(
            event_type="request_allowed",
            transaction_id=transaction.id,
            request=request_info,
            action="allow",
            processing_time_ms=processing_time_ms,
            level="INFO",
        )

    def log_processing_error(
        self,
        transaction_id: str,
        error_type: str,
        error_msg: str,
        **kwargs: Any,
    ) -> None:
        """Log processing error.

        Args:
            transaction_id: Transaction ID
            error_type: Error type
            error_msg: Error message
            **kwargs: Additional fields
        """
        self.log_security_event(
            event_type="processing_error",
            transaction_id=transaction_id,
            level="ERROR",
            error_type=error_type,
            error_msg=error_msg,
            **kwargs,
        )

    def log_config_change(
        self,
        change_type: str,
        description: str,
        **kwargs: Any,
    ) -> None:
        """Log configuration change (audit trail).

        Args:
            change_type: Change type (rule_added, rule_modified, etc.)
            description: Change description
            **kwargs: Additional fields
        """
        extra = {
            "event_type": "config_change",
            "change_type": change_type,
            "timestamp": time.time(),
        }
        extra.update(kwargs)

        self.logger.info("Configuration change: %s", description, extra=extra)

    def log_performance_metric(
        self,
        metric_name: str,
        metric_value: float,
        transaction_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Log performance metric.

        Args:
            metric_name: Metric name
            metric_value: Metric value
            transaction_id: Transaction ID (optional)
            **kwargs: Additional fields
        """
        extra = {
            "event_type": "performance_metric",
            "metric_name": metric_name,
            "metric_value": metric_value,
        }

        if transaction_id:
            extra["transaction_id"] = transaction_id

        extra.update(kwargs)

        self.logger.debug(
            "Performance: %s = %s", metric_name, metric_value, extra=extra
        )


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def configure_audit_logging(
    level: str = "INFO",
    format_type: str = "json",
    output: str | None = None,
    mask_sensitive: bool = True,
    additional_fields: dict[str, Any] | None = None,
) -> AuditLogger:
    """Configure global audit logging.

    Args:
        level: Log level
        format_type: Format type ("json" or "text")
        output: Output file path (None for stdout)
        mask_sensitive: Whether to mask sensitive data
        additional_fields: Additional fields for all logs

    Returns:
        Configured AuditLogger instance
    """
    global _audit_logger
    _audit_logger = AuditLogger(
        level=level,
        output_file=output,
        format_type=format_type,
        mask_sensitive_data=mask_sensitive,
        additional_fields=additional_fields,
    )
    return _audit_logger


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance.

    Returns:
        AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
