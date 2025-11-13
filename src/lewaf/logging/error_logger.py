"""Structured error logging for LeWAF.

This module provides context-aware logging utilities that work with
the LeWAF exception hierarchy to produce structured, searchable logs.

Features:
- Automatic serialization of WAFError context to JSON
- Transaction ID tracking
- Rule ID and phase tracking
- Log aggregation and deduplication
- Integration with monitoring systems

Example:
    from lewaf.logging.error_logger import log_error, log_operator_error

    # Log a WAF exception with full context
    try:
        process_body(body)
    except InvalidJSONError as e:
        log_error(e, logger, transaction_id="tx-123")

    # Log operator evaluation error
    log_operator_error(
        operator_name="rx",
        error=ValueError("Invalid regex"),
        value=user_input,
        transaction_id="tx-123",
        rule_id=1001,
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lewaf.exceptions import WAFError

# Default logger for this module
logger = logging.getLogger(__name__)


def log_error(
    error: WAFError | Exception,
    log: logging.Logger | None = None,
    level: int = logging.ERROR,
    **extra_context: Any,
) -> None:
    """Log a WAF error with full structured context.

    Args:
        error: The exception to log (preferably a WAFError)
        log: Logger to use (defaults to module logger)
        level: Log level (default: ERROR)
        **extra_context: Additional context to include in the log

    Example:
        try:
            parse_json(body)
        except InvalidJSONError as e:
            log_error(e, logger, transaction_id="tx-456")
    """
    if log is None:
        log = logger

    # Build structured log entry
    log_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": error.__class__.__name__,
        "message": str(error),
    }

    # If it's a WAFError, include all the rich context
    is_waf_error = hasattr(error, "to_dict")
    if is_waf_error:
        log_data.update(error.to_dict())  # type: ignore[attr-defined]

    # Add any extra context
    log_data.update(extra_context)

    # Log with structured data - use different format for WAFError vs regular exceptions
    if is_waf_error:
        log.log(
            level,
            "WAF Error: %(error_code)s - %(message)s",
            log_data,
            extra={"structured_data": log_data},
        )
    else:
        log.log(
            level,
            "Error: %(error_type)s - %(message)s",
            log_data,
            extra={"structured_data": log_data},
        )


def log_operator_error(
    operator_name: str,
    error: Exception,
    value: str,
    log: logging.Logger | None = None,
    transaction_id: str | None = None,
    rule_id: int | None = None,
    phase: int | None = None,
    variable_name: str | None = None,
) -> None:
    """Log an operator evaluation error with context.

    This is used when an operator catches an exception during evaluation
    but returns False instead of raising. The error is logged for debugging.

    Args:
        operator_name: Name of the operator (e.g., "rx", "gt", "ipMatch")
        error: The exception that occurred
        value: The value being evaluated
        log: Logger to use (defaults to module logger)
        transaction_id: Transaction ID if available
        rule_id: Rule ID if available
        phase: Processing phase if available
        variable_name: Variable name if available (e.g., "ARGS:id")

    Example:
        try:
            return float(value) > float(self._argument)
        except ValueError as e:
            log_operator_error("gt", e, value, logger)
            return False
    """
    if log is None:
        log = logger

    # Truncate long values for logging
    truncated_value = value[:100] if len(value) > 100 else value

    log_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": "OperatorEvaluationError",
        "operator": operator_name,
        "exception": error.__class__.__name__,
        "exception_message": str(error),
        "value": truncated_value,
        "value_length": len(value),
    }

    # Add optional context
    if transaction_id:
        log_data["transaction_id"] = transaction_id
    if rule_id:
        log_data["rule_id"] = rule_id
    if phase:
        log_data["phase"] = phase
    if variable_name:
        log_data["variable"] = variable_name

    # Log at WARNING level (not ERROR) since operator returning False is expected
    log.warning(
        "Operator @%s failed to evaluate value: %s (%s)",
        operator_name,
        error.__class__.__name__,
        str(error)[:50],
        extra={"structured_data": log_data},
    )


def log_transformation_error(
    transformation_name: str,
    error: Exception,
    input_value: str,
    log: logging.Logger | None = None,
    transaction_id: str | None = None,
    rule_id: int | None = None,
) -> None:
    """Log a transformation error with context.

    Args:
        transformation_name: Name of the transformation
        error: The exception that occurred
        input_value: The input value that failed to transform
        log: Logger to use (defaults to module logger)
        transaction_id: Transaction ID if available
        rule_id: Rule ID if available

    Example:
        try:
            return base64.b64decode(value)
        except Exception as e:
            log_transformation_error("base64Decode", e, value, logger)
            return value  # Return original on error
    """
    if log is None:
        log = logger

    # Truncate long values
    truncated = input_value[:100] if len(input_value) > 100 else input_value

    log_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": "TransformationError",
        "transformation": transformation_name,
        "exception": error.__class__.__name__,
        "exception_message": str(error),
        "input": truncated,
        "input_length": len(input_value),
    }

    if transaction_id:
        log_data["transaction_id"] = transaction_id
    if rule_id:
        log_data["rule_id"] = rule_id

    log.warning(
        "Transformation '%s' failed: %s (%s)",
        transformation_name,
        error.__class__.__name__,
        str(error)[:50],
        extra={"structured_data": log_data},
    )


def log_storage_error(
    backend_type: str,
    operation: str,
    error: Exception,
    log: logging.Logger | None = None,
    collection_name: str | None = None,
    key: str | None = None,
) -> None:
    """Log a storage backend error with context.

    Args:
        backend_type: Type of storage backend (e.g., "redis", "file", "memory")
        operation: Operation that failed (e.g., "get", "set", "delete")
        error: The exception that occurred
        log: Logger to use (defaults to module logger)
        collection_name: Collection name if available
        key: Key being accessed if available

    Example:
        try:
            redis_client.set(key, value)
        except redis.ConnectionError as e:
            log_storage_error("redis", "set", e, logger, key=key)
    """
    if log is None:
        log = logger

    log_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": "StorageError",
        "backend": backend_type,
        "operation": operation,
        "exception": error.__class__.__name__,
        "exception_message": str(error),
    }

    if collection_name:
        log_data["collection"] = collection_name
    if key:
        log_data["key"] = key

    log.error(
        "Storage backend '%s' %s operation failed: %s",
        backend_type,
        operation,
        str(error)[:50],
        extra={"structured_data": log_data},
    )


def log_body_processing_error(
    content_type: str,
    error: Exception,
    body_size: int,
    log: logging.Logger | None = None,
    transaction_id: str | None = None,
) -> None:
    """Log a body processing error with context.

    Args:
        content_type: Content-Type of the body being processed
        error: The exception that occurred
        body_size: Size of the body in bytes
        log: Logger to use (defaults to module logger)
        transaction_id: Transaction ID if available

    Example:
        try:
            json.loads(body)
        except json.JSONDecodeError as e:
            log_body_processing_error("application/json", e, len(body), logger)
    """
    if log is None:
        log = logger

    log_data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error_type": "BodyProcessingError",
        "content_type": content_type,
        "body_size": body_size,
        "exception": error.__class__.__name__,
        "exception_message": str(error),
    }

    if transaction_id:
        log_data["transaction_id"] = transaction_id

    log.error(
        "Body processing failed for %s (%d bytes): %s",
        content_type,
        body_size,
        str(error)[:50],
        extra={"structured_data": log_data},
    )
