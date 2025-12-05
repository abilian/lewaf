"""LeWAF exception hierarchy with standardized error codes.

This module provides a comprehensive exception hierarchy for LeWAF with:
- Standardized error codes for categorization
- Rich context information (transaction ID, rule ID, phase, etc.)
- Structured error data for logging and monitoring
- Exception chaining support for root cause analysis
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class WAFError(Exception):
    """Base exception for all WAF-related errors.

    All WAF exceptions inherit from this base class and provide:
    - Standardized error code for categorization
    - Rich context information
    - Structured error data for logging/monitoring
    - Timestamp of error occurrence

    Attributes:
        code: Standardized error code (e.g., "WAF-0001")
        message: Human-readable error message
        context: Additional context dictionary
        timestamp: When the error occurred
    """

    code: str = "WAF-0000"
    category: str = "general"

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        cause: Exception | None = None,
    ):
        """Initialize WAF error.

        Args:
            message: Human-readable error message
            context: Additional context dictionary
            cause: Original exception if this is a wrapped error
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}
        self.timestamp = datetime.now(timezone.utc)
        self.cause = cause

    def to_dict(self) -> dict[str, Any]:
        """Convert error to structured dictionary for logging.

        Returns:
            Dictionary with error code, message, context, and metadata
        """
        return {
            "error_code": self.code,
            "error_category": self.category,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp.isoformat(),
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        """Format error as string with code and context."""
        parts = [f"[{self.code}] {self.message}"]
        if self.context:
            ctx_str = ", ".join(f"{k}={v}" for k, v in self.context.items())
            parts.append(f"(context: {ctx_str})")
        return " ".join(parts)


# ============================================================================
# Configuration & Startup Errors (WAF-0xxx)
# ============================================================================


class ConfigurationError(WAFError):
    """Configuration-related errors."""

    code = "WAF-0001"
    category = "configuration"


class ConfigFileNotFoundError(ConfigurationError):
    """Configuration file not found."""

    code = "WAF-0002"

    def __init__(self, file_path: str, cause: Exception | None = None):
        super().__init__(
            f"Configuration file not found: {file_path}",
            context={"file_path": file_path},
            cause=cause,
        )


class ConfigValidationError(ConfigurationError):
    """Configuration validation failed."""

    code = "WAF-0003"

    def __init__(self, message: str, errors: list[str] | None = None, **context: Any):
        super().__init__(
            message,
            context={"errors": errors or [], **context},
        )


class EnvironmentVariableError(ConfigurationError):
    """Required environment variable missing."""

    code = "WAF-0004"

    def __init__(self, var_name: str):
        super().__init__(
            f"Required environment variable not set: {var_name}",
            context={"variable": var_name},
        )


# ============================================================================
# SecLang Parsing Errors (PARSE-1xxx)
# ============================================================================


class ParseError(WAFError):
    """Base class for parsing errors."""

    code = "PARSE-1000"
    category = "parsing"

    def __init__(
        self,
        message: str,
        file_path: str | None = None,
        line_number: int | None = None,
        **context: Any,
    ):
        # Extract cause if present in context
        cause = context.pop("cause", None)

        ctx = {"file": file_path, "line": line_number, **context}
        super().__init__(message, context=ctx, cause=cause)


class SecRuleParseError(ParseError):
    """Invalid SecRule format."""

    code = "PARSE-1001"

    def __init__(
        self,
        message: str,
        rule_text: str | None = None,
        file_path: str | None = None,
        line_number: int | None = None,
    ):
        super().__init__(
            message,
            file_path=file_path,
            line_number=line_number,
            rule_text=rule_text[:100] if rule_text else None,  # Truncate for logging
        )


class IncludeRecursionError(ParseError):
    """Include directive recursion limit exceeded."""

    code = "PARSE-1002"

    def __init__(self, file_path: str, depth: int, max_depth: int):
        super().__init__(
            f"Include recursion limit exceeded: {file_path}",
            file_path=file_path,
            depth=depth,
            max_depth=max_depth,
        )


class UnknownOperatorError(ParseError):
    """Unknown operator in rule."""

    code = "PARSE-1003"

    def __init__(
        self,
        operator_name: str,
        file_path: str | None = None,
        line_number: int | None = None,
    ):
        super().__init__(
            f"Unknown operator: @{operator_name}",
            file_path=file_path,
            line_number=line_number,
            operator=operator_name,
        )


class UnknownActionError(ParseError):
    """Unknown action in rule."""

    code = "PARSE-1004"

    def __init__(
        self,
        action_name: str,
        file_path: str | None = None,
        line_number: int | None = None,
    ):
        super().__init__(
            f"Unknown action: {action_name}",
            file_path=file_path,
            line_number=line_number,
            action=action_name,
        )


# ============================================================================
# Rule Evaluation Errors (RULE-2xxx)
# ============================================================================


class RuleEvaluationError(WAFError):
    """Base class for rule evaluation errors."""

    code = "RULE-2000"
    category = "rule_evaluation"

    def __init__(
        self,
        message: str,
        transaction_id: str | None = None,
        rule_id: int | None = None,
        phase: int | None = None,
        **context: Any,
    ):
        # Extract cause if present in context
        cause = context.pop("cause", None)

        ctx = {
            "transaction_id": transaction_id,
            "rule_id": rule_id,
            "phase": phase,
            **context,
        }
        super().__init__(message, context=ctx, cause=cause)


class OperatorEvaluationError(RuleEvaluationError):
    """Operator evaluation failed."""

    code = "RULE-2001"

    def __init__(
        self,
        operator_name: str,
        message: str,
        transaction_id: str | None = None,
        rule_id: int | None = None,
        variable_name: str | None = None,
        variable_value: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Operator @{operator_name} evaluation failed: {message}",
            transaction_id=transaction_id,
            rule_id=rule_id,
            operator=operator_name,
            variable=variable_name,
            value=variable_value[:100] if variable_value else None,  # Truncate
            cause=cause,
        )


class ActionExecutionError(RuleEvaluationError):
    """Action execution failed."""

    code = "RULE-2002"

    def __init__(
        self,
        action_name: str,
        message: str,
        transaction_id: str | None = None,
        rule_id: int | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Action '{action_name}' execution failed: {message}",
            transaction_id=transaction_id,
            rule_id=rule_id,
            action=action_name,
            cause=cause,
        )


class TransformationError(RuleEvaluationError):
    """Transformation failed."""

    code = "RULE-2003"

    def __init__(
        self,
        transformation_name: str,
        message: str,
        transaction_id: str | None = None,
        rule_id: int | None = None,
        input_value: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Transformation '{transformation_name}' failed: {message}",
            transaction_id=transaction_id,
            rule_id=rule_id,
            transformation=transformation_name,
            input=input_value[:100] if input_value else None,
            cause=cause,
        )


# ============================================================================
# Body Processing Errors (BODY-3xxx)
# ============================================================================


class BodyProcessorError(WAFError):
    """Base class for body processing errors."""

    code = "BODY-3000"
    category = "body_processing"

    def __init__(
        self,
        message: str,
        content_type: str | None = None,
        transaction_id: str | None = None,
        **context: Any,
    ):
        # Extract cause if present in context
        cause = context.pop("cause", None)

        ctx = {
            "content_type": content_type,
            "transaction_id": transaction_id,
            **context,
        }
        super().__init__(message, context=ctx, cause=cause)


class InvalidJSONError(BodyProcessorError):
    """Invalid JSON in request body."""

    code = "BODY-3001"

    def __init__(
        self,
        message: str,
        transaction_id: str | None = None,
        body_snippet: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Invalid JSON: {message}",
            content_type="application/json",
            transaction_id=transaction_id,
            body_snippet=body_snippet,
            cause=cause,
        )


class InvalidXMLError(BodyProcessorError):
    """Invalid XML in request body."""

    code = "BODY-3002"

    def __init__(
        self,
        message: str,
        transaction_id: str | None = None,
        body_snippet: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Invalid XML: {message}",
            content_type="application/xml",
            transaction_id=transaction_id,
            body_snippet=body_snippet,
            cause=cause,
        )


class BodySizeLimitError(BodyProcessorError):
    """Request body exceeds size limit."""

    code = "BODY-3003"

    def __init__(
        self,
        actual_size: int,
        limit: int,
        content_type: str | None = None,
        transaction_id: str | None = None,
    ):
        super().__init__(
            f"Body size {actual_size} exceeds limit {limit}",
            content_type=content_type,
            transaction_id=transaction_id,
            actual_size=actual_size,
            limit=limit,
        )


class InvalidMultipartError(BodyProcessorError):
    """Invalid multipart/form-data."""

    code = "BODY-3004"

    def __init__(
        self,
        message: str,
        transaction_id: str | None = None,
        body_snippet: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Invalid multipart data: {message}",
            content_type="multipart/form-data",
            transaction_id=transaction_id,
            body_snippet=body_snippet,
            cause=cause,
        )


# ============================================================================
# Operator Errors (OP-4xxx)
# ============================================================================


class OperatorError(WAFError):
    """Base class for operator-specific errors."""

    code = "OP-4000"
    category = "operator"


class OperatorNotFoundError(OperatorError):
    """Operator not found in registry."""

    code = "OP-4001"

    def __init__(self, operator_name: str):
        super().__init__(
            f"Operator not found: @{operator_name}",
            context={"operator": operator_name},
        )


class OperatorArgumentError(OperatorError):
    """Invalid operator argument."""

    code = "OP-4002"

    def __init__(self, operator_name: str, message: str, argument: str | None = None):
        super().__init__(
            f"Invalid argument for @{operator_name}: {message}",
            context={"operator": operator_name, "argument": argument},
        )


# ============================================================================
# Integration Errors (INT-5xxx)
# ============================================================================


class IntegrationError(WAFError):
    """Base class for integration errors."""

    code = "INT-5000"
    category = "integration"


class ASGIMiddlewareError(IntegrationError):
    """ASGI middleware error."""

    code = "INT-5001"

    def __init__(
        self,
        message: str,
        transaction_id: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"ASGI middleware error: {message}",
            context={"transaction_id": transaction_id},
            cause=cause,
        )


class RequestProcessingError(IntegrationError):
    """Request processing error."""

    code = "INT-5002"

    def __init__(
        self,
        message: str,
        method: str | None = None,
        uri: str | None = None,
        transaction_id: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Request processing failed: {message}",
            context={
                "transaction_id": transaction_id,
                "method": method,
                "uri": uri,
            },
            cause=cause,
        )


# ============================================================================
# Storage Errors (STORE-6xxx)
# ============================================================================


class StorageError(WAFError):
    """Base class for storage errors."""

    code = "STORE-6000"
    category = "storage"


class StorageBackendError(StorageError):
    """Storage backend operation failed."""

    code = "STORE-6001"

    def __init__(
        self,
        backend_type: str,
        operation: str,
        message: str,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"{backend_type} storage {operation} failed: {message}",
            context={"backend": backend_type, "operation": operation},
            cause=cause,
        )


class CollectionPersistenceError(StorageError):
    """Collection persistence failed."""

    code = "STORE-6002"

    def __init__(
        self,
        collection_name: str,
        message: str,
        transaction_id: str | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Failed to persist collection '{collection_name}': {message}",
            context={
                "collection": collection_name,
                "transaction_id": transaction_id,
            },
            cause=cause,
        )


# ============================================================================
# Proxy Errors (PROXY-7xxx)
# ============================================================================


class ProxyError(WAFError):
    """Base class for proxy errors."""

    code = "PROXY-7000"
    category = "proxy"


class UpstreamRequestError(ProxyError):
    """Upstream request failed."""

    code = "PROXY-7001"

    def __init__(
        self,
        upstream_url: str,
        message: str,
        status_code: int | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(
            f"Upstream request to {upstream_url} failed: {message}",
            context={
                "upstream_url": upstream_url,
                "status_code": status_code,
            },
            cause=cause,
        )


class UpstreamTimeoutError(ProxyError):
    """Upstream request timed out."""

    code = "PROXY-7002"

    def __init__(self, upstream_url: str, timeout: float):
        super().__init__(
            f"Upstream request to {upstream_url} timed out after {timeout}s",
            context={"upstream_url": upstream_url, "timeout": timeout},
        )
