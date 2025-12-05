"""Tests for structured error logging."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from lewaf.exceptions import InvalidJSONError
from lewaf.logging.error_logger import (
    log_body_processing_error,
    log_error,
    log_operator_error,
    log_storage_error,
    log_transformation_error,
)


def test_log_error_with_waf_error(caplog):
    """Test logging a WAFError with full context."""
    caplog.set_level(logging.ERROR)

    error = InvalidJSONError(
        "Invalid JSON syntax",
        transaction_id="tx-123",
        body_snippet='{"incomplete":',
    )

    log_error(error)

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.ERROR
    assert "BODY-3001" in record.message
    assert "Invalid JSON syntax" in record.message

    # Check structured data
    assert "structured_data" in record.__dict__
    data = record.__dict__["structured_data"]
    assert data["error_code"] == "BODY-3001"
    assert data["error_category"] == "body_processing"
    assert data["context"]["transaction_id"] == "tx-123"


def test_log_error_with_regular_exception(caplog):
    """Test logging a regular Python exception."""
    caplog.set_level(logging.ERROR)

    error = ValueError("Invalid value")
    log_error(error, user_id="123")

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert "Invalid value" in record.message

    data = record.__dict__["structured_data"]
    assert data["error_type"] == "ValueError"
    assert data["user_id"] == "123"


def test_log_operator_error(caplog):
    """Test logging an operator evaluation error."""
    caplog.set_level(logging.WARNING)

    log_operator_error(
        operator_name="rx",
        error=ValueError("Invalid regex"),
        value="test-input-value",
        transaction_id="tx-456",
        rule_id=1001,
        phase=2,
        variable_name="ARGS:id",
    )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert "@rx" in record.message
    assert "ValueError" in record.message

    data = record.__dict__["structured_data"]
    assert data["operator"] == "rx"
    assert data["transaction_id"] == "tx-456"
    assert data["rule_id"] == 1001
    assert data["phase"] == 2
    assert data["variable"] == "ARGS:id"
    assert data["value"] == "test-input-value"


def test_log_operator_error_truncates_long_values(caplog):
    """Test that long values are truncated in operator error logs."""
    caplog.set_level(logging.WARNING)

    long_value = "x" * 200

    log_operator_error(
        operator_name="contains",
        error=ValueError("Test error"),
        value=long_value,
    )

    assert len(caplog.records) == 1
    data = caplog.records[0].__dict__["structured_data"]
    assert len(data["value"]) == 100
    assert data["value_length"] == 200


def test_log_transformation_error(caplog):
    """Test logging a transformation error."""
    caplog.set_level(logging.WARNING)

    log_transformation_error(
        transformation_name="base64Decode",
        error=ValueError("Invalid base64"),
        input_value="not-valid-base64!!",
        transaction_id="tx-789",
        rule_id=2001,
    )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert "base64Decode" in record.message
    assert "ValueError" in record.message

    data = record.__dict__["structured_data"]
    assert data["transformation"] == "base64Decode"
    assert data["transaction_id"] == "tx-789"
    assert data["rule_id"] == 2001
    assert data["input"] == "not-valid-base64!!"


def test_log_storage_error(caplog):
    """Test logging a storage backend error."""
    caplog.set_level(logging.ERROR)

    log_storage_error(
        backend_type="redis",
        operation="set",
        error=ConnectionError("Redis connection failed"),
        collection_name="IP",
        key="blocked_ips",
    )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.ERROR
    assert "redis" in record.message
    assert "set" in record.message

    data = record.__dict__["structured_data"]
    assert data["backend"] == "redis"
    assert data["operation"] == "set"
    assert data["collection"] == "IP"
    assert data["key"] == "blocked_ips"
    assert data["exception"] == "ConnectionError"


def test_log_body_processing_error(caplog):
    """Test logging a body processing error."""
    caplog.set_level(logging.ERROR)

    log_body_processing_error(
        content_type="application/json",
        error=ValueError("Invalid JSON"),
        body_size=1024,
        transaction_id="tx-abc",
    )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.ERROR
    assert "application/json" in record.message
    assert "1024" in record.message

    data = record.__dict__["structured_data"]
    assert data["content_type"] == "application/json"
    assert data["body_size"] == 1024
    assert data["transaction_id"] == "tx-abc"


def test_log_error_custom_logger():
    """Test using a custom logger."""
    mock_logger = MagicMock(spec=logging.Logger)

    error = ValueError("Test error")
    log_error(error, log=mock_logger, level=logging.WARNING)

    # Verify the custom logger was called
    assert mock_logger.log.called
    call_args = mock_logger.log.call_args
    assert call_args[0][0] == logging.WARNING  # First arg is the level


def test_log_operator_error_without_optional_context(caplog):
    """Test operator error logging with minimal context."""
    caplog.set_level(logging.WARNING)

    log_operator_error(
        operator_name="eq",
        error=ValueError("Test"),
        value="test",
    )

    assert len(caplog.records) == 1
    data = caplog.records[0].__dict__["structured_data"]
    assert data["operator"] == "eq"
    assert "transaction_id" not in data
    assert "rule_id" not in data
    assert "phase" not in data


def test_log_transformation_error_truncates_long_input(caplog):
    """Test that long input values are truncated in transformation error logs."""
    caplog.set_level(logging.WARNING)

    long_input = "y" * 200

    log_transformation_error(
        transformation_name="urlDecode",
        error=ValueError("Test"),
        input_value=long_input,
    )

    assert len(caplog.records) == 1
    data = caplog.records[0].__dict__["structured_data"]
    assert len(data["input"]) == 100
    assert data["input_length"] == 200


def test_structured_data_includes_timestamp(caplog):
    """Test that all logged errors include timestamps."""
    caplog.set_level(logging.WARNING)

    log_operator_error(
        operator_name="test",
        error=ValueError("test"),
        value="test",
    )

    assert len(caplog.records) == 1
    data = caplog.records[0].__dict__["structured_data"]
    assert "timestamp" in data
    # Check it's in ISO format
    assert "T" in data["timestamp"]
    assert "Z" in data["timestamp"] or "+" in data["timestamp"]
