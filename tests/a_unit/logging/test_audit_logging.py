"""Tests for audit logging functionality."""

from __future__ import annotations

import json
import logging

import pytest

from lewaf.integration import WAF
from lewaf.logging import (
    AuditLogger,
    DataMasker,
    JSONFormatter,
    configure_audit_logging,
    get_audit_logger,
    mask_sensitive_data,
)


def test_json_formatter():
    """Test JSON formatter outputs valid JSON."""
    formatter = JSONFormatter()

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Test message",
        args=(),
        exc_info=None,
    )

    output = formatter.format(record)

    # Should be valid JSON
    data = json.loads(output)

    assert data["level"] == "INFO"
    assert data["message"] == "Test message"
    assert "timestamp" in data


def test_json_formatter_with_custom_fields():
    """Test JSON formatter with custom fields."""
    formatter = JSONFormatter()

    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=1,
        msg="Security event",
        args=(),
        exc_info=None,
    )

    # Add custom fields
    record.transaction_id = "tx_123"
    record.event_type = "attack_detected"
    record.rule = {"id": 1001, "msg": "SQL Injection"}

    output = formatter.format(record)
    data = json.loads(output)

    assert data["transaction_id"] == "tx_123"
    assert data["event_type"] == "attack_detected"
    assert data["rule"]["id"] == 1001


def test_data_masker_credit_card():
    """Test credit card masking."""
    masker = DataMasker()

    text = "Credit card: 1234-5678-9012-3456"
    masked = masker.mask_credit_card(text)

    assert "3456" in masked
    assert "1234" not in masked
    assert "****" in masked


def test_data_masker_ssn():
    """Test SSN masking."""
    masker = DataMasker()

    text = "SSN: 123-45-6789"
    masked = masker.mask_ssn(text)

    assert "6789" in masked
    assert "123" not in masked
    assert "***-**" in masked


def test_data_masker_email():
    """Test email masking."""
    masker = DataMasker()

    text = "Email: john.doe@example.com"
    masked = masker.mask_email(text)

    assert "example.com" in masked
    assert "john" not in masked or masked.count("john") == 0


def test_data_masker_password():
    """Test password masking."""
    masker = DataMasker()

    data = {"username": "admin", "password": "secret123"}
    masked = masker.mask(data)

    assert masked["username"] == "admin"
    assert masked["password"] == "[REDACTED]"


def test_data_masker_nested_dict():
    """Test masking nested dictionaries."""
    masker = DataMasker()

    data = {
        "user": {"name": "John", "password": "secret", "card": "1234-5678-9012-3456"},
        "meta": {"ssn": "123-45-6789"},
    }

    masked = masker.mask(data)

    assert masked["user"]["name"] == "John"
    assert masked["user"]["password"] == "[REDACTED]"
    assert "3456" in masked["user"]["card"]
    assert "6789" in masked["meta"]["ssn"]


def test_data_masker_list():
    """Test masking lists."""
    masker = DataMasker()

    data = ["Credit card: 1234-5678-9012-3456", "SSN: 123-45-6789"]

    masked = masker.mask(data)

    assert "3456" in masked[0]
    assert "6789" in masked[1]


def test_data_masker_configuration():
    """Test masker configuration."""
    # Disable email masking
    masker = DataMasker(config={"email": False, "password": True})

    data = {"email": "john@example.com", "password": "secret"}
    masked = masker.mask(data)

    # Email should not be masked
    assert "john@example.com" in str(masked["email"])
    # Password should be masked
    assert masked["password"] == "[REDACTED]"


def test_audit_logger_basic(tmp_path):
    """Test basic audit logger functionality."""
    log_file = tmp_path / "audit.log"

    logger = AuditLogger(output_file=str(log_file), format_type="json")

    logger.log_security_event(
        event_type="test_event",
        transaction_id="tx_test",
        source_ip="192.168.1.1",
        level="INFO",
    )

    # Verify log file created and contains JSON
    assert log_file.exists()
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "test_event"
    assert log_data["transaction_id"] == "tx_test"
    assert log_data["source_ip"] == "192.168.1.1"


def test_audit_logger_attack_detected(tmp_path):
    """Test logging attack detection."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    # Create WAF and transaction
    waf = WAF({"rules": []})
    tx = waf.new_transaction()
    tx.process_uri("/test", "GET")

    logger.log_attack_detected(
        transaction=tx, rule_id=1001, rule_msg="SQL Injection", processing_time_ms=1.23
    )

    # Verify log
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "attack_detected"
    assert log_data["rule"]["id"] == 1001
    assert log_data["rule"]["msg"] == "SQL Injection"
    assert log_data["processing_time_ms"] == 1.23


def test_audit_logger_masking_enabled(tmp_path):
    """Test audit logger with masking enabled."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(
        output_file=str(log_file), format_type="json", mask_sensitive_data=True
    )

    request_data = {
        "method": "POST",
        "body": {"username": "admin", "password": "secret123"},
    }

    logger.log_security_event(
        event_type="login_attempt",
        transaction_id="tx_test",
        request=request_data,
        level="INFO",
    )

    # Verify password is masked
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["request"]["body"]["username"] == "admin"
    assert log_data["request"]["body"]["password"] == "[REDACTED]"


def test_audit_logger_masking_disabled(tmp_path):
    """Test audit logger with masking disabled."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(
        output_file=str(log_file), format_type="json", mask_sensitive_data=False
    )

    request_data = {"username": "admin", "password": "secret123"}

    logger.log_security_event(
        event_type="login_attempt",
        transaction_id="tx_test",
        request=request_data,
        level="INFO",
    )

    # Verify password is NOT masked
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["request"]["password"] == "secret123"


def test_audit_logger_additional_fields(tmp_path):
    """Test audit logger with additional fields."""
    log_file = tmp_path / "audit.log"

    additional = {"environment": "production", "service": "waf", "version": "1.0.0"}

    logger = AuditLogger(
        output_file=str(log_file), format_type="json", additional_fields=additional
    )

    logger.log_security_event(
        event_type="test_event", transaction_id="tx_test", level="INFO"
    )

    # Verify additional fields present
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["environment"] == "production"
    assert log_data["service"] == "waf"
    assert log_data["version"] == "1.0.0"


def test_audit_logger_processing_error(tmp_path):
    """Test logging processing errors."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    logger.log_processing_error(
        transaction_id="tx_error",
        error_type="parse_error",
        error_msg="Invalid JSON body",
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "processing_error"
    assert log_data["error_type"] == "parse_error"
    assert log_data["error_msg"] == "Invalid JSON body"
    assert log_data["level"] == "ERROR"


def test_audit_logger_config_change(tmp_path):
    """Test logging configuration changes."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    logger.log_config_change(
        change_type="rule_added", description="Added SQL injection rule 1001"
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "config_change"
    assert log_data["change_type"] == "rule_added"


def test_configure_global_audit_logging(tmp_path):
    """Test global audit logging configuration."""
    log_file = tmp_path / "global_audit.log"

    logger = configure_audit_logging(
        level="INFO", format_type="json", output=str(log_file)
    )

    assert logger is not None

    # Get global logger
    global_logger = get_audit_logger()
    assert global_logger is logger


def test_mask_sensitive_data_function():
    """Test mask_sensitive_data convenience function."""
    data = {"password": "secret", "username": "admin", "card": "1234-5678-9012-3456"}

    masked = mask_sensitive_data(data)

    assert masked["username"] == "admin"
    assert masked["password"] == "[REDACTED]"
    assert "3456" in masked["card"]


def test_audit_logger_performance_metric(tmp_path):
    """Test logging performance metrics."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json", level="DEBUG")

    logger.log_performance_metric(
        metric_name="request_latency", metric_value=1.23, transaction_id="tx_perf"
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "performance_metric"
    assert log_data["metric_name"] == "request_latency"
    assert log_data["metric_value"] == 1.23


def test_audit_logger_text_format(tmp_path):
    """Test audit logger with text format."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="text")

    logger.log_security_event(
        event_type="test_event", transaction_id="tx_test", level="INFO"
    )

    # Verify log file contains text (not JSON)
    log_content = log_file.read_text()
    assert "test_event" in log_content
    assert "tx_test" in log_content
    # Should not be JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(log_content.strip())


def test_data_masker_ip_address():
    """Test IP address anonymization (GDPR)."""
    masker = DataMasker(config={"ip_address": True})

    text = "IP address: 192.168.1.100"
    masked = masker.mask_ip_address(text)

    assert "192.168.1.0/24" in masked
    assert "192.168.1.100" not in masked


def test_data_masker_auth_token():
    """Test authentication token masking."""
    masker = DataMasker(config={"auth_token": True})

    text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    masked = masker.mask_auth_token(text)

    assert "eyJhbGci" in masked
    assert "[REDACTED]" in masked


def test_audit_logger_request_allowed(tmp_path):
    """Test logging allowed requests."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    waf = WAF({"rules": []})
    tx = waf.new_transaction()
    tx.process_uri("/api/users", "GET")

    logger.log_request_allowed(transaction=tx, processing_time_ms=0.5)

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "request_allowed"
    assert log_data["action"] == "allow"
    assert log_data["level"] == "INFO"


def test_multiple_log_entries(tmp_path):
    """Test multiple log entries in same file."""
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    # Log multiple events
    for i in range(5):
        logger.log_security_event(
            event_type="test_event",
            transaction_id=f"tx_{i}",
            level="INFO",
        )

    # Verify all entries logged
    log_content = log_file.read_text()
    log_lines = [line for line in log_content.strip().split("\n") if line]

    assert len(log_lines) == 5

    for i, line in enumerate(log_lines):
        data = json.loads(line)
        assert data["transaction_id"] == f"tx_{i}"
