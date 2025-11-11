"""Integration tests for audit logging with WAF."""

import json


from lewaf.integration import WAF
from lewaf.logging import AuditLogger, configure_audit_logging, get_audit_logger


def test_log_attack_detection(tmp_path):
    """Test logging attack detection with real WAF transaction."""
    log_file = tmp_path / "attacks.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    # Create WAF with XSS rule
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS Attack Detected\'"',
            ]
        }
    )

    # Process malicious request
    tx = waf.new_transaction()
    tx.process_uri("/search?q=<script>alert('xss')</script>", "GET")

    result = tx.process_request_body()

    # Should be blocked
    assert result is not None
    assert result["action"] == "deny"

    # Log the attack
    logger.log_attack_detected(
        transaction=tx,
        rule_id=1001,
        rule_msg="XSS Attack Detected",
        processing_time_ms=1.5,
    )

    # Verify log
    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "attack_detected"
    assert log_data["rule"]["id"] == 1001
    assert log_data["rule"]["msg"] == "XSS Attack Detected"
    assert log_data["request"]["method"] == "GET"
    assert "/search" in log_data["request"]["uri"]
    assert log_data["action"] == "deny"
    assert log_data["processing_time_ms"] == 1.5


def test_log_sql_injection_attack(tmp_path):
    """Test logging SQL injection attack."""
    log_file = tmp_path / "sql_attacks.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx (union.*select|select.*from)" "id:1002,phase:2,deny,msg:\'SQL Injection\'"',
            ]
        }
    )

    tx = waf.new_transaction()
    tx.process_uri("/users?id=1' union select * from passwords--", "GET")

    result = tx.process_request_body()

    assert result is not None

    logger.log_attack_detected(
        transaction=tx, rule_id=1002, rule_msg="SQL Injection", processing_time_ms=2.0
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "attack_detected"
    assert log_data["rule"]["id"] == 1002
    assert log_data["rule"]["msg"] == "SQL Injection"


def test_log_legitimate_request(tmp_path):
    """Test logging legitimate requests."""
    log_file = tmp_path / "allowed.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json", level="INFO")

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/users?page=1&limit=10", "GET")

    result = tx.process_request_body()

    # Should be allowed
    assert result is None

    # Log the allowed request
    logger.log_request_allowed(transaction=tx, processing_time_ms=0.5)

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "request_allowed"
    assert log_data["action"] == "allow"
    assert log_data["level"] == "INFO"
    assert log_data["request"]["method"] == "GET"
    assert "/api/users" in log_data["request"]["uri"]


def test_multiple_attacks_logged(tmp_path):
    """Test logging multiple attack attempts."""
    log_file = tmp_path / "multi_attacks.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    waf = WAF(
        {
            "rules": [
                'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS\'"',
                'SecRule ARGS "@rx union.*select" "id:1002,phase:2,deny,msg:\'SQLi\'"',
            ]
        }
    )

    # Attack 1: XSS
    tx1 = waf.new_transaction()
    tx1.process_uri("/search?q=<script>alert(1)</script>", "GET")
    result1 = tx1.process_request_body()
    assert result1 is not None
    logger.log_attack_detected(transaction=tx1, rule_id=1001, rule_msg="XSS")

    # Attack 2: SQL Injection
    tx2 = waf.new_transaction()
    tx2.process_uri("/users?id=1 union select null", "GET")
    result2 = tx2.process_request_body()
    assert result2 is not None
    logger.log_attack_detected(transaction=tx2, rule_id=1002, rule_msg="SQLi")

    # Verify both attacks logged
    log_content = log_file.read_text()
    log_lines = [line for line in log_content.strip().split("\n") if line]

    assert len(log_lines) == 2

    log1 = json.loads(log_lines[0])
    log2 = json.loads(log_lines[1])

    assert log1["rule"]["id"] == 1001
    assert log2["rule"]["id"] == 1002


def test_post_request_with_body_logging(tmp_path):
    """Test logging POST request with body."""
    log_file = tmp_path / "post_attacks.log"
    logger = AuditLogger(
        output_file=str(log_file), format_type="json", mask_sensitive_data=True
    )

    waf = WAF(
        {
            "rules": [
                'SecRule ARGS_POST "@rx <script" "id:1003,phase:2,deny,msg:\'POST XSS\'"',
            ]
        }
    )

    tx = waf.new_transaction()
    tx.process_uri("/comment", "POST")
    tx.add_request_body(
        b"text=<script>alert('xss')</script>", "application/x-www-form-urlencoded"
    )

    result = tx.process_request_body()

    assert result is not None

    logger.log_attack_detected(transaction=tx, rule_id=1003, rule_msg="POST XSS")

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["rule"]["id"] == 1003
    assert log_data["request"]["method"] == "POST"


def test_global_logger_integration(tmp_path):
    """Test global logger configuration and usage."""
    log_file = tmp_path / "global.log"

    # Configure global logger
    logger = configure_audit_logging(
        level="INFO", format_type="json", output=str(log_file)
    )

    # Create WAF
    waf = WAF({"rules": []})

    # Use global logger from anywhere
    global_logger = get_audit_logger()
    assert global_logger is logger

    tx = waf.new_transaction()
    tx.process_uri("/api/health", "GET")

    global_logger.log_request_allowed(transaction=tx, processing_time_ms=0.2)

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "request_allowed"


def test_masking_in_attack_logs(tmp_path):
    """Test sensitive data masking in attack logs."""
    log_file = tmp_path / "masked_attacks.log"
    logger = AuditLogger(
        output_file=str(log_file), format_type="json", mask_sensitive_data=True
    )

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/login", "POST")
    tx.add_request_body(
        b'{"username": "admin", "password": "secret123"}', "application/json"
    )

    # Log as allowed (no attacks in this test)
    logger.log_security_event(
        event_type="login_attempt",
        transaction_id=tx.id,
        request={
            "method": "POST",
            "uri": "/api/login",
            "body": {"username": "admin", "password": "secret123"},
        },
        level="INFO",
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    # Password should be masked
    assert log_data["request"]["body"]["username"] == "admin"
    assert log_data["request"]["body"]["password"] == "[REDACTED]"


def test_performance_metrics_logging(tmp_path):
    """Test performance metrics logging."""
    log_file = tmp_path / "performance.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json", level="DEBUG")

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/data", "GET")

    # Log performance metric
    logger.log_performance_metric(
        metric_name="rule_evaluation_time",
        metric_value=1.23,
        transaction_id=tx.id,
        phase=2,
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "performance_metric"
    assert log_data["metric_name"] == "rule_evaluation_time"
    assert log_data["metric_value"] == 1.23


def test_additional_fields_in_logs(tmp_path):
    """Test additional fields configuration."""
    log_file = tmp_path / "with_metadata.log"
    logger = AuditLogger(
        output_file=str(log_file),
        format_type="json",
        additional_fields={"environment": "production", "datacenter": "us-east-1"},
    )

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/test", "GET")

    logger.log_request_allowed(transaction=tx, processing_time_ms=0.3)

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["environment"] == "production"
    assert log_data["datacenter"] == "us-east-1"


def test_error_logging_with_waf(tmp_path):
    """Test error logging during WAF processing."""
    log_file = tmp_path / "errors.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/submit", "POST")

    # Simulate a processing error
    logger.log_processing_error(
        transaction_id=tx.id,
        error_type="body_parse_error",
        error_msg="Failed to parse request body",
        uri="/api/submit",
    )

    log_content = log_file.read_text()
    log_data = json.loads(log_content.strip())

    assert log_data["event_type"] == "processing_error"
    assert log_data["error_type"] == "body_parse_error"
    assert log_data["level"] == "ERROR"


def test_attack_with_multiple_phases(tmp_path):
    """Test logging attacks detected in different phases."""
    log_file = tmp_path / "phases.log"
    logger = AuditLogger(output_file=str(log_file), format_type="json")

    waf = WAF(
        {
            "rules": [
                'SecRule REQUEST_URI "@rx /admin" "id:1001,phase:1,deny,msg:\'Admin Access\'"',
                'SecRule ARGS "@rx <script" "id:1002,phase:2,deny,msg:\'XSS\'"',
            ]
        }
    )

    # Phase 1 attack (URI)
    tx1 = waf.new_transaction()
    tx1.process_uri("/admin/users", "GET")
    result1 = tx1.process_request_headers()

    if result1:
        logger.log_attack_detected(
            transaction=tx1, rule_id=1001, rule_msg="Admin Access"
        )

    # Phase 2 attack (Args)
    tx2 = waf.new_transaction()
    tx2.process_uri("/search?q=<script>alert(1)</script>", "GET")
    result2 = tx2.process_request_body()

    if result2:
        logger.log_attack_detected(transaction=tx2, rule_id=1002, rule_msg="XSS")

    log_content = log_file.read_text()
    log_lines = [line for line in log_content.strip().split("\n") if line]

    assert len(log_lines) == 2

    log1 = json.loads(log_lines[0])
    log2 = json.loads(log_lines[1])

    assert log1["rule"]["phase"] == 1
    assert log2["rule"]["phase"] == 2
