"""Example: Integrating audit logging with lewaf WAF.

This example demonstrates how to integrate the audit logging system
with lewaf for comprehensive security event logging.
"""

from __future__ import annotations

import time

from lewaf.integration import WAF
from lewaf.logging import AuditLogger, configure_audit_logging


def basic_audit_logging_example():
    """Basic example: Log security events to a file."""
    # Configure audit logging
    logger = AuditLogger(
        output_file="waf_audit.log",
        format_type="json",
        mask_sensitive_data=True,
        additional_fields={
            "environment": "production",
            "service": "api-gateway",
            "version": "1.0.0",
        },
    )

    # Create WAF with rules
    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS Attack\'"',
            'SecRule ARGS "@rx (union.*select|select.*from)" "id:1002,phase:2,deny,msg:\'SQL Injection\'"',
        ]
    })

    # Process a legitimate request
    tx = waf.new_transaction()
    tx.process_uri("/api/users?page=1", "GET")

    result = tx.process_request_body()

    if result:
        # Attack detected - log it
        logger.log_attack_detected(
            transaction=tx,
            rule_id=result.get("rule_id", 0),
            rule_msg=result.get("msg", "Unknown"),
            processing_time_ms=0.5,
        )
    else:
        # Request allowed - log it
        logger.log_request_allowed(transaction=tx, processing_time_ms=0.3)


def attack_detection_example():
    """Example: Detect and log attacks."""
    logger = AuditLogger(output_file="attacks.log", format_type="json")

    waf = WAF({
        "rules": [
            'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS Attack\'"',
        ]
    })

    # Malicious request with XSS payload
    tx = waf.new_transaction()
    tx.process_uri("/search?q=<script>alert('xss')</script>", "GET")

    result = tx.process_request_body()

    if result:
        # Log the attack
        logger.log_attack_detected(
            transaction=tx,
            rule_id=result.get("rule_id", 0),
            rule_msg=result.get("msg", "Unknown"),
            processing_time_ms=1.2,
        )
        print("Attack detected and logged!")


def global_logging_configuration():
    """Example: Configure global audit logging."""
    # Configure global logger (used throughout application)
    configure_audit_logging(
        level="INFO",
        format_type="json",
        output="waf_global.log",
        mask_sensitive=True,
        additional_fields={"datacenter": "us-east-1", "cluster": "prod-web"},
    )

    waf = WAF({"rules": []})

    # The global logger can be used from anywhere
    from lewaf.logging import get_audit_logger  # noqa: PLC0415 - Avoids circular import

    logger = get_audit_logger()

    tx = waf.new_transaction()
    tx.process_uri("/api/health", "GET")

    logger.log_request_allowed(transaction=tx, processing_time_ms=0.1)


def performance_monitoring_example():
    """Example: Monitor WAF performance."""
    logger = AuditLogger(
        output_file="performance.log", format_type="json", level="DEBUG"
    )

    waf = WAF({"rules": []})

    # Process request and measure time
    start_time = time.perf_counter()

    tx = waf.new_transaction()
    tx.process_uri("/api/data", "GET")
    tx.process_request_body()

    processing_time = (time.perf_counter() - start_time) * 1000  # Convert to ms

    # Log performance metric
    logger.log_performance_metric(
        metric_name="request_processing_time",
        metric_value=processing_time,
        transaction_id=tx.id,
        uri="/api/data",
        method="GET",
    )


def configuration_change_example():
    """Example: Log configuration changes."""
    logger = AuditLogger(output_file="config_audit.log", format_type="json")

    # Log when rules are added/modified
    logger.log_config_change(
        change_type="rule_added",
        description="Added XSS protection rule 1001",
        rule_id=1001,
        user="admin",
        timestamp=1234567890,
    )

    # Create WAF with the new rule
    _waf = WAF({
        "rules": [
            'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS Attack\'"',
        ]
    })

    print("Configuration change logged!")


def error_logging_example():
    """Example: Log processing errors."""
    logger = AuditLogger(output_file="errors.log", format_type="json")

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/submit", "POST")

    # Add malformed JSON body
    tx.add_request_body(b"{invalid json}", "application/json")

    try:
        tx.process_request_body()
    except Exception as e:
        # Log the processing error
        logger.log_processing_error(
            transaction_id=tx.id,
            error_type="json_parse_error",
            error_msg=str(e),
            uri="/api/submit",
            method="POST",
        )


def sensitive_data_masking_example():
    """Example: Demonstrate sensitive data masking."""
    # Enable masking for PCI-DSS compliance
    logger = AuditLogger(
        output_file="masked_audit.log", format_type="json", mask_sensitive_data=True
    )

    waf = WAF({"rules": []})

    tx = waf.new_transaction()
    tx.process_uri("/api/payment", "POST")

    # Add request with sensitive data
    tx.add_request_body(
        b'{"card": "4532-1234-5678-9012", "password": "secret123"}',
        "application/json",
    )

    # When logged, sensitive data will be masked:
    # - Card number: ****-****-****-9012
    # - Password: [REDACTED]
    logger.log_request_allowed(transaction=tx, processing_time_ms=0.8)


if __name__ == "__main__":
    print("Running audit logging examples...\n")

    print("1. Basic audit logging")
    basic_audit_logging_example()

    print("\n2. Attack detection")
    attack_detection_example()

    print("\n3. Global logging configuration")
    global_logging_configuration()

    print("\n4. Performance monitoring")
    performance_monitoring_example()

    print("\n5. Configuration change logging")
    configuration_change_example()

    print("\n6. Error logging")
    error_logging_example()

    print("\n7. Sensitive data masking")
    sensitive_data_masking_example()

    print("\nAll examples completed! Check the log files for output.")
