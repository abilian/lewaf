"""Tests for LeWAF exception hierarchy and error handling."""

from __future__ import annotations

import re

from lewaf.exceptions import (
    ActionExecutionError,
    ASGIMiddlewareError,
    BodyProcessorError,
    BodySizeLimitError,
    CollectionPersistenceError,
    ConfigFileNotFoundError,
    ConfigurationError,
    ConfigValidationError,
    EnvironmentVariableError,
    IncludeRecursionError,
    IntegrationError,
    InvalidJSONError,
    InvalidMultipartError,
    InvalidXMLError,
    OperatorArgumentError,
    OperatorError,
    OperatorEvaluationError,
    OperatorNotFoundError,
    ParseError,
    ProxyError,
    RequestProcessingError,
    RuleEvaluationError,
    SecRuleParseError,
    StorageBackendError,
    StorageError,
    TransformationError,
    UnknownActionError,
    UnknownOperatorError,
    UpstreamRequestError,
    UpstreamTimeoutError,
    WAFError,
)

# ============================================================================
# Base Exception Tests
# ============================================================================


def test_waf_error_basic():
    """Test basic WAFError creation."""
    error = WAFError("Test error")
    assert str(error) == "[WAF-0000] Test error"
    assert error.code == "WAF-0000"
    assert error.category == "general"
    assert error.message == "Test error"
    assert error.context == {}


def test_waf_error_with_context():
    """Test WAFError with context."""
    error = WAFError("Test error", context={"key": "value", "num": 42})
    assert "key=value" in str(error)
    assert "num=42" in str(error)
    assert error.context["key"] == "value"
    assert error.context["num"] == 42


def test_waf_error_with_cause():
    """Test WAFError with wrapped exception."""
    original = ValueError("Original error")
    error = WAFError("Wrapped error", cause=original)
    assert error.cause == original
    assert error.to_dict()["cause"] == "Original error"


def test_waf_error_to_dict():
    """Test WAFError serialization to dict."""
    error = WAFError("Test error", context={"transaction_id": "tx-123"})
    error_dict = error.to_dict()

    assert error_dict["error_code"] == "WAF-0000"
    assert error_dict["error_category"] == "general"
    assert error_dict["message"] == "Test error"
    assert error_dict["context"]["transaction_id"] == "tx-123"
    assert "timestamp" in error_dict
    assert error_dict["cause"] is None


def test_waf_error_timestamp():
    """Test that errors have timestamps."""
    error = WAFError("Test")
    assert error.timestamp is not None
    assert error.to_dict()["timestamp"]


# ============================================================================
# Configuration Error Tests
# ============================================================================


def test_configuration_error():
    """Test ConfigurationError."""
    error = ConfigurationError("Config failed")
    assert error.code == "WAF-0001"
    assert error.category == "configuration"


def test_config_file_not_found_error():
    """Test ConfigFileNotFoundError."""
    error = ConfigFileNotFoundError("/path/to/config.yaml")
    assert error.code == "WAF-0002"
    assert "config.yaml" in error.message
    assert error.context["file_path"] == "/path/to/config.yaml"


def test_config_validation_error():
    """Test ConfigValidationError."""
    errors = ["Field 'engine' is required", "Invalid value for 'port'"]
    error = ConfigValidationError("Validation failed", errors=errors, field="engine")
    assert error.code == "WAF-0003"
    assert error.context["errors"] == errors
    assert error.context["field"] == "engine"


def test_environment_variable_error():
    """Test EnvironmentVariableError."""
    error = EnvironmentVariableError("DATABASE_URL")
    assert error.code == "WAF-0004"
    assert "DATABASE_URL" in error.message
    assert error.context["variable"] == "DATABASE_URL"


# ============================================================================
# Parsing Error Tests
# ============================================================================


def test_parse_error():
    """Test ParseError base class."""
    error = ParseError("Parse failed", file_path="rules.conf", line_number=42)
    assert error.code == "PARSE-1000"
    assert error.category == "parsing"
    assert error.context["file"] == "rules.conf"
    assert error.context["line"] == 42


def test_sec_rule_parse_error():
    """Test SecRuleParseError."""
    rule = 'SecRule ARGS "@rx [invalid" "id:1,deny"'
    error = SecRuleParseError(
        "Invalid regex", rule_text=rule, file_path="crs.conf", line_number=100
    )
    assert error.code == "PARSE-1001"
    assert error.context["file"] == "crs.conf"
    assert error.context["line"] == 100
    assert error.context["rule_text"] is not None


def test_sec_rule_parse_error_truncates_long_rules():
    """Test that long rules are truncated in context."""
    long_rule = "SecRule ARGS " + "x" * 200
    error = SecRuleParseError("Invalid", rule_text=long_rule)
    assert len(error.context["rule_text"]) == 100


def test_include_recursion_error():
    """Test IncludeRecursionError."""
    error = IncludeRecursionError("recursive.conf", depth=11, max_depth=10)
    assert error.code == "PARSE-1002"
    assert error.context["depth"] == 11
    assert error.context["max_depth"] == 10


def test_unknown_operator_error():
    """Test UnknownOperatorError."""
    error = UnknownOperatorError("invalidOp", file_path="rules.conf", line_number=50)
    assert error.code == "PARSE-1003"
    assert "@invalidOp" in error.message
    assert error.context["operator"] == "invalidOp"


def test_unknown_action_error():
    """Test UnknownActionError."""
    error = UnknownActionError("invalidAction", file_path="rules.conf", line_number=60)
    assert error.code == "PARSE-1004"
    assert "invalidAction" in error.message
    assert error.context["action"] == "invalidAction"


# ============================================================================
# Rule Evaluation Error Tests
# ============================================================================


def test_rule_evaluation_error():
    """Test RuleEvaluationError base class."""
    error = RuleEvaluationError(
        "Evaluation failed", transaction_id="tx-123", rule_id=1001, phase=2
    )
    assert error.code == "RULE-2000"
    assert error.category == "rule_evaluation"
    assert error.context["transaction_id"] == "tx-123"
    assert error.context["rule_id"] == 1001
    assert error.context["phase"] == 2


def test_operator_evaluation_error():
    """Test OperatorEvaluationError."""
    error = OperatorEvaluationError(
        operator_name="rx",
        message="Invalid regex pattern",
        transaction_id="tx-456",
        rule_id=2001,
        variable_name="ARGS:id",
        variable_value="test-value",
    )
    assert error.code == "RULE-2001"
    assert "@rx" in error.message
    assert error.context["operator"] == "rx"
    assert error.context["variable"] == "ARGS:id"
    assert error.context["value"] == "test-value"


def test_operator_evaluation_error_truncates_long_values():
    """Test that long values are truncated."""
    long_value = "x" * 200
    error = OperatorEvaluationError(
        "rx", "Failed", variable_name="ARGS", variable_value=long_value
    )
    assert len(error.context["value"]) == 100


def test_action_execution_error():
    """Test ActionExecutionError."""
    cause = ValueError("Invalid value")
    error = ActionExecutionError(
        action_name="setvar",
        message="Failed to set variable",
        transaction_id="tx-789",
        rule_id=3001,
        cause=cause,
    )
    assert error.code == "RULE-2002"
    assert "setvar" in error.message
    assert error.context["action"] == "setvar"
    assert error.cause == cause


def test_transformation_error():
    """Test TransformationError."""
    error = TransformationError(
        transformation_name="base64Decode",
        message="Invalid base64",
        transaction_id="tx-abc",
        rule_id=4001,
        input_value="invalid!!",
    )
    assert error.code == "RULE-2003"
    assert "base64Decode" in error.message
    assert error.context["transformation"] == "base64Decode"
    assert error.context["input"] == "invalid!!"


# ============================================================================
# Body Processing Error Tests
# ============================================================================


def test_body_processor_error():
    """Test BodyProcessorError base class."""
    error = BodyProcessorError(
        "Processing failed", content_type="application/json", transaction_id="tx-body"
    )
    assert error.code == "BODY-3000"
    assert error.category == "body_processing"
    assert error.context["content_type"] == "application/json"


def test_invalid_json_error():
    """Test InvalidJSONError."""
    cause = ValueError("Expecting value")
    error = InvalidJSONError(
        "Unexpected token",
        transaction_id="tx-json",
        body_snippet='{"incomplete":',
        cause=cause,
    )
    assert error.code == "BODY-3001"
    assert "Invalid JSON" in error.message
    assert error.context["content_type"] == "application/json"
    assert error.context["body_snippet"] == '{"incomplete":'


def test_invalid_xml_error():
    """Test InvalidXMLError."""
    error = InvalidXMLError(
        "Unclosed tag", transaction_id="tx-xml", body_snippet="<root>"
    )
    assert error.code == "BODY-3002"
    assert "Invalid XML" in error.message
    assert error.context["content_type"] == "application/xml"


def test_body_size_limit_error():
    """Test BodySizeLimitError."""
    error = BodySizeLimitError(
        actual_size=2000000,
        limit=1000000,
        content_type="application/json",
        transaction_id="tx-large",
    )
    assert error.code == "BODY-3003"
    assert "2000000" in error.message
    assert "1000000" in error.message
    assert error.context["actual_size"] == 2000000
    assert error.context["limit"] == 1000000


def test_invalid_multipart_error():
    """Test InvalidMultipartError."""
    error = InvalidMultipartError("Missing boundary", transaction_id="tx-multipart")
    assert error.code == "BODY-3004"
    assert "Invalid multipart" in error.message
    assert error.context["content_type"] == "multipart/form-data"


# ============================================================================
# Operator Error Tests
# ============================================================================


def test_operator_error():
    """Test OperatorError base class."""
    error = OperatorError("Operator failed")
    assert error.code == "OP-4000"
    assert error.category == "operator"


def test_operator_not_found_error():
    """Test OperatorNotFoundError."""
    error = OperatorNotFoundError("customOp")
    assert error.code == "OP-4001"
    assert "@customOp" in error.message
    assert error.context["operator"] == "customOp"


def test_operator_argument_error():
    """Test OperatorArgumentError."""
    error = OperatorArgumentError(
        operator_name="within", message="Expected integer", argument="abc"
    )
    assert error.code == "OP-4002"
    assert "@within" in error.message
    assert error.context["operator"] == "within"
    assert error.context["argument"] == "abc"


# ============================================================================
# Integration Error Tests
# ============================================================================


def test_integration_error():
    """Test IntegrationError base class."""
    error = IntegrationError("Integration failed")
    assert error.code == "INT-5000"
    assert error.category == "integration"


def test_asgi_middleware_error():
    """Test ASGIMiddlewareError."""
    cause = RuntimeError("ASGI error")
    error = ASGIMiddlewareError("Request failed", transaction_id="tx-asgi", cause=cause)
    assert error.code == "INT-5001"
    assert "ASGI middleware" in error.message
    assert error.cause == cause


def test_request_processing_error():
    """Test RequestProcessingError."""
    error = RequestProcessingError(
        "Processing failed",
        method="POST",
        uri="/api/users",
        transaction_id="tx-req",
    )
    assert error.code == "INT-5002"
    assert error.context["method"] == "POST"
    assert error.context["uri"] == "/api/users"


# ============================================================================
# Storage Error Tests
# ============================================================================


def test_storage_error():
    """Test StorageError base class."""
    error = StorageError("Storage failed")
    assert error.code == "STORE-6000"
    assert error.category == "storage"


def test_storage_backend_error():
    """Test StorageBackendError."""
    cause = ConnectionError("Redis connection failed")
    error = StorageBackendError(
        backend_type="redis", operation="get", message="Connection lost", cause=cause
    )
    assert error.code == "STORE-6001"
    assert "redis" in error.message
    assert "get" in error.message
    assert error.context["backend"] == "redis"
    assert error.context["operation"] == "get"


def test_collection_persistence_error():
    """Test CollectionPersistenceError."""
    error = CollectionPersistenceError(
        collection_name="IP",
        message="Write failed",
        transaction_id="tx-persist",
    )
    assert error.code == "STORE-6002"
    assert "IP" in error.message
    assert error.context["collection"] == "IP"


# ============================================================================
# Proxy Error Tests
# ============================================================================


def test_proxy_error():
    """Test ProxyError base class."""
    error = ProxyError("Proxy failed")
    assert error.code == "PROXY-7000"
    assert error.category == "proxy"


def test_upstream_request_error():
    """Test UpstreamRequestError."""
    error = UpstreamRequestError(
        upstream_url="http://backend:8080",
        message="Connection refused",
        status_code=502,
    )
    assert error.code == "PROXY-7001"
    assert "http://backend:8080" in error.message
    assert error.context["upstream_url"] == "http://backend:8080"
    assert error.context["status_code"] == 502


def test_upstream_timeout_error():
    """Test UpstreamTimeoutError."""
    error = UpstreamTimeoutError("http://slow-backend:8080", timeout=30.0)
    assert error.code == "PROXY-7002"
    assert "30" in error.message
    assert error.context["timeout"] == 30.0


# ============================================================================
# Inheritance Tests
# ============================================================================


def test_exception_inheritance():
    """Test that all exceptions inherit from WAFError."""
    exceptions = [
        ConfigurationError,
        ParseError,
        RuleEvaluationError,
        BodyProcessorError,
        OperatorError,
        IntegrationError,
        StorageError,
        ProxyError,
    ]
    for exc_class in exceptions:
        assert issubclass(exc_class, WAFError)


def test_exception_hierarchy():
    """Test specific exception inheritance."""
    assert issubclass(ConfigFileNotFoundError, ConfigurationError)
    assert issubclass(SecRuleParseError, ParseError)
    assert issubclass(OperatorEvaluationError, RuleEvaluationError)
    assert issubclass(InvalidJSONError, BodyProcessorError)
    assert issubclass(StorageBackendError, StorageError)


# ============================================================================
# Error Code Uniqueness Tests
# ============================================================================


def test_error_codes_are_unique():
    """Test that all error codes are unique."""
    exceptions = [
        WAFError,
        ConfigurationError,
        ConfigFileNotFoundError,
        ConfigValidationError,
        EnvironmentVariableError,
        ParseError,
        SecRuleParseError,
        IncludeRecursionError,
        UnknownOperatorError,
        UnknownActionError,
        RuleEvaluationError,
        OperatorEvaluationError,
        ActionExecutionError,
        TransformationError,
        BodyProcessorError,
        InvalidJSONError,
        InvalidXMLError,
        BodySizeLimitError,
        InvalidMultipartError,
        OperatorError,
        OperatorNotFoundError,
        OperatorArgumentError,
        IntegrationError,
        ASGIMiddlewareError,
        RequestProcessingError,
        StorageError,
        StorageBackendError,
        CollectionPersistenceError,
        ProxyError,
        UpstreamRequestError,
        UpstreamTimeoutError,
    ]

    codes = [exc.code for exc in exceptions]
    assert len(codes) == len(set(codes)), "Duplicate error codes found"


def test_error_code_format():
    """Test that error codes follow the expected format."""
    exceptions = [
        ConfigFileNotFoundError,
        SecRuleParseError,
        OperatorEvaluationError,
        InvalidJSONError,
        StorageBackendError,
    ]

    # Error codes should be CATEGORY-NNNN format
    pattern = re.compile(r"^[A-Z]+-\d{4}$")

    for exc_class in exceptions:
        assert pattern.match(exc_class.code), f"Invalid format: {exc_class.code}"
