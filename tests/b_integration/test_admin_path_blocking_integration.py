"""Integration tests for admin path blocking with WAF instance.

This module tests the complete WAF flow: rule parsing, transaction processing,
and request blocking for admin paths.
"""

import pytest

from lewaf.integration import WAF


@pytest.fixture
def admin_blocking_waf():
    """Create WAF instance with admin path blocking rule."""
    return WAF(
        {
            "rules": [
                "SecRule REQUEST_URI \"@streq /admin\" "
                '"id:101,phase:1,t:lowercase,deny,msg:\'ADMIN PATH forbidden\'"'
            ]
        }
    )


def test_waf_blocks_lowercase_admin_path(admin_blocking_waf):
    """Test WAF blocks /admin path (lowercase)."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/admin", "GET")

    result = tx.process_request_headers()

    assert result is not None, "Request should be blocked"
    assert result["action"] == "deny"
    assert result["rule_id"] == 101


def test_waf_blocks_uppercase_admin_path(admin_blocking_waf):
    """Test WAF blocks /ADMIN path (uppercase)."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/ADMIN", "GET")

    result = tx.process_request_headers()

    assert result is not None, "Request should be blocked due to lowercase transformation"
    assert result["action"] == "deny"
    assert result["rule_id"] == 101


def test_waf_blocks_mixed_case_admin_path(admin_blocking_waf):
    """Test WAF blocks /Admin path (mixed case)."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/Admin", "GET")

    result = tx.process_request_headers()

    assert result is not None, "Request should be blocked"
    assert result["action"] == "deny"
    assert result["rule_id"] == 101


def test_waf_blocks_various_case_combinations(admin_blocking_waf):
    """Test WAF blocks all case variations of /admin."""
    test_cases = ["/admin", "/ADMIN", "/Admin", "/aDmIn", "/AdMiN", "/aDMIN"]

    for uri in test_cases:
        tx = admin_blocking_waf.new_transaction()
        tx.process_uri(uri, "GET")

        result = tx.process_request_headers()

        assert result is not None, f"URI {uri} should be blocked"
        assert result["action"] == "deny"
        assert result["rule_id"] == 101


def test_waf_allows_non_admin_paths(admin_blocking_waf):
    """Test WAF allows paths that are not /admin."""
    allowed_paths = [
        "/user",
        "/home",
        "/api/users",
        "/administrator",  # Different path
        "/admin/users",  # Sub-path, not exact match
        "/api/admin",  # Contains admin but not exact match
        "/",
        "/index.html",
    ]

    for uri in allowed_paths:
        tx = admin_blocking_waf.new_transaction()
        tx.process_uri(uri, "GET")

        result = tx.process_request_headers()

        assert result is None, f"URI {uri} should be allowed"


def test_waf_blocks_admin_with_query_string(admin_blocking_waf):
    """Test WAF blocks /admin even with query string."""
    # Note: REQUEST_URI includes query string, so this should NOT match
    # because @streq requires exact match of "/admin"
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/admin?user=test", "GET")

    result = tx.process_request_headers()

    # With @streq, "/admin?user=test" != "/admin", so should be allowed
    assert result is None, "Query string makes URI not match exactly"


def test_waf_admin_blocking_different_http_methods(admin_blocking_waf):
    """Test WAF blocks /admin for all HTTP methods."""
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    for method in methods:
        tx = admin_blocking_waf.new_transaction()
        tx.process_uri("/admin", method)

        result = tx.process_request_headers()

        assert result is not None, f"Method {method} to /admin should be blocked"
        assert result["action"] == "deny"


def test_transaction_state_after_blocking(admin_blocking_waf):
    """Test transaction state is correctly set after blocking."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/admin", "GET")

    # Check transaction state before processing
    assert tx.interruption is None

    result = tx.process_request_headers()

    # Check transaction state after processing
    assert tx.interruption is not None
    assert tx.interruption == result
    assert tx.current_phase == 1


def test_multiple_transactions_independent(admin_blocking_waf):
    """Test that multiple transactions are independent."""
    # First transaction: blocked
    tx1 = admin_blocking_waf.new_transaction()
    tx1.process_uri("/admin", "GET")
    result1 = tx1.process_request_headers()

    # Second transaction: allowed
    tx2 = admin_blocking_waf.new_transaction()
    tx2.process_uri("/user", "GET")
    result2 = tx2.process_request_headers()

    # Third transaction: blocked
    tx3 = admin_blocking_waf.new_transaction()
    tx3.process_uri("/ADMIN", "GET")
    result3 = tx3.process_request_headers()

    assert result1 is not None
    assert result2 is None
    assert result3 is not None

    # Ensure transactions have different IDs
    assert tx1.id != tx2.id
    assert tx2.id != tx3.id


def test_waf_with_multiple_blocking_rules():
    """Test WAF with multiple path blocking rules."""
    waf = WAF(
        {
            "rules": [
                "SecRule REQUEST_URI \"@streq /admin\" "
                '"id:101,phase:1,t:lowercase,deny,msg:\'Admin blocked\'"',
                "SecRule REQUEST_URI \"@streq /root\" "
                '"id:102,phase:1,t:lowercase,deny,msg:\'Root blocked\'"',
                "SecRule REQUEST_URI \"@streq /config\" "
                '"id:103,phase:1,t:lowercase,deny,msg:\'Config blocked\'"',
            ]
        }
    )

    # Test each blocked path
    blocked_paths = [
        ("/admin", 101),
        ("/ADMIN", 101),
        ("/root", 102),
        ("/ROOT", 102),
        ("/config", 103),
        ("/CONFIG", 103),
    ]

    for uri, expected_rule_id in blocked_paths:
        tx = waf.new_transaction()
        tx.process_uri(uri, "GET")
        result = tx.process_request_headers()

        assert result is not None, f"URI {uri} should be blocked"
        assert result["rule_id"] == expected_rule_id

    # Test allowed path
    tx = waf.new_transaction()
    tx.process_uri("/user", "GET")
    result = tx.process_request_headers()
    assert result is None


def test_rule_parsing_correctness(admin_blocking_waf):
    """Test that the rule is correctly parsed."""
    rules = admin_blocking_waf.rule_group.rules_by_phase[1]

    assert len(rules) == 1

    rule = rules[0]
    assert rule.id == 101
    assert rule.phase == 1
    assert rule.variables == [("REQUEST_URI", None)]
    assert rule.operator.name == "streq"
    assert rule.operator.argument == "/admin"
    assert rule.transformations == ["lowercase"]
    assert "deny" in rule.actions
    # Note: argument includes quotes as parsed from rule string
    assert "ADMIN PATH forbidden" in rule.actions["msg"].argument


def test_admin_path_with_trailing_slash():
    """Test that trailing slash makes path not match (exact match behavior)."""
    waf = WAF(
        {
            "rules": [
                "SecRule REQUEST_URI \"@streq /admin\" "
                '"id:101,phase:1,t:lowercase,deny"'
            ]
        }
    )

    # /admin/ should NOT match /admin with @streq
    tx = waf.new_transaction()
    tx.process_uri("/admin/", "GET")
    result = tx.process_request_headers()

    assert result is None, "/admin/ should not match /admin with @streq"


def test_phase_1_execution_timing(admin_blocking_waf):
    """Test that rule executes in phase 1 (request headers)."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/admin", "GET")

    # Phase should be 0 before processing
    assert tx.current_phase == 0

    # Process phase 1
    result = tx.process_request_headers()

    # Phase should be 1 after processing headers
    assert tx.current_phase == 1
    assert result is not None

    # Further phases should not execute (already interrupted)
    result2 = tx.process_request_body()
    assert result2 == result  # Should return same interruption


def test_integration_with_request_variables(admin_blocking_waf):
    """Test that REQUEST_URI variable is correctly populated."""
    tx = admin_blocking_waf.new_transaction()
    tx.process_uri("/ADMIN", "GET")

    # Check that REQUEST_URI variable is set
    request_uri = tx.variables.request_uri.get()
    assert request_uri == "/ADMIN"

    # Process and check blocking
    result = tx.process_request_headers()
    assert result is not None, "Should be blocked due to lowercase transformation"
