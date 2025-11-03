"""Integration tests for core WAF functionality."""

import pytest

from lewaf.integration import WAF
from lewaf.primitives.operators import RxOperator


def test_waf_initialization_with_rules():
    """Test WAF initialization with rule configuration."""
    config = {
        "rules": ['SecRule ARGS:id "@rx ^\\d+$" "id:101,phase:1,deny,log,t:lowercase"']
    }
    waf = WAF(config)

    assert waf is not None
    assert waf.rule_group is not None
    assert len(waf.rule_group.rules_by_phase[1]) == 1


def test_waf_initialization_without_rules():
    """Test WAF initialization with empty configuration."""
    config = {"rules": []}
    waf = WAF(config)

    assert waf is not None
    assert waf.rule_group is not None
    # Should have no rules in any phase
    for phase_rules in waf.rule_group.rules_by_phase.values():
        assert len(phase_rules) == 0


def test_seclang_parser_rule_parsing():
    """Test that SecLang parser correctly populates Rule objects."""
    config = {
        "rules": ['SecRule ARGS:id "@rx ^\\d+$" "id:101,phase:1,deny,log,t:lowercase"']
    }
    waf = WAF(config)
    rule = waf.rule_group.rules_by_phase[1][0]

    assert rule.id == 101
    assert rule.phase == 1
    assert rule.variables == [("ARGS", "id")]
    assert isinstance(rule.operator.op, RxOperator)
    assert "deny" in rule.actions
    assert "log" in rule.actions
    assert rule.transformations == ["lowercase"]


def test_transaction_creation():
    """Test transaction creation from WAF instance."""
    config = {"rules": []}
    waf = WAF(config)

    tx = waf.new_transaction()

    assert tx is not None
    assert tx.waf is waf
    assert tx.interruption is None


def test_transaction_benign_request():
    """Test transaction processing for benign requests."""
    config = {"rules": ['SecRule ARGS:id "@rx ^\\d+$" "id:101,phase:1,deny,log"']}
    waf = WAF(config)
    tx = waf.new_transaction()

    # Process URI with non-numeric ID (should pass rule)
    tx.process_uri("/index.php?id=abc", "GET")
    interruption = tx.process_request_headers()

    assert interruption is None


def test_transaction_malicious_request():
    """Test transaction processing for requests matching rules."""
    config = {"rules": ['SecRule ARGS:id "@rx ^\\d+$" "id:101,phase:1,deny,log"']}
    waf = WAF(config)
    tx = waf.new_transaction()

    # Process URI with numeric ID (should trigger rule)
    tx.process_uri("/index.php?id=123", "GET")
    interruption = tx.process_request_headers()

    assert interruption is not None
    assert interruption["rule_id"] == 101
    assert interruption["action"] == "deny"


def test_multiple_rules_single_phase():
    """Test multiple rules in the same phase."""
    config = {
        "rules": [
            'SecRule ARGS:test1 "@rx danger" "id:201,phase:1,deny,log"',
            'SecRule ARGS:test2 "@rx evil" "id:202,phase:1,deny,log"',
        ]
    }
    waf = WAF(config)

    # Test first rule
    tx1 = waf.new_transaction()
    tx1.process_uri("/?test1=danger", "GET")
    interruption1 = tx1.process_request_headers()

    assert interruption1 is not None
    assert interruption1["rule_id"] == 201

    # Test second rule
    tx2 = waf.new_transaction()
    tx2.process_uri("/?test2=evil", "GET")
    interruption2 = tx2.process_request_headers()

    assert interruption2 is not None
    assert interruption2["rule_id"] == 202


def test_multiple_phases_processing():
    """Test processing across multiple phases."""
    config = {
        "rules": [
            'SecRule ARGS:blockme "@rx true" "id:301,phase:1,deny,log"',
            'SecRule ARGS:phase2 "@rx true" "id:302,phase:2,deny,log"',
        ]
    }
    waf = WAF(config)

    # Scenario 1: Blocked in Phase 1
    tx1 = waf.new_transaction()
    tx1.process_uri("/?blockme=true", "GET")

    interruption1 = tx1.process_request_headers()
    assert interruption1 is not None
    assert interruption1["rule_id"] == 301

    # Should still be interrupted in phase 2
    interruption2 = tx1.process_request_body()
    assert interruption2 is not None
    assert interruption2["rule_id"] == 301

    # Scenario 2: Allowed in Phase 1, Blocked in Phase 2
    tx2 = waf.new_transaction()
    tx2.process_uri("/?phase2=true", "GET")

    interruption3 = tx2.process_request_headers()
    assert interruption3 is None

    interruption4 = tx2.process_request_body()
    assert interruption4 is not None
    assert interruption4["rule_id"] == 302


def test_transaction_isolation():
    """Test that transactions are isolated from each other."""
    config = {"rules": ['SecRule ARGS:block "@rx yes" "id:401,phase:1,deny,log"']}
    waf = WAF(config)

    # Create two transactions
    tx1 = waf.new_transaction()
    tx2 = waf.new_transaction()

    # Process different requests
    tx1.process_uri("/?block=yes", "GET")
    tx2.process_uri("/?block=no", "GET")

    # First should be blocked, second should pass
    interruption1 = tx1.process_request_headers()
    interruption2 = tx2.process_request_headers()

    assert interruption1 is not None
    assert interruption2 is None


def test_rule_with_transformations():
    """Test rules with transformation processing."""
    config = {
        "rules": [
            'SecRule ARGS:data "@rx ATTACK" "id:501,phase:2,deny,log,t:uppercase"'
        ]
    }
    waf = WAF(config)
    tx = waf.new_transaction()

    # Test with lowercase input (should be transformed to uppercase)
    tx.process_uri("/?data=attack", "GET")
    interruption1 = tx.process_request_headers()
    assert interruption1 is None  # Phase 1 should not trigger

    interruption2 = tx.process_request_body()
    assert interruption2 is not None  # Phase 2 should trigger
    assert interruption2["rule_id"] == 501


def test_rule_with_multiple_variables():
    """Test rules that check multiple variable sources."""
    config = {
        "rules": ['SecRule ARGS|REQUEST_URI "@rx malicious" "id:601,phase:1,deny,log"']
    }
    waf = WAF(config)

    # Test URI match
    tx1 = waf.new_transaction()
    tx1.process_uri("/malicious/path", "GET")
    interruption1 = tx1.process_request_headers()

    assert interruption1 is not None
    assert interruption1["rule_id"] == 601

    # Test ARGS match
    tx2 = waf.new_transaction()
    tx2.process_uri("/?param=malicious", "GET")
    interruption2 = tx2.process_request_headers()

    assert interruption2 is not None
    assert interruption2["rule_id"] == 601


def test_waf_error_handling_invalid_rule():
    """Test WAF behavior with invalid rule syntax."""
    config = {"rules": ["Invalid rule syntax that should fail"]}

    # Should handle parsing errors gracefully
    with pytest.raises(Exception):
        WAF(config)


def test_rule_action_variations():
    """Test different rule actions (deny, allow, pass)."""
    config = {
        "rules": [
            'SecRule ARGS:deny "@rx trigger" "id:701,phase:1,deny,log"',
            'SecRule ARGS:allow "@rx trigger" "id:702,phase:1,allow,log"',
            'SecRule ARGS:pass "@rx trigger" "id:703,phase:1,pass,log"',
        ]
    }
    waf = WAF(config)

    # Test deny action
    tx1 = waf.new_transaction()
    tx1.process_uri("/?deny=trigger", "GET")
    interruption1 = tx1.process_request_headers()

    assert interruption1 is not None
    assert interruption1["action"] == "deny"

    # Test allow action (allow doesn't interrupt)
    tx2 = waf.new_transaction()
    tx2.process_uri("/?allow=trigger", "GET")
    interruption2 = tx2.process_request_headers()

    assert interruption2 is None  # Allow action doesn't interrupt

    # Test pass action (no interruption)
    tx3 = waf.new_transaction()
    tx3.process_uri("/?pass=trigger", "GET")
    interruption3 = tx3.process_request_headers()

    # Pass actions don't interrupt
    assert interruption3 is None


def test_rule_with_complex_regex():
    """Test rules with complex regular expressions."""
    config = {
        "rules": [
            'SecRule ARGS "@rx (?i)\\b(union|select|insert|update|delete|drop)\\b.*\\b(from|where|table)\\b" "id:801,phase:2,deny,log,msg:\'SQL Injection Pattern\'"'
        ]
    }
    waf = WAF(config)

    # Test SQL injection pattern
    tx = waf.new_transaction()
    tx.process_uri("/?query=SELECT * FROM users WHERE id=1", "GET")
    interruption1 = tx.process_request_headers()
    assert interruption1 is None  # Phase 1 should not trigger

    interruption2 = tx.process_request_body()
    assert interruption2 is not None  # Phase 2 should trigger
    assert interruption2["rule_id"] == 801


def test_transaction_state_persistence():
    """Test that transaction state persists across processing phases."""
    config = {
        "rules": [
            'SecRule ARGS:data "@rx test" "id:901,phase:1,pass,log"',
            'SecRule ARGS:data "@rx test" "id:902,phase:2,deny,log,msg:\'Data detected\'"',
        ]
    }
    waf = WAF(config)
    tx = waf.new_transaction()

    # Process request with data parameter
    tx.process_uri("/submit?data=test", "GET")

    # Phase 1 should pass (rule with pass action)
    interruption1 = tx.process_request_headers()
    assert interruption1 is None

    # Phase 2 should see the same ARGS data and block
    interruption2 = tx.process_request_body()
    assert interruption2 is not None
    assert interruption2["rule_id"] == 902
