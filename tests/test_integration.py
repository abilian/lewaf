import pytest

from coraza_poc.integration import WAF


@pytest.fixture
def simple_waf():
    """Provides a WAF instance with a single, simple rule."""
    config = {
        "rules": ['SecRule ARGS:id "@rx ^\\d+$" "id:101,phase:1,deny,log,t:lowercase"']
    }
    return WAF(config)


@pytest.fixture
def multi_rule_waf():
    """Provides a WAF instance with multiple rules across phases."""
    config = {
        "rules": [
            'SecRule ARGS:blockme "@rx true" "id:1,phase:1,deny,log"',
            'SecRule ARGS:phase2 "@rx true" "id:2,phase:2,deny,log"',
        ]
    }
    return WAF(config)


def test_seclang_parser(simple_waf):
    """Tests that the parser correctly populates a Rule object."""
    rule = simple_waf.rule_group.rules_by_phase[1][0]
    assert rule.id == 101
    assert rule.phase == 1
    assert rule.variables == [("ARGS", "id")]
    assert isinstance(rule.operator.op, RxOperator)
    assert "deny" in rule.actions
    assert "log" in rule.actions
    assert rule.transformations == ["lowercase"]


def test_transaction_benign_request(simple_waf):
    """Tests a full transaction flow for a request that should be allowed."""
    tx = simple_waf.new_transaction()
    # FIX: Added the missing 'method' argument.
    tx.process_uri("/index.php?id=abc", "GET")

    interruption = tx.process_request_headers()

    assert interruption is None, "Benign request should not be interrupted"


def test_transaction_malicious_request(simple_waf):
    """Tests a full transaction flow for a request that should be blocked."""
    tx = simple_waf.new_transaction()
    # FIX: Added the missing 'method' argument.
    tx.process_uri("/index.php?id=123", "GET")

    interruption = tx.process_request_headers()

    assert interruption is not None, "Malicious request should be interrupted"
    assert interruption["rule_id"] == 101
    assert interruption["action"] == "deny"


def test_multiple_rules_and_phases(multi_rule_waf):
    """Tests phase separation and interruption logic."""
    # Scenario 1: Blocked in Phase 1
    tx1 = multi_rule_waf.new_transaction()
    # FIX: Added the missing 'method' argument.
    tx1.process_uri("/?blockme=true", "GET")

    interruption1 = tx1.process_request_headers()
    assert interruption1 is not None
    assert interruption1["rule_id"] == 1

    interruption2 = tx1.process_request_body()
    assert interruption2 is not None
    assert interruption2["rule_id"] == 1

    # Scenario 2: Allowed in Phase 1, Blocked in Phase 2
    tx2 = multi_rule_waf.new_transaction()
    # FIX: Added the missing 'method' argument.
    tx2.process_uri("/?phase2=true", "GET")

    interruption3 = tx2.process_request_headers()
    assert interruption3 is None

    interruption4 = tx2.process_request_body()
    assert interruption4 is not None
    assert interruption4["rule_id"] == 2
