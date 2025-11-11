"""Test Phase 6 Advanced Rule Features implementation.

Following the principle of avoiding mocks in favor of stubs, these tests use
simple stub objects instead of Mock() to verify tangible outcomes.
"""

from __future__ import annotations

import time

from lewaf.engine import RuleGroup
from lewaf.primitives.actions import (
    ChainAction,
    ConditionalAction,
    CtlAction,
    MacroExpander,
    SetVarAction,
    SkipAfterAction,
    SkipNextAction,
)
from lewaf.primitives.collections import TransactionVariables
from lewaf.primitives.transformations import TRANSFORMATIONS


class StubRule:
    """Stub rule object for testing.

    This is a simple stub that provides only what's needed for testing,
    avoiding the use of Mock() objects.
    """

    def __init__(self, rule_id: int = 1001, phase: int = 1):
        self.id = rule_id
        self.phase = phase
        self.actions = {}
        self.evaluated = False
        self.evaluation_count = 0

    def evaluate(self, transaction):
        """Stub evaluate method that records it was called."""
        self.evaluated = True
        self.evaluation_count += 1
        return True


class StubTransaction:
    """Stub transaction object for testing.

    This is a simple stub that provides only what's needed for testing,
    avoiding the use of Mock() objects.
    """

    def __init__(self):
        self.variables = TransactionVariables()
        self.chain_state = {}
        self.skip_state = {}
        self.multimatch_state = {}
        self.ctl_directives = {}

        # Engine control attributes
        self.rule_engine_enabled = True
        self.rule_engine_mode = "on"
        self.body_processor = "URLENCODED"
        self.body_limit = 131072

        # Transaction state
        self.current_phase = 1
        self.interruption = None

        # Matched data
        self.matched_var = ""
        self.matched_var_name = ""


class TestChainAction:
    """Tests for chain action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.action = ChainAction()
        self.rule = StubRule()
        self.transaction = StubTransaction()

    def test_chain_action_sets_state(self):
        """Test that chain action sets proper transaction state."""
        self.action.evaluate(self.rule, self.transaction)

        assert "in_chain" in self.transaction.chain_state
        assert self.transaction.chain_state["in_chain"] is True
        assert self.transaction.chain_state["chain_starter"] == 1001
        assert self.transaction.chain_state["chain_matched"] is True

    def test_chain_action_type(self):
        """Test chain action type classification."""
        from lewaf.primitives.actions import ActionType

        assert self.action.action_type() == ActionType.FLOW


class TestSkipActions:
    """Tests for skip action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = StubRule()
        self.transaction = StubTransaction()

    def test_skip_after_rule_id(self):
        """Test skipAfter with rule ID."""
        action = SkipAfterAction("2000")
        action.evaluate(self.rule, self.transaction)

        assert "skip_after_id" in self.transaction.skip_state
        assert self.transaction.skip_state["skip_after_id"] == 2000

    def test_skip_after_tag(self):
        """Test skipAfter with tag."""
        action = SkipAfterAction("ATTACK-SQLI")
        action.evaluate(self.rule, self.transaction)

        assert "skip_after_tag" in self.transaction.skip_state
        assert self.transaction.skip_state["skip_after_tag"] == "ATTACK-SQLI"

    def test_skip_after_all_remaining(self):
        """Test skipAfter without arguments."""
        action = SkipAfterAction("")
        action.evaluate(self.rule, self.transaction)

        assert "skip_remaining" in self.transaction.skip_state
        assert self.transaction.skip_state["skip_remaining"] is True

    def test_skip_next_default(self):
        """Test skipNext with default count."""
        action = SkipNextAction("")
        action.evaluate(self.rule, self.transaction)

        assert "skip_next_count" in self.transaction.skip_state
        assert self.transaction.skip_state["skip_next_count"] == 1

    def test_skip_next_custom_count(self):
        """Test skipNext with custom count."""
        action = SkipNextAction("5")
        action.evaluate(self.rule, self.transaction)

        assert "skip_next_count" in self.transaction.skip_state
        assert self.transaction.skip_state["skip_next_count"] == 5


class TestSetVarAction:
    """Tests for setvar action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = StubRule()
        self.transaction = StubTransaction()

    def test_setvar_direct_assignment(self):
        """Test direct variable assignment."""
        action = SetVarAction()
        action.init({}, "tx.score=100")
        action.evaluate(self.rule, self.transaction)

        values = self.transaction.variables.tx.get("score")
        assert len(values) == 1
        assert values[0] == "100"

    def test_setvar_increment(self):
        """Test variable increment operation."""
        # Set initial value
        self.transaction.variables.tx.add("score", "10")

        action = SetVarAction()
        action.init({}, "tx.score=+5")
        action.evaluate(self.rule, self.transaction)

        values = self.transaction.variables.tx.get("score")
        assert len(values) == 1
        assert values[0] == "15"

    def test_setvar_decrement(self):
        """Test variable decrement operation."""
        # Set initial value
        self.transaction.variables.tx.add("score", "20")

        action = SetVarAction()
        action.init({}, "tx.score=-3")
        action.evaluate(self.rule, self.transaction)

        values = self.transaction.variables.tx.get("score")
        assert len(values) == 1
        assert values[0] == "17"

    def test_setvar_delete(self):
        """Test variable deletion."""
        # Set initial value
        self.transaction.variables.tx.add("temp_var", "value")

        action = SetVarAction()
        action.init({}, "!tx.temp_var")
        action.evaluate(self.rule, self.transaction)

        values = self.transaction.variables.tx.get("temp_var")
        assert len(values) == 0

    def test_setvar_with_macro_expansion(self):
        """Test setvar with macro expansion."""
        # Set up transaction state for macro expansion
        self.transaction.matched_var = "attack_payload"
        self.transaction.variables.tx.add("base_score", "10")

        action = SetVarAction()
        action.init({}, "tx.anomaly_score=+%{TX.base_score}")
        action.evaluate(self.rule, self.transaction)

        values = self.transaction.variables.tx.get("anomaly_score")
        assert len(values) == 1
        assert values[0] == "10"


class TestConditionalAction:
    """Tests for conditional action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = StubRule()
        self.transaction = StubTransaction()

    def test_conditional_equality_true(self):
        """Test conditional with equality that evaluates to true."""
        self.transaction.variables.tx.add("blocking_mode", "1")

        action = ConditionalAction()
        action.init({}, "TX.blocking_mode=1,deny:403")

        # Track whether conditional actions would be executed
        # by checking if the condition is met
        result = action._evaluate_condition("TX.blocking_mode=1", self.transaction)
        assert result is True

    def test_conditional_equality_false(self):
        """Test conditional with equality that evaluates to false."""
        self.transaction.variables.tx.add("blocking_mode", "0")

        action = ConditionalAction()
        action.init({}, "TX.blocking_mode=1,deny:403")

        result = action._evaluate_condition("TX.blocking_mode=1", self.transaction)
        assert result is False

    def test_conditional_greater_than(self):
        """Test conditional with greater than comparison."""
        self.transaction.variables.tx.add("anomaly_score", "15")

        action = ConditionalAction()
        action.init({}, "TX.anomaly_score>10,block")

        result = action._evaluate_condition("TX.anomaly_score>10", self.transaction)
        assert result is True

    def test_conditional_less_than(self):
        """Test conditional with less than comparison."""
        self.transaction.variables.tx.add("anomaly_score", "5")

        action = ConditionalAction()
        action.init({}, "TX.anomaly_score<10,allow")

        result = action._evaluate_condition("TX.anomaly_score<10", self.transaction)
        assert result is True

    def test_conditional_variable_existence(self):
        """Test conditional checking variable existence."""
        self.transaction.variables.tx.add("debug_mode", "1")

        action = ConditionalAction()
        action.init({}, "TX.debug_mode,log")

        result = action._evaluate_condition("TX.debug_mode", self.transaction)
        assert result is True


class TestCtlAction:
    """Tests for ctl (control) action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = StubRule()
        self.transaction = StubTransaction()

    def test_ctl_rule_engine_off(self):
        """Test ctl action to turn off rule engine."""
        action = CtlAction()
        action.init({}, "ruleEngine=Off")
        action.evaluate(self.rule, self.transaction)

        assert "ruleEngine" in self.transaction.ctl_directives
        assert self.transaction.ctl_directives["ruleEngine"] == "Off"
        assert self.transaction.rule_engine_enabled is False

    def test_ctl_rule_engine_detection_only(self):
        """Test ctl action for detection only mode."""
        action = CtlAction()
        action.init({}, "ruleEngine=DetectionOnly")
        action.evaluate(self.rule, self.transaction)

        assert self.transaction.rule_engine_mode == "detection"
        assert self.transaction.rule_engine_enabled is True

    def test_ctl_request_body_processor(self):
        """Test ctl action for request body processor."""
        action = CtlAction()
        action.init({}, "requestBodyProcessor=XML")
        action.evaluate(self.rule, self.transaction)

        assert self.transaction.body_processor == "XML"

    def test_ctl_request_body_limit(self):
        """Test ctl action for request body limit."""
        action = CtlAction()
        action.init({}, "requestBodyLimit=1048576")
        action.evaluate(self.rule, self.transaction)

        assert self.transaction.body_limit == 1048576


class TestMacroExpander:
    """Tests for macro expansion functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.transaction = StubTransaction()
        self.transaction.matched_var = "attack_string"
        self.transaction.matched_var_name = "ARGS:input"

    def test_simple_variable_expansion(self):
        """Test simple variable reference expansion."""
        result = MacroExpander.expand("%{MATCHED_VAR}", self.transaction)
        assert result == "attack_string"

        result = MacroExpander.expand("%{MATCHED_VAR_NAME}", self.transaction)
        assert result == "ARGS:input"

    def test_collection_member_expansion(self):
        """Test collection member access expansion."""
        self.transaction.variables.tx.add("score", "25")
        self.transaction.variables.request_headers.add("host", "example.com")

        result = MacroExpander.expand("%{TX.score}", self.transaction)
        assert result == "25"

        result = MacroExpander.expand("%{REQUEST_HEADERS.host}", self.transaction)
        assert result == "example.com"

    def test_time_expansion(self):
        """Test time-related macro expansion."""
        # Save original time.time
        original_time = time.time

        # Replace with a stub that returns a fixed value
        time.time = lambda: 1234567890.123

        try:
            result = MacroExpander.expand("%{TIME}", self.transaction)
            assert result == "1234567890123"  # Milliseconds

            result = MacroExpander.expand("%{TIME_SEC}", self.transaction)
            assert result == "1234567890"  # Seconds
        finally:
            # Restore original time.time
            time.time = original_time

    def test_environment_variable_expansion(self):
        """Test environment variable expansion."""
        import os

        # Save original value
        original_value = os.environ.get("TEST_VAR")

        # Set test value
        os.environ["TEST_VAR"] = "test_value"

        try:
            result = MacroExpander.expand("%{ENV.test_var}", self.transaction)
            assert result == "test_value"
        finally:
            # Restore original value
            if original_value is None:
                os.environ.pop("TEST_VAR", None)
            else:
                os.environ["TEST_VAR"] = original_value

    def test_geo_variable_expansion(self):
        """Test geographic variable expansion."""
        self.transaction.variables.geo.add("country_code", "US")
        self.transaction.variables.geo.add("city", "San Francisco")

        result = MacroExpander.expand("%{GEO.country_code}", self.transaction)
        assert result == "US"

        result = MacroExpander.expand("%{GEO.city}", self.transaction)
        assert result == "San Francisco"

    def test_complex_expression_expansion(self):
        """Test complex expression with multiple variables."""
        self.transaction.variables.tx.add("score", "10")
        self.transaction.variables.request_headers.add("user-agent", "TestAgent")

        expression = "Score: %{TX.score}, Agent: %{REQUEST_HEADERS.user-agent}, Matched: %{MATCHED_VAR}"
        result = MacroExpander.expand(expression, self.transaction)

        expected = "Score: 10, Agent: TestAgent, Matched: attack_string"
        assert result == expected

    def test_unknown_variable_expansion(self):
        """Test expansion of unknown variables."""
        result = MacroExpander.expand("%{UNKNOWN_VAR}", self.transaction)
        assert result == ""

        result = MacroExpander.expand("%{UNKNOWN_COLLECTION.member}", self.transaction)
        assert result == ""


class TestAdvancedTransformations:
    """Tests for Phase 6 advanced transformations."""

    def test_sha1_transformation(self):
        """Test SHA-1 hash transformation."""
        result, changed = TRANSFORMATIONS["sha1"]("hello")
        assert changed is True
        assert result == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"

    def test_md5_transformation(self):
        """Test MD5 hash transformation."""
        result, changed = TRANSFORMATIONS["md5"]("hello")
        assert changed is True
        assert result == "5d41402abc4b2a76b9719d911017c592"

    def test_sha256_transformation(self):
        """Test SHA-256 hash transformation."""
        result, changed = TRANSFORMATIONS["sha256"]("hello")
        assert changed is True
        assert (
            result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_replace_comments_transformation(self):
        """Test comment replacement transformation."""
        input_value = "SELECT * FROM users -- this is a comment"
        result, changed = TRANSFORMATIONS["replacecomments"](input_value)
        assert changed is True
        assert " this is a comment" not in result
        assert "SELECT * FROM users " in result

    def test_replace_nulls_transformation(self):
        """Test null replacement transformation."""
        input_value = "test\x00string%00encoded"
        result, changed = TRANSFORMATIONS["replacenulls"](input_value)
        assert changed is True
        assert "\x00" not in result
        assert "%00" not in result

    def test_normalize_path_transformation(self):
        """Test path normalization transformation."""
        input_value = "/path/to/../file/./name"
        result, changed = TRANSFORMATIONS["normalizepath"](input_value)
        assert changed is True
        assert result == "/path/file/name"

    def test_sql_hex_decode_transformation(self):
        """Test SQL hex decoding transformation."""
        # "Hello" in hex
        input_value = "0x48656c6c6f"
        result, changed = TRANSFORMATIONS["sqlhexdecode"](input_value)
        assert changed is True
        assert result == "Hello"

    def test_remove_comments_transformation(self):
        """Test comment removal transformation."""
        input_value = "SELECT * FROM users /* block comment */ WHERE id=1"
        result, changed = TRANSFORMATIONS["removecomments"](input_value)
        assert changed is True
        assert "/* block comment */" not in result
        assert "SELECT * FROM users  WHERE id=1" == result

    def test_parity_transformations(self):
        """Test parity bit transformations."""
        # Test even parity - A has 2 bits (even), no change needed
        result, changed = TRANSFORMATIONS["parityeven7bit"]("A")  # 0x41
        assert changed is False  # A already has even parity

        # Test odd parity - A has 2 bits (even), needs change
        result, changed = TRANSFORMATIONS["parityodd7bit"]("A")
        assert changed is True

        # Test zero parity with character that has high bit set
        test_char = chr(0xC1)  # Character with high bit set
        result, changed = TRANSFORMATIONS["parityzero7bit"](test_char)
        assert changed is True


class TestRuleEngineIntegration:
    """Integration tests for rule engine with Phase 6 features."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule_group = RuleGroup()
        self.transaction = StubTransaction()

    def test_skip_rule_processing(self):
        """Test rule skipping in engine."""
        # Create stub rules
        rule1 = StubRule(1001, 1)
        rule2 = StubRule(1002, 1)
        rule3 = StubRule(1003, 1)

        self.rule_group.add(rule1)
        self.rule_group.add(rule2)
        self.rule_group.add(rule3)

        # Set skip state to skip next 2 rules
        self.transaction.skip_state = {"skip_next_count": 2}

        self.rule_group.evaluate(1, self.transaction)

        # First two rules should be skipped
        # Only the third rule should execute
        assert rule1.evaluated is False
        assert rule2.evaluated is False
        assert rule3.evaluated is True

    def test_chain_processing(self):
        """Test chain rule processing in engine."""
        # Create stub rules for chain
        rule1 = StubRule(1001, 1)
        rule1.actions = {"chain": ChainAction()}

        rule2 = StubRule(1002, 1)
        # No chain action - end of chain

        self.rule_group.add(rule1)
        self.rule_group.add(rule2)

        # Set initial chain state
        self.transaction.chain_state = {"in_chain": True}

        self.rule_group.evaluate(1, self.transaction)

        # Both rules should evaluate in chain mode
        assert rule1.evaluated is True
        assert rule2.evaluated is True


class TestComplexScenarios:
    """Tests for complex rule processing scenarios."""

    def setup_method(self):
        """Setup test fixtures."""
        self.transaction = StubTransaction()

    def test_anomaly_scoring_workflow(self):
        """Test complete anomaly scoring workflow."""
        # Initialize transaction variables
        self.transaction.variables.tx.add("anomaly_score", "0")
        self.transaction.variables.tx.add("inbound_anomaly_score_threshold", "5")

        # Simulate SQL injection detection
        self.transaction.matched_var = "' OR 1=1--"
        self.transaction.matched_var_name = "ARGS:q"

        # Increment anomaly score
        action = SetVarAction()
        action.init({}, "tx.anomaly_score=+5")
        action.evaluate(StubRule(942100), self.transaction)

        # Check if threshold exceeded
        condition_action = ConditionalAction()
        condition_action.init({}, "TX.anomaly_score>4,block")

        # Verify condition is met
        result = condition_action._evaluate_condition(
            "TX.anomaly_score>4", self.transaction
        )
        assert result is True

        # Verify final score
        score_values = self.transaction.variables.tx.get("anomaly_score")
        assert score_values[0] == "5"

    def test_geo_based_blocking(self):
        """Test geographic-based blocking scenario."""
        # Set up geographic data
        self.transaction.variables.geo.add("country_code", "XX")  # Suspicious country

        # Create conditional action for geo-blocking
        action = ConditionalAction()
        action.init({}, "GEO.country_code=XX,deny:403")

        # Verify condition is met
        result = action._evaluate_condition("GEO.country_code=XX", self.transaction)
        assert result is True

    def test_rate_limiting_scenario(self):
        """Test rate limiting with transaction variables."""
        # Simulate multiple requests from same IP
        self.transaction.variables.remote_addr.set("192.168.1.100")
        self.transaction.variables.tx.add("ip_request_count", "10")
        self.transaction.variables.tx.add("request_limit", "5")

        # Check rate limit
        action = ConditionalAction()
        action.init({}, "TX.ip_request_count>5,deny:429")

        # Verify condition is met
        result = action._evaluate_condition("TX.ip_request_count>5", self.transaction)
        assert result is True

    def test_debug_mode_logging(self):
        """Test debug mode conditional logging."""
        # Enable debug mode
        self.transaction.variables.tx.add("debug_mode", "1")

        # Conditional debug logging
        action = ConditionalAction()
        action.init({}, "TX.debug_mode=1,log:Debug mode active")

        # Verify condition is met when debug mode is on
        result = action._evaluate_condition("TX.debug_mode=1", self.transaction)
        assert result is True

        # Disable debug mode
        self.transaction.variables.tx.remove("debug_mode")
        self.transaction.variables.tx.add("debug_mode", "0")

        # Verify condition is not met when debug mode is off
        result = action._evaluate_condition("TX.debug_mode=1", self.transaction)
        assert result is False
