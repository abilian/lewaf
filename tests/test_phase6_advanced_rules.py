"""Test Phase 6 Advanced Rule Features implementation."""

from unittest.mock import Mock, patch

from coraza_poc.primitives.actions import (
    ChainAction,
    SkipAfterAction,
    SkipNextAction,
    SetVarAction,
    ConditionalAction,
    CtlAction,
    MacroExpander,
)
from coraza_poc.primitives.collections import TransactionVariables
from coraza_poc.primitives.transformations import TRANSFORMATIONS
from coraza_poc.engine import RuleGroup


class TestChainAction:
    """Tests for chain action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.action = ChainAction()
        self.rule = Mock()
        self.rule.id = 1001
        self.transaction = Mock()
        # Initialize chain_state as a real dict to support item assignment
        self.transaction.chain_state = {}

    def test_chain_action_sets_state(self):
        """Test that chain action sets proper transaction state."""
        self.action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "chain_state")
        assert self.transaction.chain_state["in_chain"] is True
        assert self.transaction.chain_state["chain_starter"] == 1001
        assert self.transaction.chain_state["chain_matched"] is True

    def test_chain_action_type(self):
        """Test chain action type classification."""
        from coraza_poc.primitives.actions import ActionType

        assert self.action.action_type() == ActionType.FLOW


class TestSkipActions:
    """Tests for skip action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = Mock()
        self.rule.id = 1001
        self.transaction = Mock()
        # Initialize skip_state as a real dict to support item assignment
        self.transaction.skip_state = {}

    def test_skip_after_rule_id(self):
        """Test skipAfter with rule ID."""
        action = SkipAfterAction("2000")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "skip_state")
        assert self.transaction.skip_state["skip_after_id"] == 2000

    def test_skip_after_tag(self):
        """Test skipAfter with tag."""
        action = SkipAfterAction("ATTACK-SQLI")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "skip_state")
        assert self.transaction.skip_state["skip_after_tag"] == "ATTACK-SQLI"

    def test_skip_after_all_remaining(self):
        """Test skipAfter without arguments."""
        action = SkipAfterAction("")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "skip_state")
        assert self.transaction.skip_state["skip_remaining"] is True

    def test_skip_next_default(self):
        """Test skipNext with default count."""
        action = SkipNextAction("")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "skip_state")
        assert self.transaction.skip_state["skip_next_count"] == 1

    def test_skip_next_custom_count(self):
        """Test skipNext with custom count."""
        action = SkipNextAction("5")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "skip_state")
        assert self.transaction.skip_state["skip_next_count"] == 5


class TestSetVarAction:
    """Tests for setvar action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = Mock()
        self.rule.id = 1001
        self.transaction = Mock()
        self.transaction.variables = TransactionVariables()

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
        self.rule = Mock()
        self.rule.id = 1001
        self.transaction = Mock()
        self.transaction.variables = TransactionVariables()

    def test_conditional_equality_true(self):
        """Test conditional with equality that evaluates to true."""
        self.transaction.variables.tx.add("blocking_mode", "1")

        action = ConditionalAction()
        action.init({}, "TX.blocking_mode=1,deny:403")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(self.rule, self.transaction)
            mock_execute.assert_called_once_with(
                "deny:403", self.rule, self.transaction
            )

    def test_conditional_equality_false(self):
        """Test conditional with equality that evaluates to false."""
        self.transaction.variables.tx.add("blocking_mode", "0")

        action = ConditionalAction()
        action.init({}, "TX.blocking_mode=1,deny:403")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(self.rule, self.transaction)
            mock_execute.assert_not_called()

    def test_conditional_greater_than(self):
        """Test conditional with greater than comparison."""
        self.transaction.variables.tx.add("anomaly_score", "15")

        action = ConditionalAction()
        action.init({}, "TX.anomaly_score>10,block")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(self.rule, self.transaction)
            mock_execute.assert_called_once()

    def test_conditional_less_than(self):
        """Test conditional with less than comparison."""
        self.transaction.variables.tx.add("anomaly_score", "5")

        action = ConditionalAction()
        action.init({}, "TX.anomaly_score<10,allow")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(self.rule, self.transaction)
            mock_execute.assert_called_once()

    def test_conditional_variable_existence(self):
        """Test conditional checking variable existence."""
        self.transaction.variables.tx.add("debug_mode", "1")

        action = ConditionalAction()
        action.init({}, "TX.debug_mode,log")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(self.rule, self.transaction)
            mock_execute.assert_called_once()


class TestCtlAction:
    """Tests for ctl (control) action functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.rule = Mock()
        self.rule.id = 1001
        self.transaction = Mock()
        # Initialize ctl_directives as a real dict to support item assignment
        self.transaction.ctl_directives = {}

    def test_ctl_rule_engine_off(self):
        """Test ctl action to turn off rule engine."""
        action = CtlAction()
        action.init({}, "ruleEngine=Off")
        action.evaluate(self.rule, self.transaction)

        assert hasattr(self.transaction, "ctl_directives")
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
        self.transaction = Mock()
        self.transaction.variables = TransactionVariables()
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
        with patch("time.time", return_value=1234567890.123):
            result = MacroExpander.expand("%{TIME}", self.transaction)
            assert result == "1234567890123"  # Milliseconds

            result = MacroExpander.expand("%{TIME_SEC}", self.transaction)
            assert result == "1234567890"  # Seconds

    def test_environment_variable_expansion(self):
        """Test environment variable expansion."""
        with patch.dict("os.environ", {"TEST_VAR": "test_value"}):
            result = MacroExpander.expand("%{ENV.test_var}", self.transaction)
            assert result == "test_value"

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
        self.transaction = Mock()
        self.transaction.variables = TransactionVariables()
        self.transaction.current_phase = 1
        self.transaction.interruption = None
        # Initialize state dicts
        self.transaction.skip_state = {}
        self.transaction.chain_state = {}

    def test_skip_rule_processing(self):
        """Test rule skipping in engine."""
        # Create mock rules
        rule1 = Mock()
        rule1.id = 1001
        rule1.phase = 1
        rule1.actions = {}
        rule1.evaluate = Mock(return_value=True)

        rule2 = Mock()
        rule2.id = 1002
        rule2.phase = 1
        rule2.actions = {}
        rule2.evaluate = Mock(return_value=True)

        rule3 = Mock()
        rule3.id = 1003
        rule3.phase = 1
        rule3.actions = {}
        rule3.evaluate = Mock(return_value=True)

        self.rule_group.add(rule1)
        self.rule_group.add(rule2)
        self.rule_group.add(rule3)

        # Set skip state to skip next 2 rules
        self.transaction.skip_state = {"skip_next_count": 2}

        self.rule_group.evaluate(1, self.transaction)

        # First rule should be skipped, then skip count decremented
        # Only the third rule should execute
        rule1.evaluate.assert_not_called()
        rule2.evaluate.assert_not_called()
        rule3.evaluate.assert_called_once()

    def test_chain_processing(self):
        """Test chain rule processing in engine."""
        # Create mock rules for chain
        rule1 = Mock()
        rule1.id = 1001
        rule1.phase = 1
        rule1.actions = {"chain": Mock(__class__=Mock(__name__="ChainAction"))}
        rule1.evaluate = Mock(return_value=True)

        rule2 = Mock()
        rule2.id = 1002
        rule2.phase = 1
        rule2.actions = {}  # No chain action - end of chain
        rule2.evaluate = Mock(return_value=True)

        self.rule_group.add(rule1)
        self.rule_group.add(rule2)

        # Set initial chain state
        self.transaction.chain_state = {"in_chain": True}

        self.rule_group.evaluate(1, self.transaction)

        # Both rules should evaluate in chain mode
        rule1.evaluate.assert_called_once()
        rule2.evaluate.assert_called_once()


class TestComplexScenarios:
    """Tests for complex rule processing scenarios."""

    def setup_method(self):
        """Setup test fixtures."""
        self.transaction = Mock()
        self.transaction.variables = TransactionVariables()

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
        action.evaluate(Mock(id=942100), self.transaction)

        # Check if threshold exceeded - use simple comparison for now
        condition_action = ConditionalAction()
        condition_action.init({}, "TX.anomaly_score>4,block")

        rule_mock = Mock(id=949110)
        with patch.object(
            condition_action, "_execute_conditional_actions"
        ) as mock_execute:
            condition_action.evaluate(rule_mock, self.transaction)
            mock_execute.assert_called_once()

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

        rule_mock = Mock(id=1001)
        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(rule_mock, self.transaction)
            mock_execute.assert_called_once_with(
                "deny:403", rule_mock, self.transaction
            )

    def test_rate_limiting_scenario(self):
        """Test rate limiting with transaction variables."""
        # Simulate multiple requests from same IP
        self.transaction.variables.remote_addr.set("192.168.1.100")
        self.transaction.variables.tx.add("ip_request_count", "10")
        self.transaction.variables.tx.add("request_limit", "5")

        # Check rate limit - use simple comparison for now
        action = ConditionalAction()
        action.init({}, "TX.ip_request_count>5,deny:429")

        rule_mock = Mock(id=1001)
        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(rule_mock, self.transaction)
            mock_execute.assert_called_once()

    def test_debug_mode_logging(self):
        """Test debug mode conditional logging."""
        # Enable debug mode
        self.transaction.variables.tx.add("debug_mode", "1")

        # Conditional debug logging
        action = ConditionalAction()
        action.init({}, "TX.debug_mode=1,log:Debug mode active")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            action.evaluate(Mock(id=1001), self.transaction)
            mock_execute.assert_called_once()

        # Disable debug mode
        self.transaction.variables.tx.remove("debug_mode")
        self.transaction.variables.tx.add("debug_mode", "0")

        with patch.object(action, "_execute_conditional_actions") as mock_execute:
            mock_execute.reset_mock()
            action.evaluate(Mock(id=1001), self.transaction)
            mock_execute.assert_not_called()
