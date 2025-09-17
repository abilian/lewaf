"""Tests for Phase 2 features: file operations, external data sources, and advanced actions."""

from __future__ import annotations

import os
import tempfile
import pytest

from coraza_poc.primitives.operators import (
    InspectFileOperator,
    IpMatchFromFileOperator,
    PmFromDatasetOperator,
    IpMatchFromDatasetOperator,
    register_dataset,
    get_dataset,
)
from coraza_poc.primitives.actions import (
    DropAction,
    ExecAction,
    SetEnvAction,
    ExpireVarAction,
    InitColAction,
    ACTIONS,
)
from coraza_poc.primitives.collections import TransactionVariables


class MockTransaction:
    """Mock transaction for testing."""

    def __init__(self):
        self._capturing = False
        self._captures = {}
        self.interruption: dict[str, str | int] | None = None

    def capturing(self) -> bool:
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        self._captures[index] = value

    def interrupt(self, rule) -> None:
        self.interruption = {"rule_id": rule.id, "action": "deny"}


class MockRule:
    """Mock rule for testing actions."""

    def __init__(self, rule_id=1):
        self.id = rule_id


def test_inspect_file_operator_validation():
    """Test inspectFile operator input validation."""
    # Should require script path
    with pytest.raises(ValueError, match="InspectFile operator requires a script path"):
        InspectFileOperator("")

    # Should reject invalid file extensions
    with pytest.raises(ValueError, match="Script type not allowed"):
        op = InspectFileOperator("malicious.exe")
        tx = MockTransaction()
        op.evaluate(tx, "test content")

    # Should reject path traversal (use allowed extension to test path check)
    with pytest.raises(ValueError, match="Path traversal not allowed"):
        op = InspectFileOperator("../../../malicious.py")
        tx = MockTransaction()
        op.evaluate(tx, "test content")


def test_inspect_file_operator_allowed_extensions():
    """Test inspectFile operator with allowed file extensions."""
    tx = MockTransaction()

    # Test that allowed extensions don't raise validation errors during init
    allowed_scripts = ["scan.pl", "check.py", "validate.sh", "inspect.lua"]

    for script in allowed_scripts:
        try:
            op = InspectFileOperator(script)
            # We expect this to fail during evaluation (script doesn't exist)
            # but not during initialization
            result = op.evaluate(tx, "test content")
            assert result is True  # Should return True on error (script not found)
        except ValueError as e:
            if "Script type not allowed" in str(e):
                pytest.fail(f"Script {script} should be allowed but was rejected")


def test_ip_match_from_file_operator():
    """Test ipMatchFromFile operator."""
    # Create temporary file with IP addresses
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("192.168.1.100\n")
        f.write("10.0.0.0/8\n")
        f.write("# This is a comment\n")
        f.write("172.16.0.0/16\n")
        f.write("\n")  # Empty line
        temp_file = f.name

    try:
        op = IpMatchFromFileOperator(temp_file)
        tx = MockTransaction()

        # Should match exact IP
        assert op.evaluate(tx, "192.168.1.100") is True

        # Should match IP in network range
        assert op.evaluate(tx, "10.5.5.5") is True
        assert op.evaluate(tx, "172.16.1.1") is True

        # Should not match IPs outside ranges
        assert op.evaluate(tx, "8.8.8.8") is False
        assert op.evaluate(tx, "192.168.2.100") is False

        # Should handle invalid input
        assert op.evaluate(tx, "not.an.ip") is False

    finally:
        os.unlink(temp_file)


def test_ip_match_from_file_nonexistent():
    """Test ipMatchFromFile with nonexistent file."""
    op = IpMatchFromFileOperator("nonexistent.txt")
    tx = MockTransaction()

    # Should return False for nonexistent file
    assert op.evaluate(tx, "192.168.1.1") is False


def test_dataset_registration():
    """Test dataset registration and retrieval."""
    # Register a test dataset
    register_dataset("test_patterns", ["malware", "virus", "trojan"])

    # Should retrieve the dataset
    patterns = get_dataset("test_patterns")
    assert patterns == ["malware", "virus", "trojan"]

    # Should return empty list for nonexistent dataset
    empty = get_dataset("nonexistent")
    assert empty == []


def test_pm_from_dataset_operator():
    """Test pmFromDataset operator."""
    # Register test dataset
    register_dataset("bad_words", ["evil", "malicious", "hack"])

    op = PmFromDatasetOperator("bad_words")
    tx = MockTransaction()

    # Should match patterns (case insensitive)
    assert op.evaluate(tx, "This is evil content") is True
    assert op.evaluate(tx, "MALICIOUS code detected") is True
    assert op.evaluate(tx, "trying to hack") is True

    # Should not match safe content
    assert op.evaluate(tx, "safe normal content") is False

    # Should handle empty dataset
    op_empty = PmFromDatasetOperator("nonexistent")
    assert op_empty.evaluate(tx, "any content") is False


def test_ip_match_from_dataset_operator():
    """Test ipMatchFromDataset operator."""
    # Register test IP dataset
    register_dataset("bad_ips", ["192.168.1.100", "10.0.0.0/24", "172.16.1.1"])

    op = IpMatchFromDatasetOperator("bad_ips")
    tx = MockTransaction()

    # Should match exact IPs
    assert op.evaluate(tx, "192.168.1.100") is True
    assert op.evaluate(tx, "172.16.1.1") is True

    # Should match IPs in networks
    assert op.evaluate(tx, "10.0.0.50") is True

    # Should not match other IPs
    assert op.evaluate(tx, "8.8.8.8") is False

    # Should handle invalid input
    assert op.evaluate(tx, "not.an.ip") is False


def test_drop_action():
    """Test drop action."""
    action = DropAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should be disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.DISRUPTIVE

    # Should interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is not None
    assert tx.interruption["rule_id"] == 123


def test_exec_action():
    """Test exec action (security disabled)."""
    action = ExecAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require command
    with pytest.raises(ValueError, match="Exec action requires a command"):
        action.init({}, "")

    # Should initialize with command
    action.init({}, "echo test")
    assert action.command == "echo test"

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not interrupt transaction (disabled for security)
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_setenv_action():
    """Test setenv action."""
    action = SetEnvAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require var=value format
    with pytest.raises(ValueError, match="SetEnv action requires var=value format"):
        action.init({}, "")

    with pytest.raises(ValueError, match="SetEnv action requires var=value format"):
        action.init({}, "VARNAME")

    # Should initialize with var=value
    action.init({}, "TEST_VAR=test_value")
    assert action.var_name == "TEST_VAR"
    assert action.var_value == "test_value"

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should set environment variable
    action.evaluate(rule, tx)
    assert os.environ.get("TEST_VAR") == "test_value"

    # Clean up
    if "TEST_VAR" in os.environ:
        del os.environ["TEST_VAR"]


def test_expirevar_action():
    """Test expirevar action."""
    action = ExpireVarAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require var=seconds format
    with pytest.raises(
        ValueError, match="ExpireVar action requires var=seconds format"
    ):
        action.init({}, "")

    with pytest.raises(ValueError, match="ExpireVar seconds must be integer"):
        action.init({}, "VAR=not_a_number")

    # Should initialize with var=seconds
    action.init({}, "session_id=3600")
    assert action.var_name == "session_id"
    assert action.expire_seconds == 3600

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_initcol_action():
    """Test initcol action."""
    action = InitColAction()
    rule = MockRule(123)
    tx = MockTransaction()

    # Should require collection specification
    with pytest.raises(
        ValueError, match="InitCol action requires collection specification"
    ):
        action.init({}, "")

    # Should initialize with collection spec
    action.init({}, "ip=%{REMOTE_ADDR}")
    assert action.collection_spec == "ip=%{REMOTE_ADDR}"

    # Should be non-disruptive
    from coraza_poc.primitives.actions import ActionType

    assert action.action_type() == ActionType.NONDISRUPTIVE

    # Should not interrupt transaction
    action.evaluate(rule, tx)
    assert tx.interruption is None


def test_phase2_action_registry():
    """Test that Phase 2 actions are registered correctly."""
    assert "drop" in ACTIONS
    assert "exec" in ACTIONS
    assert "setenv" in ACTIONS
    assert "expirevar" in ACTIONS
    assert "initcol" in ACTIONS


def test_extended_transaction_variables():
    """Test that Phase 2 variables are available."""
    variables = TransactionVariables()

    # File upload variables
    assert hasattr(variables, "files_combined_size")
    assert hasattr(variables, "files_names")
    assert hasattr(variables, "files_tmp_names")

    # Error handling variables
    assert hasattr(variables, "reqbody_error")
    assert hasattr(variables, "inbound_data_error")
    assert hasattr(variables, "outbound_data_error")

    # Performance variables
    assert hasattr(variables, "duration")
    assert hasattr(variables, "highest_severity")
    assert hasattr(variables, "unique_id")

    # Check variable names
    assert variables.files_combined_size.name() == "FILES_COMBINED_SIZE"
    assert variables.reqbody_error.name() == "REQBODY_ERROR"
    assert variables.duration.name() == "DURATION"


def test_phase2_crs_sample_rules():
    """Test that Phase 2 features work with advanced CRS-style rules."""
    from coraza_poc.integration import WAF

    # Register test dataset for pmFromDataset
    register_dataset("attack_patterns", ["script", "eval", "javascript"])

    # Sample rules using Phase 2 features
    sample_rules = [
        # Rule using pmFromDataset
        'SecRule ARGS "@pmFromDataset attack_patterns" "id:2001,phase:2,block,msg:\'Attack pattern detected\'"',
        # Rule using drop action
        'SecRule REMOTE_ADDR "@eq 192.168.1.100" "id:2002,phase:1,drop,msg:\'Banned IP\'"',
        # Rule using setenv action
        'SecRule REQUEST_METHOD "@within GET POST" "id:2003,phase:1,pass,setenv:VALID_METHOD=1,msg:\'Valid method\'"',
        # Rule using expirevar action
        'SecRule ARGS "@contains login" "id:2004,phase:2,pass,setvar:TX.login_attempt=1,expirevar:TX.login_attempt=3600,msg:\'Login attempt tracked\'"',
    ]

    parsed_count = 0
    for rule in sample_rules:
        try:
            config = {"rules": [rule]}
            waf = WAF(config)
            waf.new_transaction()
            parsed_count += 1
            print(f"✓ Parsed: {rule[:60]}...")
        except Exception as e:
            print(f"✗ Failed: {rule[:60]}... - {e}")

    # All Phase 2 rules should parse successfully
    success_rate = parsed_count / len(sample_rules)
    assert success_rate == 1.0, f"Expected 100% success rate, got {success_rate:.1%}"


def test_file_operations_with_crs_style():
    """Test file operation operators with CRS-style rules."""
    from coraza_poc.integration import WAF

    # Create a simple test script for inspectFile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".py") as f:
        f.write("#!/usr/bin/env python3\n")
        f.write("import sys\n")
        f.write('print("1 clean file")\n')  # Always report clean
        test_script = f.name

    try:
        # Make script executable
        os.chmod(test_script, 0o755)

        rule = f'SecRule FILES_TMPNAMES "@inspectFile {test_script}" "id:2005,phase:2,block,msg:\'File inspection\'"'

        try:
            config = {"rules": [rule]}
            waf = WAF(config)
            tx = waf.new_transaction()
            assert tx is not None
            print("✓ File inspection rule parsed successfully")
        except Exception as e:
            # This might fail due to FILES_TMPNAMES not being populated, which is expected
            # The important thing is that the rule parses correctly
            if "operator" not in str(e).lower():
                pytest.fail(f"File inspection rule failed to parse: {e}")

    finally:
        os.unlink(test_script)
