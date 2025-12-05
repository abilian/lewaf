"""Unit tests for file and dataset operators (Phase 2 features)."""

from __future__ import annotations

import os
import tempfile

from lewaf.primitives.operators import (
    OperatorOptions,
    get_dataset,
    get_operator,
    register_dataset,
)
from tests.utils import StubOperatorTransaction, stub_tx


def test_register_and_get_dataset():
    """Test dataset registration and retrieval."""
    test_data = ["pattern1", "pattern2", "pattern3"]
    register_dataset("test_dataset", test_data)

    retrieved = get_dataset("test_dataset")
    assert retrieved == test_data


def test_get_nonexistent_dataset():
    """Test retrieving non-existent dataset returns empty list."""
    result = get_dataset("nonexistent_dataset")
    assert result == []


def test_pm_from_dataset_operator():
    """Test pattern matching from dataset operator."""
    # Register test dataset
    register_dataset("attack_patterns", ["malware", "virus", "trojan"])

    options = OperatorOptions("attack_patterns")
    operator = get_operator("pmfromdataset", options)

    tx = StubOperatorTransaction()

    # Should match patterns in dataset
    assert operator.evaluate(tx, "detected malware in file") is True
    assert operator.evaluate(tx, "VIRUS detected") is True  # Case insensitive
    assert operator.evaluate(tx, "trojan horse attack") is True

    # Should not match other content
    assert operator.evaluate(tx, "clean file content") is False


def test_pm_from_dataset_empty():
    """Test pattern matching with empty dataset."""
    options = OperatorOptions("empty_dataset")
    operator = get_operator("pmfromdataset", options)

    tx = StubOperatorTransaction()

    # Should not match anything with empty dataset
    assert operator.evaluate(tx, "any content") is False


def test_ip_match_from_dataset_operator():
    """Test IP matching from dataset operator."""
    # Register test IP dataset
    register_dataset("bad_ips", ["192.168.1.100", "10.0.0.0/24", "172.16.1.1"])

    options = OperatorOptions("bad_ips")
    operator = get_operator("ipmatchfromdataset", options)

    tx = StubOperatorTransaction()

    # Should match exact IPs
    assert operator.evaluate(tx, "192.168.1.100") is True
    assert operator.evaluate(tx, "172.16.1.1") is True

    # Should match IPs in networks
    assert operator.evaluate(tx, "10.0.0.50") is True
    assert operator.evaluate(tx, "10.0.0.1") is True

    # Should not match other IPs
    assert operator.evaluate(tx, "8.8.8.8") is False
    assert operator.evaluate(tx, "192.168.2.100") is False


def test_ip_match_from_file_operator():
    """Test IP matching from file operator."""
    # Create temporary file with IP addresses
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("192.168.1.100\n")
        f.write("10.0.0.0/8\n")
        f.write("# This is a comment\n")
        f.write("172.16.0.0/16\n")
        f.write("\n")  # Empty line
        temp_file = f.name

    try:
        options = OperatorOptions(temp_file)
        operator = get_operator("ipmatchfromfile", options)

        tx = stub_tx()

        # Should match exact IP
        assert operator.evaluate(tx, "192.168.1.100") is True

        # Should match IP in network range
        assert operator.evaluate(tx, "10.5.5.5") is True
        assert operator.evaluate(tx, "172.16.1.1") is True

        # Should not match IPs outside ranges
        assert operator.evaluate(tx, "8.8.8.8") is False
        assert operator.evaluate(tx, "192.168.2.100") is False

        # Should handle invalid input
        assert operator.evaluate(tx, "not.an.ip") is False

    finally:
        os.unlink(temp_file)


def test_ip_match_from_nonexistent_file():
    """Test IP matching with nonexistent file."""
    options = OperatorOptions("nonexistent_file.txt")
    operator = get_operator("ipmatchfromfile", options)

    tx = stub_tx()

    # Should return False for nonexistent file
    assert operator.evaluate(tx, "192.168.1.1") is False


def test_inspect_file_operator_validation():
    """Test file inspection operator input validation."""
    # Should reject invalid file extensions
    try:
        options = OperatorOptions("malicious.exe")
        operator = get_operator("inspectfile", options)
        tx = stub_tx()
        # This should raise during evaluation, not creation
        result = operator.evaluate(tx, "test content")
        assert result is True  # Should return True on security rejection
    except ValueError:
        # May raise during creation in some implementations
        pass


def test_inspect_file_operator_allowed_extensions():
    """Test file inspection with allowed extensions."""
    allowed_scripts = ["scan.pl", "check.py", "validate.sh", "inspect.lua"]

    for script in allowed_scripts:
        try:
            options = OperatorOptions(script)
            operator = get_operator("inspectfile", options)
            tx = stub_tx()
            # Script doesn't exist, so should return True (safe default)
            result = operator.evaluate(tx, "test content")
            assert result is True
        except ValueError as e:
            if "Script type not allowed" in str(e):
                msg = f"Script {script} should be allowed but was rejected"
                raise AssertionError(msg)


def test_inspect_file_operator_path_traversal():
    """Test file inspection rejects path traversal."""
    try:
        options = OperatorOptions("../../../malicious.py")
        operator = get_operator("inspectfile", options)
        tx = stub_tx()
        result = operator.evaluate(tx, "test content")
        assert result is True  # Should return True on security rejection
    except ValueError:
        # Should reject path traversal
        pass
