"""Tests for configuration validation CLI tool."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from lewaf.cli.validate import validate


@pytest.fixture
def runner():
    """Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def valid_config_file():
    """Create a valid config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [],
                "request_limits": {"body_limit": 1048576},
            },
            f,
        )
        temp_path = f.name

    yield temp_path
    Path(temp_path).unlink()


@pytest.fixture
def invalid_config_file():
    """Create an invalid config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "InvalidMode",  # Invalid engine
            },
            f,
        )
        temp_path = f.name

    yield temp_path
    Path(temp_path).unlink()


@pytest.fixture
def config_with_warnings():
    """Create a config file with warnings."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [],  # No rules -> warning
            },
            f,
        )
        temp_path = f.name

    yield temp_path
    Path(temp_path).unlink()


def test_validate_valid_config(runner, valid_config_file):
    """Test validation of valid config file."""
    result = runner.invoke(validate, [valid_config_file])

    assert result.exit_code == 0
    assert "Configuration is valid" in result.output


def test_validate_invalid_config(runner, invalid_config_file):
    """Test validation of invalid config file."""
    result = runner.invoke(validate, [invalid_config_file])

    assert result.exit_code == 1
    assert "Errors:" in result.output
    assert "Configuration is invalid" in result.output


def test_validate_with_warnings(runner, config_with_warnings):
    """Test validation shows warnings."""
    result = runner.invoke(validate, [config_with_warnings])

    assert result.exit_code == 0
    assert "Warnings:" in result.output
    assert "Configuration is valid" in result.output


def test_validate_strict_mode_with_warnings(runner, config_with_warnings):
    """Test strict mode treats warnings as errors."""
    result = runner.invoke(validate, ["--strict", config_with_warnings])

    assert result.exit_code == 1
    assert "Warnings:" in result.output
    assert "Configuration has warnings (strict mode)" in result.output


def test_validate_quiet_mode(runner, valid_config_file):
    """Test quiet mode only shows errors."""
    result = runner.invoke(validate, ["--quiet", valid_config_file])

    assert result.exit_code == 0
    assert "Validating configuration" not in result.output
    assert "Configuration is valid" in result.output


def test_validate_nonexistent_file(runner):
    """Test validation of nonexistent file."""
    result = runner.invoke(validate, ["nonexistent.yaml"])

    assert result.exit_code != 0


def test_validate_with_rule_syntax_checking(runner):
    """Test validation with rule syntax checking."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [
                    'SecRule ARGS "@rx test" "id:1,deny"',  # Valid
                ],
            },
            f,
        )
        temp_path = f.name

    try:
        result = runner.invoke(validate, ["--check-rules", temp_path])

        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
    finally:
        Path(temp_path).unlink()


def test_validate_with_invalid_rule_syntax(runner):
    """Test validation catches invalid rule syntax."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [
                    "Invalid rule syntax here",  # Invalid
                ],
            },
            f,
        )
        temp_path = f.name

    try:
        result = runner.invoke(validate, ["--check-rules", temp_path])

        assert result.exit_code == 1
        assert "Errors:" in result.output
        assert "invalid" in result.output.lower() and "syntax" in result.output.lower()
    finally:
        Path(temp_path).unlink()


def test_validate_with_variable_checking(runner):
    """Test validation with variable reference checking."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [
                    'SecRule ARGS "@rx test" "id:1,deny"',  # Valid variable
                ],
            },
            f,
        )
        temp_path = f.name

    try:
        result = runner.invoke(validate, ["--check-variables", temp_path])

        # Should pass since ARGS is a valid variable
        assert result.exit_code == 0
    finally:
        Path(temp_path).unlink()


def test_validate_with_invalid_variable(runner):
    """Test validation catches invalid variable references."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [
                    'SecRule INVALID_VAR "@rx test" "id:1,deny"',
                ],
            },
            f,
        )
        temp_path = f.name

    try:
        result = runner.invoke(validate, ["--check-variables", temp_path])

        assert result.exit_code == 1
        assert "Unknown variable reference" in result.output
    finally:
        Path(temp_path).unlink()


def test_validate_with_rule_file(runner):
    """Test validation of config with rule files."""
    # Create rule file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as rf:
        rf.write('SecRule ARGS "@rx test" "id:1,deny"\n')
        rule_file = rf.name

    # Create config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as cf:
        yaml.dump(
            {
                "engine": "On",
                "rule_files": [rule_file],
            },
            cf,
        )
        config_file = cf.name

    try:
        result = runner.invoke(validate, ["--check-rules", config_file])

        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
    finally:
        Path(rule_file).unlink()
        Path(config_file).unlink()


def test_validate_with_invalid_rule_file(runner):
    """Test validation catches errors in rule files."""
    # Create rule file with invalid rule
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as rf:
        rf.write("Invalid rule syntax\n")
        rule_file = rf.name

    # Create config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as cf:
        yaml.dump(
            {
                "engine": "On",
                "rule_files": [rule_file],
            },
            cf,
        )
        config_file = cf.name

    try:
        result = runner.invoke(validate, ["--check-rules", config_file])

        assert result.exit_code == 1
        assert "invalid" in result.output.lower() and "syntax" in result.output.lower()
        assert rule_file in result.output
    finally:
        Path(rule_file).unlink()
        Path(config_file).unlink()


def test_validate_all_checks_combined(runner):
    """Test validation with all checks enabled."""
    # Create rule file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as rf:
        rf.write('SecRule ARGS "@rx test" "id:1,deny"\n')
        rule_file = rf.name

    # Create config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as cf:
        yaml.dump(
            {
                "engine": "On",
                "rule_files": [rule_file],
                "rules": [
                    'SecRule REQUEST_HEADERS "@rx attack" "id:2,deny"',
                ],
            },
            cf,
        )
        config_file = cf.name

    try:
        result = runner.invoke(
            validate,
            ["--check-rules", "--check-variables", config_file],
        )

        assert result.exit_code == 0
        assert "Configuration is valid" in result.output
    finally:
        Path(rule_file).unlink()
        Path(config_file).unlink()


def test_validate_help_message(runner):
    """Test --help shows usage information."""
    result = runner.invoke(validate, ["--help"])

    assert result.exit_code == 0
    assert "Validate LeWAF configuration file" in result.output
    assert "--check-rules" in result.output
    assert "--check-variables" in result.output
    assert "--strict" in result.output


def test_validate_malformed_yaml(runner):
    """Test validation of malformed YAML file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("invalid: yaml: [unclosed")
        temp_path = f.name

    try:
        result = runner.invoke(validate, [temp_path])

        assert result.exit_code == 1
        assert "Failed to load configuration" in result.output
    finally:
        Path(temp_path).unlink()


def test_validate_shows_line_numbers_in_errors(runner):
    """Test that errors show line numbers for rule files."""
    # Create rule file with multiple rules, one invalid
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False) as rf:
        rf.write('SecRule ARGS "@rx test" "id:1,deny"\n')
        rf.write("Invalid rule on line 2\n")
        rf.write('SecRule ARGS "@rx test" "id:3,deny"\n')
        rule_file = rf.name

    # Create config file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as cf:
        yaml.dump(
            {
                "engine": "On",
                "rule_files": [rule_file],
            },
            cf,
        )
        config_file = cf.name

    try:
        result = runner.invoke(validate, ["--check-rules", config_file])

        assert result.exit_code == 1
        # Should show line number in error
        assert ":2:" in result.output or "line 2" in result.output.lower()
    finally:
        Path(rule_file).unlink()
        Path(config_file).unlink()
