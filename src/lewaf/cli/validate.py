"""Configuration validation CLI tool."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import click

from lewaf.config.loader import ConfigLoader
from lewaf.config.validator import ConfigValidator


@click.command()
@click.argument(
    "config_file",
    type=click.Path(exists=True, path_type=Path),
)
@click.option(
    "--check-rules",
    is_flag=True,
    help="Validate rule syntax (requires rules engine)",
)
@click.option(
    "--check-variables",
    is_flag=True,
    help="Verify all variable references in rules",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Treat warnings as errors",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Only show errors",
)
def validate(
    config_file: Path,
    check_rules: bool,
    check_variables: bool,
    strict: bool,
    quiet: bool,
) -> None:
    """Validate LeWAF configuration file before deployment.

    This tool performs comprehensive validation of configuration files:
    - Schema validation
    - File path verification
    - Rule syntax checking (optional)
    - Variable reference verification (optional)

    Examples:

        # Basic validation
        lewaf-validate config/production.yaml

        # Strict validation (warnings are errors)
        lewaf-validate --strict config/production.yaml

        # Full validation with rule syntax checking
        lewaf-validate --check-rules --check-variables config/production.yaml
    """
    if not quiet:
        click.echo(f"Validating configuration: {config_file}")

    try:
        # Load configuration
        loader = ConfigLoader()
        config = loader.load_from_file(config_file)

        # Basic validation
        validator = ConfigValidator()
        is_valid, errors, warnings = validator.validate(config)

        # Rule syntax validation
        rule_errors: list[str] = []
        if check_rules:
            rule_errors = _validate_rule_syntax(config)
            if rule_errors:
                is_valid = False
                errors.extend(rule_errors)

        # Variable reference validation
        var_errors: list[str] = []
        if check_variables:
            var_errors = _validate_variable_references(config)
            if var_errors:
                is_valid = False
                errors.extend(var_errors)

        # Display results
        if errors:
            click.secho("\nErrors:", fg="red", bold=True)
            for error in errors:
                click.echo(f"  ✗ {error}", err=True)

        if warnings:
            click.secho("\nWarnings:", fg="yellow", bold=True)
            for warning in warnings:
                click.echo(f"  ⚠ {warning}")

        # Summary
        click.echo()
        if is_valid and not (strict and warnings):
            click.secho("✓ Configuration is valid", fg="green", bold=True)
        elif strict and warnings:
            click.secho(
                "✗ Configuration has warnings (strict mode)", fg="red", bold=True
            )
            sys.exit(1)
        else:
            click.secho("✗ Configuration is invalid", fg="red", bold=True)
            sys.exit(1)

    except Exception as e:
        click.secho(f"\nFailed to load configuration: {e}", fg="red", err=True)
        sys.exit(1)


def _validate_rule_syntax(config: Any) -> list[str]:
    """Validate SecLang rule syntax.

    Args:
        config: Configuration to validate

    Returns:
        List of rule syntax errors
    """
    errors: list[str] = []

    # Basic syntax validation using regex patterns
    # This checks for common SecLang directive patterns without full parsing
    secrule_pattern = re.compile(r'^SecRule\s+\S+\s+"[^"]*"\s+"[^"]*"')
    secaction_pattern = re.compile(r'^SecAction\s+"[^"]*"')
    secmarker_pattern = re.compile(r"^SecMarker\s+\S+")
    secdefaultaction_pattern = re.compile(r'^SecDefaultAction\s+"[^"]*"')

    def validate_line(line: str, location: str) -> None:
        """Validate a single rule line."""
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # Check if it matches any valid SecLang directive pattern
        if line.startswith("SecRule"):
            if not secrule_pattern.match(line):
                errors.append(f"{location}: Invalid SecRule syntax")
        elif line.startswith("SecAction"):
            if not secaction_pattern.match(line):
                errors.append(f"{location}: Invalid SecAction syntax")
        elif line.startswith("SecMarker"):
            if not secmarker_pattern.match(line):
                errors.append(f"{location}: Invalid SecMarker syntax")
        elif line.startswith("SecDefaultAction"):
            if not secdefaultaction_pattern.match(line):
                errors.append(f"{location}: Invalid SecDefaultAction syntax")
        elif line.startswith("Sec"):
            # Unknown Sec directive
            errors.append(f"{location}: Unknown SecLang directive")
        else:
            # Non-directive lines should be flagged as invalid
            errors.append(
                f"{location}: Invalid rule syntax - expected SecLang directive"
            )

    # Validate inline rules
    for i, rule_str in enumerate(config.rules):
        validate_line(rule_str, f"Rule {i + 1}")

    # Validate rule files
    for rule_file in config.rule_files:
        rule_path = Path(rule_file)
        if not rule_path.exists():
            continue  # Already caught by basic validation

        try:
            with open(rule_path) as f:
                for line_num, line in enumerate(f, start=1):
                    validate_line(line, f"{rule_file}:{line_num}")
        except Exception as e:
            errors.append(f"Failed to read rule file {rule_file}: {e}")

    return errors


def _validate_variable_references(config: Any) -> list[str]:
    """Validate that all variable references in rules are valid.

    Args:
        config: Configuration to validate

    Returns:
        List of variable reference errors
    """
    errors: list[str] = []

    # Known valid SecLang collection variables
    valid_collections = {
        "ARGS",
        "ARGS_COMBINED_SIZE",
        "ARGS_GET",
        "ARGS_GET_NAMES",
        "ARGS_NAMES",
        "ARGS_POST",
        "ARGS_POST_NAMES",
        "FILES",
        "FILES_COMBINED_SIZE",
        "FILES_NAMES",
        "FILES_SIZES",
        "FILES_TMPNAMES",
        "GEO",
        "MATCHED_VAR",
        "MATCHED_VAR_NAME",
        "MATCHED_VARS",
        "MATCHED_VARS_NAMES",
        "MULTIPART_CRLF_LF_LINES",
        "MULTIPART_FILENAME",
        "MULTIPART_NAME",
        "MULTIPART_STRICT_ERROR",
        "MULTIPART_UNMATCHED_BOUNDARY",
        "QUERY_STRING",
        "REMOTE_ADDR",
        "REMOTE_HOST",
        "REMOTE_PORT",
        "REMOTE_USER",
        "REQBODY_ERROR",
        "REQBODY_ERROR_MSG",
        "REQBODY_PROCESSOR",
        "REQUEST_BASENAME",
        "REQUEST_BODY",
        "REQUEST_BODY_LENGTH",
        "REQUEST_COOKIES",
        "REQUEST_COOKIES_NAMES",
        "REQUEST_FILENAME",
        "REQUEST_HEADERS",
        "REQUEST_HEADERS_NAMES",
        "REQUEST_LINE",
        "REQUEST_METHOD",
        "REQUEST_PROTOCOL",
        "REQUEST_URI",
        "REQUEST_URI_RAW",
        "RESPONSE_BODY",
        "RESPONSE_CONTENT_LENGTH",
        "RESPONSE_CONTENT_TYPE",
        "RESPONSE_HEADERS",
        "RESPONSE_HEADERS_NAMES",
        "RESPONSE_PROTOCOL",
        "RESPONSE_STATUS",
        "SERVER_ADDR",
        "SERVER_NAME",
        "SERVER_PORT",
        "SESSION",
        "SESSIONID",
        "TX",
        "UNIQUE_ID",
        "URLENCODED_ERROR",
        "USERID",
        "WEBAPPID",
        "XML",
    }

    # Pattern to find potential variable references
    # Matches words that are all uppercase (3+ chars) that appear after SecRule
    var_pattern = re.compile(r"SecRule\s+([A-Z][A-Z_]{2,})")

    def check_variables(rule_str: str, location: str) -> None:
        """Check variables in a rule string."""
        # Find all potential variable names in SecRule directives
        matches = var_pattern.findall(rule_str)

        for var_name in matches:
            # Check if it's a valid collection
            if var_name not in valid_collections:
                errors.append(f"{location}: Unknown variable reference: {var_name}")

    # Check inline rules
    for i, rule_str in enumerate(config.rules):
        check_variables(rule_str, f"Rule {i + 1}")

    # Check rule files
    for rule_file in config.rule_files:
        rule_path = Path(rule_file)
        if not rule_path.exists():
            continue

        try:
            with open(rule_path) as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    check_variables(line, f"{rule_file}:{line_num}")
        except Exception:
            pass  # File read errors already caught

    return errors


if __name__ == "__main__":
    validate()
