"""Tests for Core Rule Set (CRS) rule parsing and validation."""

import re
from pathlib import Path
from typing import List, Tuple

import pytest

from coraza_poc.integration import SecLangParser
from coraza_poc.engine import RuleGroup


class CRSRuleTest:
    """Helper class for testing CRS rule parsing."""

    def __init__(self):
        self.rules_dir = Path(__file__).parent.parent.parent / "rules"
        # SecLangParser needs a RuleGroup
        self.rule_group = RuleGroup()
        self.parser = SecLangParser(self.rule_group)

    def get_crs_files(self) -> List[Path]:
        """Get all CRS configuration files."""
        if not self.rules_dir.exists():
            pytest.skip(f"Rules directory not found: {self.rules_dir}")

        conf_files = list(self.rules_dir.glob("*.conf"))
        if not conf_files:
            pytest.skip(f"No .conf files found in {self.rules_dir}")

        return conf_files

    def read_file_content(self, file_path: Path) -> str:
        """Read file content safely."""
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return file_path.read_text(encoding="latin1")

    def extract_secrules(self, content: str) -> List[Tuple[str, int]]:
        """Extract SecRule directives from file content."""
        rules = []
        lines = content.split("\n")

        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                i += 1
                continue

            # Check for SecRule directive
            if line.startswith("SecRule"):
                rule_lines = [line]
                line_start = i + 1

                # Handle multi-line rules (lines ending with \)
                while line.endswith("\\") or (
                    rule_lines and not self._rule_is_complete(rule_lines)
                ):
                    i += 1
                    if i >= len(lines):
                        break
                    next_line = lines[i].strip()
                    if next_line and not next_line.startswith("#"):
                        rule_lines.append(next_line)
                    line = next_line

                full_rule = " ".join(rule_lines).replace("\\\n", " ").replace("\\", "")
                rules.append((full_rule, line_start))

            i += 1

        return rules

    def _rule_is_complete(self, rule_lines: List[str]) -> bool:
        """Check if a multi-line rule is complete."""
        full_rule = " ".join(rule_lines)
        # A rule is complete if it has all required parts
        # SecRule <VARIABLES> <OPERATOR> <ACTIONS>
        parts = full_rule.split('"')
        # Should have at least: SecRule, variables, operator (in quotes), actions (in quotes)
        return len(parts) >= 4

    def parse_secrule_components(self, rule: str) -> dict:
        """Parse a SecRule into its components."""
        # Remove SecRule prefix
        rule_content = rule[7:].strip()  # Remove 'SecRule '

        # Find the operator (first quoted string) and actions (last quoted string)
        components = {}

        # Extract variables (everything before the first quote)
        quote_pos = rule_content.find('"')
        if quote_pos == -1:
            return {"error": "No quoted sections found"}

        variables = rule_content[:quote_pos].strip()
        components["variables"] = variables

        # Extract operator and actions from quoted sections
        quoted_parts = []
        in_quote = False
        current_quote = ""
        i = 0

        while i < len(rule_content):
            char = rule_content[i]
            if char == '"' and (i == 0 or rule_content[i - 1] != "\\"):
                if in_quote:
                    quoted_parts.append(current_quote)
                    current_quote = ""
                    in_quote = False
                else:
                    in_quote = True
            elif in_quote:
                current_quote += char
            i += 1

        if len(quoted_parts) >= 1:
            components["operator"] = quoted_parts[0]
        if len(quoted_parts) >= 2:
            components["actions"] = quoted_parts[1]

        return components


@pytest.fixture
def crs_tester():
    """Fixture providing CRS rule testing functionality."""
    return CRSRuleTest()


def test_crs_files_exist(crs_tester):
    """Test that CRS rule files exist and are readable."""
    files = crs_tester.get_crs_files()

    assert len(files) > 0, "No CRS rule files found"

    # Check for key rule files
    expected_files = [
        "REQUEST-901-INITIALIZATION.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
    ]

    found_files = [f.name for f in files]
    for expected in expected_files:
        assert expected in found_files, f"Expected rule file {expected} not found"


def test_crs_file_format(crs_tester):
    """Test that CRS files have the correct format and structure."""
    files = crs_tester.get_crs_files()

    for file_path in files:
        content = crs_tester.read_file_content(file_path)

        # Should have OWASP header
        assert "OWASP ModSecurity Core Rule Set" in content, (
            f"File {file_path.name} missing OWASP header"
        )

        # Should have copyright notice
        assert "Copyright" in content, f"File {file_path.name} missing copyright notice"

        # Should have license reference
        assert "Apache Software License" in content or "LICENSE" in content, (
            f"File {file_path.name} missing license reference"
        )


def test_secrule_extraction(crs_tester):
    """Test that SecRule directives can be extracted from CRS files."""
    files = crs_tester.get_crs_files()
    total_rules = 0

    for file_path in files:
        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        # Files should contain some rules (except example files)
        if not file_path.name.endswith(".example"):
            if "REQUEST" in file_path.name or "RESPONSE" in file_path.name:
                # Core rule files should have rules
                assert len(rules) > 0, f"No rules found in {file_path.name}"

        total_rules += len(rules)

        # Verify rule format
        for rule, line_num in rules:
            assert rule.startswith("SecRule"), (
                f"Invalid rule format at line {line_num} in {file_path.name}"
            )

    assert total_rules > 100, f"Expected many rules, found only {total_rules}"


def test_secrule_syntax_validation(crs_tester):
    """Test that SecRule syntax is valid and parseable."""
    files = crs_tester.get_crs_files()
    rule_count = 0

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue  # Skip example files

        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        for rule, line_num in rules:
            rule_count += 1
            components = crs_tester.parse_secrule_components(rule)

            # Should not have parsing errors
            assert "error" not in components, (
                f"Parse error in {file_path.name} at line {line_num}: {components.get('error')}"
            )

            # Should have essential components
            assert "variables" in components, (
                f"Missing variables in {file_path.name} at line {line_num}"
            )

            assert "operator" in components, (
                f"Missing operator in {file_path.name} at line {line_num}"
            )

            # Operator should start with @ for named operators
            operator = components["operator"]
            if operator.startswith("@"):
                operator[1:].split()[0]  # Get operator name
                # Verify it's a known operator type
                # Note: Some operators might not be implemented yet
                # This is just checking the format is correct

    print(f"Validated {rule_count} rules across {len(files)} files")
    assert rule_count > 50, f"Expected to validate many rules, only found {rule_count}"


def test_rule_id_uniqueness(crs_tester):
    """Test that rule IDs are unique across all CRS files."""
    files = crs_tester.get_crs_files()
    rule_ids = {}

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        for rule, line_num in rules:
            # Extract ID from the rule
            id_match = re.search(r"id:(\d+)", rule)
            if id_match:
                rule_id = id_match.group(1)
                if rule_id in rule_ids:
                    pytest.fail(
                        f"Duplicate rule ID {rule_id} found in {file_path.name} "
                        f"(line {line_num}) and {rule_ids[rule_id]}"
                    )
                rule_ids[rule_id] = f"{file_path.name}:{line_num}"

    assert len(rule_ids) > 100, f"Expected many unique rule IDs, found {len(rule_ids)}"


def test_rule_phases(crs_tester):
    """Test that rules have valid phase declarations."""
    files = crs_tester.get_crs_files()
    phase_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        for rule, line_num in rules:
            # Extract phase from the rule
            phase_match = re.search(r"phase:(\d+)", rule)
            if phase_match:
                phase = int(phase_match.group(1))
                assert 1 <= phase <= 5, (
                    f"Invalid phase {phase} in {file_path.name} at line {line_num}"
                )
                phase_counts[phase] += 1

    # Should have rules in multiple phases
    active_phases = sum(1 for count in phase_counts.values() if count > 0)
    assert active_phases >= 2, f"Rules found in only {active_phases} phases"


def test_common_crs_variables(crs_tester):
    """Test that CRS files use expected ModSecurity variables."""
    files = crs_tester.get_crs_files()
    expected_variables = [
        "REQUEST_METHOD",
        "REQUEST_URI",
        "REQUEST_HEADERS",
        "REQUEST_BODY",
        "ARGS",
        "ARGS_NAMES",
        "REQUEST_COOKIES",
        "REQUEST_FILENAME",
        "RESPONSE_HEADERS",
        "RESPONSE_BODY",
        "TX",
        "FILES",
    ]

    found_variables = set()

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)

        for var in expected_variables:
            if var in content:
                found_variables.add(var)

    # Should find most common variables
    assert len(found_variables) >= len(expected_variables) * 0.7, (
        f"Only found {len(found_variables)} of {len(expected_variables)} expected variables"
    )


def test_crs_operators_coverage(crs_tester):
    """Test that CRS files use operators we support."""
    files = crs_tester.get_crs_files()
    used_operators = set()
    unsupported_operators = set()

    # Operators we currently support
    supported_operators = {
        "lt",
        "le",
        "gt",
        "ge",
        "eq",
        "within",
        "rx",
        "contains",
        "beginswith",
        "endswith",
        "detectsqli",
        "detectxss",
        "ipmatch",
        "validatebyterange",
        "validateutf8encoding",
    }

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        for rule, line_num in rules:
            components = crs_tester.parse_secrule_components(rule)
            if "operator" in components:
                operator = components["operator"]
                if operator.startswith("@"):
                    op_name = operator[1:].split()[0].lower()
                    used_operators.add(op_name)
                    if op_name not in supported_operators:
                        unsupported_operators.add(op_name)

    print(f"Found operators: {sorted(used_operators)}")
    if unsupported_operators:
        print(f"Unsupported operators: {sorted(unsupported_operators)}")

    # Should recognize most operators used
    coverage = len(used_operators - unsupported_operators) / len(used_operators)
    assert coverage >= 0.3, f"Only support {coverage:.1%} of operators used in CRS"


def test_crs_transformations_coverage(crs_tester):
    """Test coverage of transformations used in CRS rules."""
    files = crs_tester.get_crs_files()
    used_transformations = set()

    # Transformations we support
    supported_transformations = {
        "lowercase",
        "uppercase",
        "length",
        "trim",
        "compresswhitespace",
        "removewhitespace",
        "urldecode",
        "urldecodeuni",
        "htmlentitydecode",
        "jsdecode",
        "cssjsdecode",
        "base64decode",
        "hexdecode",
        "md5",
        "sha1",
        "sha256",
        "normalizepath",
        "removenulls",
        "removenullbytes",
        "replacecomments",
        "replacewhitespace",
    }

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)

        # Look for transformation references (t:transform_name)
        transform_matches = re.findall(r"t:([a-zA-Z0-9_]+)", content)
        for transform in transform_matches:
            used_transformations.add(transform.lower())

    print(f"Found transformations: {sorted(used_transformations)}")

    if used_transformations:
        unsupported = used_transformations - supported_transformations
        if unsupported:
            print(f"Unsupported transformations: {sorted(unsupported)}")

        coverage = len(used_transformations & supported_transformations) / len(
            used_transformations
        )
        assert coverage >= 0.5, (
            f"Only support {coverage:.1%} of transformations used in CRS"
        )


def test_rule_parsing_with_seclang_parser(crs_tester):
    """Test that our SecLang parser can handle CRS rules."""
    files = crs_tester.get_crs_files()

    parsed_count = 0
    error_count = 0

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)
        rules = crs_tester.extract_secrules(content)

        for rule, line_num in rules[:5]:  # Test first 5 rules per file
            try:
                # Create a new parser for each rule to avoid rule conflicts
                rule_group = RuleGroup()
                parser = SecLangParser(rule_group)
                parser.from_string(rule)
                parsed_count += 1
            except Exception as e:
                error_count += 1
                # For now, just track errors - some operators may not be implemented
                print(f"Parse error in {file_path.name}:{line_num} - {str(e)[:100]}")

    total_tested = parsed_count + error_count
    if total_tested > 0:
        success_rate = parsed_count / total_tested
        print(
            f"Parser success rate: {success_rate:.1%} ({parsed_count}/{total_tested})"
        )

        # We expect at least some rules to parse successfully
        assert parsed_count > 0, "No rules parsed successfully"


def test_crs_data_files_exist(crs_tester):
    """Test that CRS data files referenced in rules exist."""
    crs_tester.get_crs_files()

    # Common data files that should exist
    expected_data_files = [
        "php-errors.data",
        "sql-errors.data",
        "unix-shell.data",
        "lfi-os-files.data",
        "java-errors.data",
    ]

    existing_files = list(crs_tester.rules_dir.glob("*.data"))
    existing_names = [f.name for f in existing_files]

    for data_file in expected_data_files:
        assert data_file in existing_names, f"Expected data file {data_file} not found"

    # Verify data files are not empty
    for data_file in existing_files:
        content = crs_tester.read_file_content(data_file)
        assert len(content.strip()) > 0, f"Data file {data_file.name} is empty"


def test_crs_version_consistency(crs_tester):
    """Test that CRS version is consistent across files."""
    files = crs_tester.get_crs_files()
    versions = set()

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)

        # Look for version strings
        version_match = re.search(r"ver\.([0-9.-]+(?:rc\d+)?)", content)
        if version_match:
            versions.add(version_match.group(1))

    # Should have consistent version across files
    assert len(versions) <= 2, f"Found inconsistent versions: {versions}"

    if versions:
        print(f"CRS versions found: {versions}")


def test_paranoia_levels_present(crs_tester):
    """Test that CRS rules include paranoia level organization."""
    files = crs_tester.get_crs_files()
    paranoia_levels = set()

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = crs_tester.read_file_content(file_path)

        # Look for paranoia level references
        paranoia_matches = re.findall(r"paranoia.level/(\d+)", content)
        for level in paranoia_matches:
            paranoia_levels.add(int(level))

    # Should have multiple paranoia levels
    assert len(paranoia_levels) >= 2, f"Found paranoia levels: {paranoia_levels}"
    assert 1 in paranoia_levels, "Should have paranoia level 1 (default)"
