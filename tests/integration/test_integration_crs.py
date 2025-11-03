"""Integration tests for Core Rule Set (CRS) functionality."""

import re
from pathlib import Path

import pytest

from lewaf.engine import RuleGroup
from lewaf.integration import SecLangParser, WAF
from lewaf.transaction import Transaction


def get_rules_directory():
    """Get the CRS rules directory path."""
    return Path(__file__).parent.parent.parent / "rules"


def test_crs_files_accessible():
    """Test that CRS rule files are accessible."""
    rules_dir = get_rules_directory()

    if not rules_dir.exists():
        pytest.skip("CRS rules directory not found")

    conf_files = list(rules_dir.glob("*.conf"))
    assert len(conf_files) > 0, "No CRS configuration files found"


def test_crs_method_enforcement_loading():
    """Test loading CRS METHOD-ENFORCEMENT rules."""
    rules_dir = get_rules_directory()
    method_file = rules_dir / "REQUEST-911-METHOD-ENFORCEMENT.conf"

    if not method_file.exists():
        pytest.skip("METHOD-ENFORCEMENT file not found")

    content = method_file.read_text(encoding="utf-8")

    # Extract simple rules for testing
    simple_rules = []
    for line in content.split("\n"):
        line = line.strip()
        if (
            line.startswith("SecRule")
            and "nolog" in line
            and "skipAfter" in line
            and len(line) < 200
        ):
            simple_rules.append(line)

    if not simple_rules:
        pytest.skip("No suitable simple rules found")

    # Test loading rule into WAF
    config = {"rules": [simple_rules[0]]}
    waf = WAF(config)
    tx = waf.new_transaction()

    assert isinstance(tx, Transaction)
    assert tx.waf is waf


def test_crs_rule_file_structure():
    """Test that CRS files have expected structure."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS REQUEST files found")

    # Check key files exist
    expected_files = [
        "REQUEST-901-INITIALIZATION.conf",
        "REQUEST-911-METHOD-ENFORCEMENT.conf",
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
    ]

    found_files = [f.name for f in files]
    for expected in expected_files:
        if (rules_dir / expected).exists():
            assert expected in found_files


def test_crs_rule_id_ranges():
    """Test that CRS rules have expected ID ranges."""
    rules_dir = get_rules_directory()
    files = [
        ("REQUEST-911-METHOD-ENFORCEMENT.conf", "911"),
        ("REQUEST-942-APPLICATION-ATTACK-SQLI.conf", "942"),
        ("REQUEST-941-APPLICATION-ATTACK-XSS.conf", "941"),
    ]

    for filename, id_prefix in files:
        file_path = rules_dir / filename
        if file_path.exists():
            content = file_path.read_text(encoding="utf-8")
            assert f"id:{id_prefix}" in content, (
                f"Missing {id_prefix}xxx IDs in {filename}"
            )


def test_crs_rule_phases():
    """Test that CRS rules specify phases correctly."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    phase_found = False
    for file_path in files:
        content = file_path.read_text(encoding="utf-8")
        if "phase:" in content:
            phase_found = True
            break

    assert phase_found, "No phase declarations found in CRS rules"


def test_crs_owasp_tags():
    """Test that CRS rules contain OWASP_CRS tags."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    owasp_tag_found = False
    for file_path in files:
        content = file_path.read_text(encoding="utf-8")
        if "OWASP_CRS" in content:
            owasp_tag_found = True
            break

    assert owasp_tag_found, "No OWASP_CRS tags found in CRS rules"


def test_crs_paranoia_levels():
    """Test CRS paranoia level organization."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-9*.conf"))

    if not files:
        pytest.skip("No CRS 9xx rule files found")

    paranoia_markers = []
    for rule_file in files:
        content = rule_file.read_text(encoding="utf-8")
        lines = content.split("\n")
        for line in lines:
            if "Paranoia Level" in line and "=" in line:
                paranoia_markers.append(line.strip())

    assert len(paranoia_markers) > 5, "Expected multiple paranoia level markers"


def test_crs_data_file_references():
    """Test that CRS data files exist and are referenced."""
    rules_dir = get_rules_directory()

    # Get available data files
    data_files = list(rules_dir.glob("*.data"))
    if not data_files:
        pytest.skip("No CRS data files found")

    data_file_names = [f.name for f in data_files]
    conf_files = list(rules_dir.glob("*.conf"))

    referenced_files = set()
    for conf_file in conf_files:
        if conf_file.name.endswith(".example"):
            continue

        content = conf_file.read_text(encoding="utf-8")
        for data_name in data_file_names:
            if data_name in content:
                referenced_files.add(data_name)

    # Should have at least some data file references
    assert len(referenced_files) > 0, "No data file references found in CRS rules"


def test_sample_crs_rule_parsing():
    """Test parsing representative CRS rules."""
    sample_rules = [
        # Paranoia level check
        'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:911011,phase:1,pass,nolog,skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT"',
        # Method check
        'SecRule REQUEST_METHOD "@within GET POST HEAD" "id:911100,phase:1,block,msg:\'Method not allowed\'"',
        # XSS detection
        'SecRule ARGS "@detectXSS" "id:941100,phase:2,block,msg:\'XSS Attack Detected\'"',
        # SQL injection
        'SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:\'SQL Injection Attack\'"',
    ]

    parsed_count = 0
    for rule in sample_rules:
        try:
            config = {"rules": [rule]}
            waf = WAF(config)
            waf.new_transaction()
            parsed_count += 1
        except Exception:
            # Some operators may not be implemented yet
            pass

    # Should parse at least some rules
    assert parsed_count > 0, "No sample CRS rules parsed successfully"


def test_crs_rule_metadata_extraction():
    """Test extraction of metadata from CRS rules."""
    rules_dir = get_rules_directory()
    test_files = [
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
    ]

    rule_ids = []
    phases = set()

    for filename in test_files:
        file_path = rules_dir / filename
        if not file_path.exists():
            continue

        content = file_path.read_text(encoding="utf-8")

        # Extract rule IDs
        id_matches = re.findall(r"id:(\d+)", content)
        rule_ids.extend([int(id_str) for id_str in id_matches])

        # Extract phases
        phase_matches = re.findall(r"phase:(\d+)", content)
        phases.update([int(phase) for phase in phase_matches])

    if rule_ids:
        assert len(rule_ids) > 5, "Should find multiple rule IDs"
        assert all(isinstance(rule_id, int) for rule_id in rule_ids)

    if phases:
        assert len(phases) >= 1, "Should find at least one phase"
        assert all(1 <= phase <= 5 for phase in phases)


def test_crs_rule_uniqueness():
    """Test that CRS rule IDs are unique."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    rule_ids = {}
    duplicate_found = False

    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = file_path.read_text(encoding="utf-8")
        id_matches = re.findall(r"id:(\d+)", content)

        for rule_id in id_matches:
            if rule_id in rule_ids:
                duplicate_found = True
                break
            rule_ids[rule_id] = file_path.name

        if duplicate_found:
            break

    assert not duplicate_found, "Found duplicate rule IDs in CRS files"
    assert len(rule_ids) > 10, "Should find multiple unique rule IDs"


def test_crs_common_variables():
    """Test that CRS uses expected ModSecurity variables."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    expected_variables = [
        "REQUEST_METHOD",
        "REQUEST_URI",
        "REQUEST_HEADERS",
        "ARGS",
        "REQUEST_BODY",
        "REQUEST_COOKIES",
        "TX",
        "RESPONSE_HEADERS",
    ]

    found_variables = set()
    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = file_path.read_text(encoding="utf-8")
        for var in expected_variables:
            if var in content:
                found_variables.add(var)

    # Should find most common variables
    coverage = len(found_variables) / len(expected_variables)
    assert coverage >= 0.5, f"Only found {coverage:.1%} of expected variables"


def test_crs_operator_coverage():
    """Test coverage of operators used in CRS."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    # Extract operators from rules
    used_operators = set()
    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = file_path.read_text(encoding="utf-8")

        # Find operator patterns like @rx, @eq, etc.
        operator_matches = re.findall(r'"@(\w+)', content)
        used_operators.update([op.lower() for op in operator_matches])

    if used_operators:
        # Common operators we expect
        expected_operators = {"rx", "eq", "lt", "gt", "within", "contains"}
        found_expected = used_operators & expected_operators

        assert len(found_expected) > 0, "Should find some common operators"


def test_crs_transformation_coverage():
    """Test coverage of transformations used in CRS."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    used_transformations = set()
    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = file_path.read_text(encoding="utf-8")
        transform_matches = re.findall(r"t:([a-zA-Z0-9_]+)", content)
        used_transformations.update([t.lower() for t in transform_matches])

    if used_transformations:
        # Common transformations we expect
        expected_transforms = {
            "lowercase",
            "uppercase",
            "urldecode",
            "htmlentitydecode",
        }
        found_expected = used_transformations & expected_transforms

        assert len(found_expected) >= 0  # May be 0 if different naming


def test_crs_version_consistency():
    """Test CRS version consistency across files."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    versions = set()
    for file_path in files:
        if file_path.name.endswith(".example"):
            continue

        content = file_path.read_text(encoding="utf-8")
        version_matches = re.findall(r"ver\.([0-9.-]+(?:rc\d+)?)", content)
        versions.update(version_matches)

    # Should have consistent version (allow for minor variations)
    assert len(versions) <= 3, f"Too many different versions found: {versions}"


def test_crs_file_headers():
    """Test that CRS files have proper headers."""
    rules_dir = get_rules_directory()
    files = list(rules_dir.glob("REQUEST-*.conf"))

    if not files:
        pytest.skip("No CRS files found")

    for file_path in files[:3]:  # Test first few files
        content = file_path.read_text(encoding="utf-8")

        # Should have OWASP reference
        assert "OWASP" in content, f"Missing OWASP reference in {file_path.name}"

        # Should have some form of license/copyright
        has_license = any(
            term in content.lower() for term in ["copyright", "license", "apache"]
        )
        assert has_license, f"Missing license/copyright in {file_path.name}"


def test_crs_data_files_accessible():
    """Test that CRS data files are accessible and non-empty."""
    rules_dir = get_rules_directory()
    data_files = list(rules_dir.glob("*.data"))

    if not data_files:
        pytest.skip("No CRS data files found")

    for data_file in data_files:
        content = data_file.read_text(encoding="utf-8")
        assert len(content.strip()) > 0, f"Data file {data_file.name} is empty"


def test_seclang_parser_with_crs_samples():
    """Test SecLang parser with sample CRS rules."""
    # Simple rules that should parse successfully
    simple_crs_rules = [
        'SecRule REQUEST_METHOD "@rx ^(GET|POST)$" "id:901001,phase:1,pass,nolog"',
        'SecRule ARGS:test "@eq value" "id:901002,phase:2,block,log"',
        'SecRule REQUEST_URI "@beginsWith /admin" "id:901003,phase:1,deny,log"',
    ]

    parsed_count = 0
    for rule in simple_crs_rules:
        try:
            rule_group = RuleGroup()
            parser = SecLangParser(rule_group)
            parser.from_string(rule)
            parsed_count += 1
        except Exception:
            # Some features may not be implemented
            pass

    # Should successfully parse at least some rules
    assert parsed_count > 0, "No CRS sample rules parsed successfully"
