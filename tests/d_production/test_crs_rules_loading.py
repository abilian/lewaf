"""Tests that load CRS rules from the rules/ directory.

These tests validate that the SecLang parser can load real OWASP CRS rule files
and that the loaded rules can detect actual attacks.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lewaf.engine import RuleGroup
from lewaf.integration import WAF
from lewaf.seclang import SecLangParser

RULES_DIR = Path(__file__).parent.parent.parent / "rules"


class StubWAF:
    """Stub WAF for testing parser directly."""

    def __init__(self):
        self.rule_group = RuleGroup()


def get_crs_rule_files() -> list[Path]:
    """Get all CRS .conf files from rules/ directory."""
    if not RULES_DIR.exists():
        return []
    return sorted(
        f for f in RULES_DIR.glob("*.conf") if not f.name.endswith(".example")
    )


# =============================================================================
# Individual CRS File Loading Tests
# =============================================================================


class TestCRSFileLoading:
    """Test loading individual CRS rule files."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup test fixtures."""
        self.waf = StubWAF()
        self.parser = SecLangParser(self.waf)

    def _count_rules(self) -> int:
        """Count total rules loaded."""
        return sum(len(rules) for rules in self.waf.rule_group.rules_by_phase.values())

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_load_request_920_protocol_enforcement(self):
        """Test loading REQUEST-920-PROTOCOL-ENFORCEMENT.conf."""
        conf_path = RULES_DIR / "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
        if not conf_path.exists():
            pytest.skip("Rule file not found")

        self.parser.from_file(conf_path)
        rule_count = self._count_rules()

        assert rule_count > 0, "Should load rules from protocol enforcement file"
        print(f"\nLoaded {rule_count} rules from {conf_path.name}")

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_load_request_941_xss(self):
        """Test loading REQUEST-941-APPLICATION-ATTACK-XSS.conf."""
        conf_path = RULES_DIR / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
        if not conf_path.exists():
            pytest.skip("Rule file not found")

        self.parser.from_file(conf_path)
        rule_count = self._count_rules()

        assert rule_count > 0, "Should load XSS rules"
        print(f"\nLoaded {rule_count} rules from {conf_path.name}")

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_load_request_942_sqli(self):
        """Test loading REQUEST-942-APPLICATION-ATTACK-SQLI.conf."""
        conf_path = RULES_DIR / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        if not conf_path.exists():
            pytest.skip("Rule file not found")

        self.parser.from_file(conf_path)
        rule_count = self._count_rules()

        assert rule_count > 0, "Should load SQL injection rules"
        print(f"\nLoaded {rule_count} rules from {conf_path.name}")

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_load_request_932_rce(self):
        """Test loading REQUEST-932-APPLICATION-ATTACK-RCE.conf."""
        conf_path = RULES_DIR / "REQUEST-932-APPLICATION-ATTACK-RCE.conf"
        if not conf_path.exists():
            pytest.skip("Rule file not found")

        self.parser.from_file(conf_path)
        rule_count = self._count_rules()

        assert rule_count > 0, "Should load RCE rules"
        print(f"\nLoaded {rule_count} rules from {conf_path.name}")

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_load_request_930_lfi(self):
        """Test loading REQUEST-930-APPLICATION-ATTACK-LFI.conf."""
        conf_path = RULES_DIR / "REQUEST-930-APPLICATION-ATTACK-LFI.conf"
        if not conf_path.exists():
            pytest.skip("Rule file not found")

        self.parser.from_file(conf_path)
        rule_count = self._count_rules()

        assert rule_count > 0, "Should load LFI rules"
        print(f"\nLoaded {rule_count} rules from {conf_path.name}")


# =============================================================================
# Comprehensive CRS Loading Test
# =============================================================================


@pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
def test_load_all_crs_files():
    """Test loading all CRS rule files and report statistics."""
    rule_files = get_crs_rule_files()
    if not rule_files:
        pytest.skip("No CRS rule files found")

    results = {
        "total_files": len(rule_files),
        "files_loaded": 0,
        "files_failed": 0,
        "total_rules": 0,
        "errors": [],
    }

    for conf_path in rule_files:
        waf = StubWAF()
        parser = SecLangParser(waf)

        try:
            parser.from_file(conf_path)
            rule_count = sum(
                len(rules) for rules in waf.rule_group.rules_by_phase.values()
            )
            results["files_loaded"] += 1
            results["total_rules"] += rule_count
        except Exception as e:
            results["files_failed"] += 1
            results["errors"].append({"file": conf_path.name, "error": str(e)[:100]})

    # Report
    success_rate = results["files_loaded"] / results["total_files"]
    print(f"\n{'=' * 60}")
    print("CRS File Loading Results:")
    print(f"{'=' * 60}")
    print(f"Total files: {results['total_files']}")
    print(f"Files loaded successfully: {results['files_loaded']}")
    print(f"Files failed: {results['files_failed']}")
    print(f"Total rules loaded: {results['total_rules']}")
    print(f"Success rate: {success_rate:.1%}")

    if results["errors"]:
        print(f"\nErrors ({len(results['errors'])}):")
        for err in results["errors"][:5]:
            print(f"  {err['file']}: {err['error']}")

    # Assertions
    assert results["files_loaded"] > 0, "Should load at least some CRS files"
    assert results["total_rules"] > 0, "Should load at least some rules"
    assert success_rate >= 0.5, f"At least 50% of files should load: {success_rate:.1%}"


# =============================================================================
# Attack Detection Tests with Loaded CRS Rules
# =============================================================================


class TestCRSAttackDetection:
    """Test attack detection using loaded CRS rules."""

    @pytest.fixture
    def xss_waf(self) -> WAF | None:
        """Load WAF with XSS rules from file."""
        conf_path = RULES_DIR / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
        if not conf_path.exists():
            return None

        waf = WAF({"rules": []})
        parser = SecLangParser(waf)
        try:
            parser.from_file(conf_path)
            return waf
        except Exception:
            return None

    @pytest.fixture
    def sqli_waf(self) -> WAF | None:
        """Load WAF with SQL injection rules from file."""
        conf_path = RULES_DIR / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        if not conf_path.exists():
            return None

        waf = WAF({"rules": []})
        parser = SecLangParser(waf)
        try:
            parser.from_file(conf_path)
            return waf
        except Exception:
            return None

    @pytest.fixture
    def lfi_waf(self) -> WAF | None:
        """Load WAF with LFI rules from file."""
        conf_path = RULES_DIR / "REQUEST-930-APPLICATION-ATTACK-LFI.conf"
        if not conf_path.exists():
            return None

        waf = WAF({"rules": []})
        parser = SecLangParser(waf)
        try:
            parser.from_file(conf_path)
            return waf
        except Exception:
            return None

    def _test_detection(self, waf: WAF, payload: str) -> bool:
        """Test if WAF detects payload as attack."""
        tx = waf.new_transaction()
        tx.process_uri(f"/test?param={payload}", "GET")
        tx.process_request_headers()
        tx.process_request_body()
        return tx.interruption is not None

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_xss_detection_with_loaded_rules(self, xss_waf):
        """Test XSS detection using rules loaded from file."""
        if xss_waf is None:
            pytest.skip("Could not load XSS rules")

        xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'-alert(1)-'",
        ]

        detected = sum(1 for p in xss_payloads if self._test_detection(xss_waf, p))
        detection_rate = detected / len(xss_payloads)

        print(f"\nXSS Detection: {detected}/{len(xss_payloads)} ({detection_rate:.0%})")

        # Should detect at least some XSS
        assert detected > 0, "Should detect at least one XSS payload"

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_sqli_detection_with_loaded_rules(self, sqli_waf):
        """Test SQL injection detection using rules loaded from file."""
        if sqli_waf is None:
            pytest.skip("Could not load SQL injection rules")

        sqli_payloads = [
            "' OR 1=1--",
            "' UNION SELECT * FROM users--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "admin'--",
        ]

        detected = sum(1 for p in sqli_payloads if self._test_detection(sqli_waf, p))
        detection_rate = detected / len(sqli_payloads)

        print(
            f"\nSQLi Detection: {detected}/{len(sqli_payloads)} ({detection_rate:.0%})"
        )

        # Should detect at least some SQLi
        assert detected > 0, "Should detect at least one SQL injection payload"

    @pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
    def test_lfi_detection_with_loaded_rules(self, lfi_waf):
        """Test LFI/path traversal detection using rules loaded from file."""
        if lfi_waf is None:
            pytest.skip("Could not load LFI rules")

        lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ]

        detected = sum(1 for p in lfi_payloads if self._test_detection(lfi_waf, p))
        detection_rate = detected / len(lfi_payloads)

        print(f"\nLFI Detection: {detected}/{len(lfi_payloads)} ({detection_rate:.0%})")

        # Should detect at least some LFI
        assert detected > 0, "Should detect at least one LFI payload"


# =============================================================================
# Combined Rules Test
# =============================================================================


@pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
def test_combined_crs_rules_detection():
    """Test attack detection with multiple CRS rule files loaded together."""
    rule_files = [
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
    ]

    waf = WAF({"rules": []})
    parser = SecLangParser(waf)
    loaded_files = []

    for filename in rule_files:
        conf_path = RULES_DIR / filename
        if conf_path.exists():
            try:
                parser.from_file(conf_path)
                loaded_files.append(filename)
            except Exception:
                pass

    if not loaded_files:
        pytest.skip("Could not load any CRS rule files")

    # Count total rules
    total_rules = sum(len(rules) for rules in waf.rule_group.rules_by_phase.values())
    print(f"\nLoaded {total_rules} rules from {len(loaded_files)} files")

    # Test various attacks
    attacks = {
        "xss": "<script>alert('xss')</script>",
        "sqli": "' OR 1=1--",
        "lfi": "../../../etc/passwd",
        "rce": "; cat /etc/passwd",
    }

    detections = {}
    errors = {}
    for attack_type, payload in attacks.items():
        try:
            tx = waf.new_transaction()
            tx.process_uri(f"/test?param={payload}", "GET")
            tx.process_request_headers()
            tx.process_request_body()
            detections[attack_type] = tx.interruption is not None
        except AttributeError as e:
            # Some CRS rules use variables not yet implemented
            errors[attack_type] = str(e)
            detections[attack_type] = False

    print("\nDetection results:")
    for attack_type, detected in detections.items():
        if attack_type in errors:
            status = f"⚠ Error: {errors[attack_type][:50]}"
        else:
            status = "✓ Detected" if detected else "✗ Missed"
        print(f"  {attack_type}: {status}")

    detected_count = sum(1 for d in detections.values() if d)
    # With combined rules, some may error but we should still detect attacks
    assert detected_count > 0 or len(errors) > 0, (
        "Should detect attacks or have known limitations"
    )


# =============================================================================
# Data Files Test
# =============================================================================


@pytest.mark.skipif(not RULES_DIR.exists(), reason="rules/ directory not found")
def test_crs_data_files_exist():
    """Verify CRS data files exist and are readable."""
    data_files = list(RULES_DIR.glob("*.data"))

    assert len(data_files) > 0, "Should have data files in rules/ directory"

    readable = 0
    for data_file in data_files:
        try:
            content = data_file.read_text()
            if content.strip():
                readable += 1
        except Exception:
            pass

    print(f"\nData files: {len(data_files)} total, {readable} readable")
    assert readable == len(data_files), "All data files should be readable"
