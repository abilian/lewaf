"""CRS rule validation utility."""

from pathlib import Path
from typing import Any

from lewaf.integration import WAF


class CRSValidator:
    """Validate CRS rules work correctly with attack payloads."""

    def __init__(self, waf: WAF):
        """Initialize validator.

        Args:
            waf: WAF instance with CRS rules loaded
        """
        self.waf = waf
        self.results: list[dict[str, Any]] = []

    def validate_payload(
        self, rule_id: int, payload: str, should_block: bool = True
    ) -> bool:
        """Test single payload against a rule.

        Args:
            rule_id: Expected rule ID that should match
            payload: Attack payload to test
            should_block: Whether payload should be blocked

        Returns:
            True if test passed, False otherwise
        """
        tx = self.waf.new_transaction()
        tx.process_uri("/test", "POST")
        tx.add_request_body(
            payload.encode("utf-8", errors="ignore"), "application/json"
        )
        result = tx.process_request_body()

        blocked = result is not None
        passed = blocked == should_block

        # If blocked, check if it was the expected rule
        if blocked and result:
            matched_rule_id = result.get("rule_id")
            rule_match = matched_rule_id == rule_id if rule_id else True
        else:
            rule_match = not should_block

        test_passed = blocked == should_block and rule_match

        self.results.append(
            {
                "rule_id": rule_id,
                "payload": payload[:100],  # Truncate for readability
                "expected": "block" if should_block else "pass",
                "actual": "block" if blocked else "pass",
                "matched_rule": result.get("rule_id") if result else None,
                "passed": test_passed,
            }
        )

        return test_passed

    def validate_category(
        self, category: str, payloads: list[str], rule_id: int | None = None
    ) -> dict[str, Any]:
        """Test all payloads in a category.

        Args:
            category: Attack category name (e.g., "sqli", "xss")
            payloads: List of attack payloads
            rule_id: Expected rule ID (None means any detection)

        Returns:
            Summary dictionary with pass rate
        """
        passed = 0
        failed = 0

        for payload in payloads:
            if self.validate_payload(rule_id or 0, payload, should_block=True):
                passed += 1
            else:
                failed += 1

        return {
            "category": category,
            "total": len(payloads),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / len(payloads) if payloads else 0.0,
        }

    def get_coverage_report(self) -> dict[str, Any]:
        """Generate coverage report grouped by category.

        Returns:
            Report dictionary with statistics
        """
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r["passed"])

        # Group by rule ID
        rule_stats: dict[int, dict[str, int]] = {}
        for result in self.results:
            rule_id = result["rule_id"]
            if rule_id not in rule_stats:
                rule_stats[rule_id] = {"passed": 0, "failed": 0}

            if result["passed"]:
                rule_stats[rule_id]["passed"] += 1
            else:
                rule_stats[rule_id]["failed"] += 1

        return {
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": total_tests - passed_tests,
            "pass_rate": passed_tests / total_tests if total_tests else 0.0,
            "rule_stats": rule_stats,
        }

    def load_payloads_from_file(self, filepath: Path) -> list[str]:
        """Load attack payloads from a text file.

        Args:
            filepath: Path to payload file

        Returns:
            List of payloads (non-empty, non-comment lines)
        """
        if not filepath.exists():
            return []

        with filepath.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        payloads = []
        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                payloads.append(line)

        return payloads

    def print_summary(self) -> None:
        """Print formatted summary of validation results."""
        report = self.get_coverage_report()

        print("\n=== CRS Validation Summary ===")
        print(f"Total Tests: {report['total_tests']}")
        print(f"Passed: {report['passed']}")
        print(f"Failed: {report['failed']}")
        print(f"Pass Rate: {report['pass_rate'] * 100:.1f}%")

        if report["rule_stats"]:
            print("\nRule Statistics:")
            for rule_id, stats in sorted(report["rule_stats"].items()):
                total = stats["passed"] + stats["failed"]
                rate = stats["passed"] / total * 100 if total > 0 else 0
                print(f"  Rule {rule_id}: {stats['passed']}/{total} ({rate:.1f}%)")

        # Print failures if any
        failures = [r for r in self.results if not r["passed"]]
        if failures:
            print(f"\nFailed Tests ({len(failures)}):")
            for failure in failures[:10]:  # Show first 10
                print(f"  Rule {failure['rule_id']}: {failure['payload'][:80]}")
                print(
                    f"    Expected: {failure['expected']}, Got: {failure['actual']} (Rule: {failure['matched_rule']})"
                )
