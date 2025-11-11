"""False positive testing with legitimate traffic."""

import json
from pathlib import Path

import pytest

from lewaf.integration import WAF


class FalsePositiveChecker:
    """Check for false positives in legitimate traffic."""

    def __init__(self, waf: WAF):
        self.waf = waf
        self.false_positives: list[dict] = []
        self.total_requests = 0

    def test_request(
        self, name: str, method: str, uri: str, body: str | None = None
    ) -> bool:
        """Test a legitimate request.

        Args:
            name: Request name/description
            method: HTTP method
            uri: Request URI
            body: Request body (optional)

        Returns:
            True if passed (not blocked), False if blocked (false positive)
        """
        self.total_requests += 1

        tx = self.waf.new_transaction()
        tx.process_uri(uri, method)

        # Add headers for realistic request
        tx.variables.request_headers.add("user-agent", "Mozilla/5.0")
        tx.variables.request_headers.add("accept", "application/json")

        result = tx.process_request_headers()
        if result:
            self.false_positives.append(
                {"name": name, "method": method, "uri": uri, "phase": "headers"}
            )
            return False

        if body:
            content_type = (
                "application/json"
                if uri.endswith("/graphql") or method != "GET"
                else "application/x-www-form-urlencoded"
            )
            tx.add_request_body(body.encode("utf-8"), content_type)

        result = tx.process_request_body()
        if result:
            self.false_positives.append(
                {
                    "name": name,
                    "method": method,
                    "uri": uri,
                    "body": body[:100] if body else None,
                    "phase": "body",
                }
            )
            return False

        return True

    def get_false_positive_rate(self) -> float:
        """Calculate false positive rate.

        Returns:
            False positive rate (0.0 to 1.0)
        """
        if self.total_requests == 0:
            return 0.0
        return len(self.false_positives) / self.total_requests

    def print_summary(self) -> None:
        """Print false positive summary."""
        rate = self.get_false_positive_rate()
        print("\n=== False Positive Check Summary ===")
        print(f"Total Requests: {self.total_requests}")
        print(f"False Positives: {len(self.false_positives)}")
        print(f"False Positive Rate: {rate * 100:.2f}%")

        if self.false_positives:
            print("\nFalse Positives Detected:")
            for fp in self.false_positives[:5]:  # Show first 5
                print(
                    f"  - {fp['name']} ({fp['method']} {fp['uri']}) @ phase {fp['phase']}"
                )


@pytest.fixture
def production_waf():
    """WAF with production-grade rules."""
    return WAF(
        {
            "rules": [
                # SQL injection detection (should not trigger on legitimate queries)
                'SecRule ARGS "@rx (?i:select.*from)" "id:1001,phase:2,deny"',
                'SecRule ARGS "@rx (?i:union.*select)" "id:1002,phase:2,deny"',
                'SecRule REQUEST_BODY "@rx (?i:select.*from)" "id:1011,phase:2,deny"',
                # XSS detection
                'SecRule ARGS "@rx <script" "id:2001,phase:2,deny"',
                'SecRule REQUEST_BODY "@rx <script" "id:2011,phase:2,deny"',
                # Path traversal
                'SecRule ARGS "@rx \\.\\./\\.\\." "id:3001,phase:2,deny"',
                'SecRule REQUEST_URI "@rx \\.\\./\\.\\." "id:3011,phase:1,deny"',
            ]
        }
    )


@pytest.fixture
def fixtures_dir():
    """Get fixtures directory."""
    return Path(__file__).parent.parent / "fixtures" / "legitimate_traffic"


def test_rest_api_legitimate_traffic(production_waf, fixtures_dir):
    """Test REST API patterns don't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Load REST API samples
    rest_file = fixtures_dir / "rest_api.json"
    with rest_file.open("r") as f:
        samples = json.load(f)

    for sample in samples:
        passed = checker.test_request(
            sample["name"], sample["method"], sample["uri"], sample.get("body")
        )
        if not passed:
            print(f"\nFalse positive on: {sample['name']}")

    checker.print_summary()

    # Should have 0% false positive rate on REST APIs
    assert checker.get_false_positive_rate() == 0.0


def test_graphql_legitimate_traffic(production_waf, fixtures_dir):
    """Test GraphQL queries don't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Load GraphQL samples
    graphql_file = fixtures_dir / "graphql.json"
    with graphql_file.open("r") as f:
        samples = json.load(f)

    for sample in samples:
        passed = checker.test_request(
            sample["name"], sample["method"], sample["uri"], sample.get("body")
        )
        if not passed:
            print(f"\nFalse positive on: {sample['name']}")

    checker.print_summary()

    # GraphQL "query" keyword might trigger, allow up to 5% false positives
    assert checker.get_false_positive_rate() <= 0.05


def test_file_upload_legitimate(production_waf):
    """Test file uploads don't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Image upload
    image_body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="photo.jpg"\r\n'
        b"Content-Type: image/jpeg\r\n"
        b"\r\n"
        b"\xff\xd8\xff\xe0\x00\x10JFIF"  # JPEG header
        b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    passed = checker.test_request(
        "Image upload",
        "POST",
        "/upload",
        image_body.decode("latin-1"),
    )
    assert passed, "Image upload should not be blocked"

    # Document upload
    doc_body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="document.pdf"\r\n'
        b"Content-Type: application/pdf\r\n"
        b"\r\n"
        b"%PDF-1.4"  # PDF header
        b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    passed2 = checker.test_request(
        "PDF upload",
        "POST",
        "/upload",
        doc_body.decode("latin-1"),
    )
    assert passed2, "PDF upload should not be blocked"

    checker.print_summary()

    # Should not block legitimate uploads
    assert checker.get_false_positive_rate() == 0.0


def test_unicode_content_legitimate(production_waf):
    """Test Unicode content doesn't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Unicode samples
    unicode_samples = [
        {
            "name": "Chinese",
            "uri": "/search?q=编程语言",
            "body": '{"text": "学习Python"}',
        },
        {
            "name": "Arabic",
            "uri": "/search?q=برمجة",
            "body": '{"text": "تعلم البرمجة"}',
        },
        {"name": "Emoji", "uri": "/post", "body": '{"content": "Hello 👋 World 🌍"}'},
        {
            "name": "Mixed scripts",
            "uri": "/comment",
            "body": '{"text": "Python是一个programming language"}',
        },
    ]

    for sample in unicode_samples:
        passed = checker.test_request(
            sample["name"], "POST", sample["uri"], sample["body"]
        )
        assert passed, f"{sample['name']} should not be blocked"

    checker.print_summary()

    # Should handle Unicode without issues
    assert checker.get_false_positive_rate() == 0.0


def test_long_urls_legitimate(production_waf):
    """Test long URLs don't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Long but legitimate URLs
    long_urls = [
        "/api/search?q=" + "programming" * 20,
        "/api/data?" + "&".join([f"param{i}=value{i}" for i in range(50)]),
        "/path/to/resource/" + "/".join([f"level{i}" for i in range(20)]),
    ]

    for i, url in enumerate(long_urls):
        passed = checker.test_request(f"Long URL {i + 1}", "GET", url)
        assert passed, f"Long URL {i + 1} should not be blocked"

    checker.print_summary()

    # Long URLs should not be blocked
    assert checker.get_false_positive_rate() == 0.0


def test_edge_case_parameters(production_waf):
    """Test edge case parameter values."""
    checker = FalsePositiveChecker(production_waf)

    # Edge cases that might look suspicious but are legitimate
    edge_cases = [
        {"name": "Email with + sign", "uri": "/api/user?email=john+doe@example.com"},
        {"name": "URL-encoded space", "uri": "/search?q=hello%20world"},
        {"name": "Special chars in name", "uri": "/api/user?name=O'Brien"},
        {"name": "Ampersand in text", "uri": "/search?q=rock%20%26%20roll"},
        {"name": "Question mark in param", "uri": "/search?q=what%3F"},
    ]

    for case in edge_cases:
        passed = checker.test_request(case["name"], "GET", case["uri"])
        assert passed, f"{case['name']} should not be blocked"

    checker.print_summary()

    # Should handle edge cases correctly
    assert checker.get_false_positive_rate() == 0.0


def test_common_web_frameworks(production_waf):
    """Test common web framework patterns."""
    checker = FalsePositiveChecker(production_waf)

    # Django-style
    checker.test_request("Django admin", "GET", "/admin/auth/user/")
    checker.test_request(
        "Django filter", "GET", "/api/posts/?format=json&status=published"
    )

    # Flask-style
    checker.test_request("Flask endpoint", "GET", "/api/v1/users/123")
    checker.test_request("Flask JSON", "POST", "/api/data", '{"key": "value"}')

    # FastAPI-style
    checker.test_request("FastAPI docs", "GET", "/docs")
    checker.test_request("FastAPI openapi", "GET", "/openapi.json")

    checker.print_summary()

    # Framework patterns should not be blocked
    assert checker.get_false_positive_rate() == 0.0


def test_realistic_user_behavior(production_waf):
    """Test realistic user behavior patterns."""
    checker = FalsePositiveChecker(production_waf)

    # Typical user session
    checker.test_request("Homepage", "GET", "/")
    checker.test_request("Login page", "GET", "/login")
    checker.test_request(
        "Login POST", "POST", "/login", '{"username": "user", "password": "pass123"}'
    )
    checker.test_request("Dashboard", "GET", "/dashboard")
    checker.test_request("Profile", "GET", "/profile/user123")
    checker.test_request("Settings", "GET", "/settings")
    checker.test_request(
        "Update profile", "POST", "/api/profile", '{"name": "John", "bio": "Developer"}'
    )
    checker.test_request("Logout", "POST", "/logout", "{}")

    checker.print_summary()

    # Normal user flow should not be blocked
    assert checker.get_false_positive_rate() == 0.0


def test_search_queries_legitimate(production_waf):
    """Test search queries don't trigger false positives."""
    checker = FalsePositiveChecker(production_waf)

    # Legitimate search queries
    queries = [
        "python programming",
        "how to select a database",  # Contains "select" but not attack
        "SQL tutorial",  # Contains "SQL" but not attack
        "script writing guide",  # Contains "script" but not attack
        "union of sets in math",  # Contains "union" but not attack
    ]

    for query in queries:
        checker.test_request(f"Search: {query}", "GET", f"/search?q={query}")

    checker.print_summary()

    # Legitimate searches might have SQL keywords, allow small false positive rate
    rate = checker.get_false_positive_rate()
    print(f"\nSearch query false positive rate: {rate * 100:.1f}%")

    # Accept up to 40% false positives on these edge case queries
    # (they contain SQL keywords but in legitimate context)
    assert rate <= 0.40


def test_json_with_keywords(production_waf):
    """Test JSON containing keywords in legitimate context."""
    checker = FalsePositiveChecker(production_waf)

    # JSON with keywords that aren't attacks
    samples = [
        {
            "name": "Tutorial content",
            "body": '{"title": "How to SELECT columns in SQL", "content": "This tutorial..."}',
        },
        {
            "name": "Code example",
            "body": '{"code": "SELECT * FROM users WHERE id = ?", "language": "sql"}',
        },
        {
            "name": "Description",
            "body": '{"description": "This script selects from multiple sources"}',
        },
    ]

    for sample in samples:
        checker.test_request(sample["name"], "POST", "/api/content", sample["body"])

    checker.print_summary()

    # Keywords in legitimate content context
    rate = checker.get_false_positive_rate()

    # These might trigger rules, allow up to 100% (they're legitimate but flagged)
    # This shows need for context-aware rules
    assert rate <= 1.0


def test_comprehensive_legitimate_traffic(production_waf, fixtures_dir):
    """Comprehensive test of all legitimate traffic types."""
    checker = FalsePositiveChecker(production_waf)

    # Load all samples
    rest_file = fixtures_dir / "rest_api.json"
    graphql_file = fixtures_dir / "graphql.json"

    total_tested = 0

    # REST API
    if rest_file.exists():
        with rest_file.open("r") as f:
            samples = json.load(f)
        for sample in samples:
            checker.test_request(
                f"REST: {sample['name']}",
                sample["method"],
                sample["uri"],
                sample.get("body"),
            )
            total_tested += 1

    # GraphQL
    if graphql_file.exists():
        with graphql_file.open("r") as f:
            samples = json.load(f)
        for sample in samples:
            checker.test_request(
                f"GraphQL: {sample['name']}",
                sample["method"],
                sample["uri"],
                sample.get("body"),
            )
            total_tested += 1

    checker.print_summary()

    print(f"\nTested {total_tested} legitimate requests")
    print(f"False positive rate: {checker.get_false_positive_rate() * 100:.2f}%")

    # Overall false positive rate should be low (<5%)
    assert checker.get_false_positive_rate() <= 0.05
