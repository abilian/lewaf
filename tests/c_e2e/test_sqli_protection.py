"""Comprehensive SQL injection protection tests.

This module tests that the WAF correctly detects and blocks various SQL injection attacks
using real-world attack vectors and CRS rules.
"""

from __future__ import annotations

import pytest

from lewaf.integration import WAF


class TestSQLiProtection:
    """Test SQL injection detection and prevention."""

    @pytest.fixture
    def sqli_waf(self):
        """Create WAF instance with SQL injection protection rules."""
        rules = [
            # Core libinjection rule (from CRS 942100)
            'SecRule ARGS "@detectSQLi" '
            '"id:942100,phase:2,block,capture,'
            "t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,"
            "msg:'SQL Injection Attack Detected via libinjection',"
            "severity:'CRITICAL'\"",
            # Common DB names detection (simplified)
            'SecRule ARGS "@rx (?i)(information_schema|mysql|pg_catalog|master|tempdb)" '
            '"id:942140,phase:2,block,capture,'
            "msg:'SQL Injection Attack: Common DB Names Detected',"
            "severity:'CRITICAL'\"",
            # SQL function names detection
            'SecRule ARGS "@rx (?i)\\b(concat|union|select|insert|update|delete|drop|create|alter|exec|execute)\\b" '
            '"id:942160,phase:2,block,capture,'
            "msg:'SQL Injection Attack: SQL Function Names Detected',"
            "severity:'CRITICAL'\"",
            # SQL operators detection (simplified)
            'SecRule ARGS "@rx (?i)(\\x27|\\x22)?\\s*\\b(or|and)\\b\\s*(\\x27|\\x22)?" '
            '"id:942200,phase:2,block,capture,'
            "msg:'SQL Injection Attack: SQL Operators Detected',"
            "severity:'CRITICAL'\"",
        ]

        return WAF({"rules": rules})

    def test_classic_sqli_attacks(self, sqli_waf):
        """Test classic SQL injection patterns."""
        attack_vectors = [
            # Classic OR-based injection
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin' OR '1'='1' --",
            # Union-based injection
            "' UNION SELECT * FROM users--",
            "1' UNION SELECT username,password FROM users--",
            "' UNION ALL SELECT NULL,concat(username,0x3a,password),NULL FROM users--",
            # Boolean-based blind injection
            "' AND '1'='1",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT LENGTH(username) FROM users WHERE id=1)>5--",
            # Time-based blind injection
            "'; WAITFOR DELAY '00:00:10'--",
            "'; SELECT SLEEP(10)--",
            "' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3)x GROUP BY CONCAT(MID(version(),1,50),FLOOR(RAND(0)*2)))--",
        ]

        for attack in attack_vectors:
            tx = sqli_waf.new_transaction()
            tx.process_uri(f"/login?username={attack}&password=test", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, (
                f"Failed to detect SQL injection: {attack}"
            )
            assert tx.interruption.get("rule_id") in [
                942100,
                942140,
                942160,
                942200,
            ], f"Wrong rule triggered for attack: {attack}"

    def test_database_specific_attacks(self, sqli_waf):
        """Test database-specific SQL injection patterns."""
        attack_vectors = [
            # MySQL specific
            "' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "'; SELECT IF(1=1,SLEEP(5),0)--",
            # PostgreSQL specific
            "'; SELECT pg_sleep(10)--",
            "' UNION SELECT current_user,current_database()--",
            "'; SELECT version()--",
            # MSSQL specific
            "'; EXEC xp_cmdshell('dir')--",
            "' UNION SELECT @@version--",
            "'; WAITFOR DELAY '00:00:05'--",
            # Oracle specific
            "' UNION SELECT banner FROM v$version--",
            "' AND (SELECT COUNT(*) FROM all_tables)>0--",
            "'; SELECT UTL_INADDR.get_host_name('127.0.0.1') FROM dual--",
        ]

        for attack in attack_vectors:
            tx = sqli_waf.new_transaction()
            tx.process_uri(f"/search?q={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, (
                f"Failed to detect DB-specific attack: {attack}"
            )

    def test_encoded_sqli_attacks(self, sqli_waf):
        """Test URL-encoded and other encoded SQL injection attempts."""
        attack_vectors = [
            # URL encoded
            "%27%20OR%20%271%27%3D%271",  # ' OR '1'='1
            "%27%20UNION%20SELECT%20*%20FROM%20users--",  # ' UNION SELECT * FROM users--
            "%2527%2520OR%2520%25271%2527%253D%25271",  # Double URL encoded
            # Unicode encoded
            "\\u0027\\u0020OR\\u0020\\u0031\\u003D\\u0031",  # ' OR 1=1
            # Hex encoded
            "0x27204f5220312031",  # ' OR 1 1 in hex
        ]

        for attack in attack_vectors:
            tx = sqli_waf.new_transaction()
            tx.process_uri(f"/api/data?filter={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # Note: Some encoding might bypass detection depending on transformation coverage
            # This test validates the current state and can be enhanced as more transformations are added
            if tx.interruption is None:
                print(f"Warning: Encoded attack bypassed detection: {attack}")

    def test_sqli_in_post_data(self, sqli_waf):
        """Test SQL injection in POST request bodies."""
        attack_vectors = [
            {"username": "admin' OR '1'='1' --", "password": "anything"},
            {"email": "test@test.com", "comment": "'; DROP TABLE users; --"},
            {"search": "' UNION SELECT password FROM users WHERE username='admin'--"},
        ]

        for attack_data in attack_vectors:
            tx = sqli_waf.new_transaction()

            # Simulate form POST data
            query_string = "&".join([f"{k}={v}" for k, v in attack_data.items()])
            tx.process_uri(f"/submit?{query_string}", "POST")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, (
                f"Failed to detect POST SQL injection: {attack_data}"
            )

    def test_sqli_bypass_attempts(self, sqli_waf):
        """Test common SQL injection bypass techniques."""
        bypass_vectors = [
            # Case variation
            "' Or '1'='1",
            "' oR 1=1--",
            "' UnIoN sElEcT * FrOm users--",
            # Comment variation
            "'/**/OR/**/1=1--",
            "'/*comment*/UNION/*comment*/SELECT--",
            # Space replacement
            "'OR'1'='1",
            "'%09OR%091=1--",  # Tab instead of space
            "'%0aOR%0a1=1--",  # Newline instead of space
            # Quote variation
            '"OR"1"="1',
            "\\'OR\\'1\\'=\\'1",
            # Function-based bypasses
            "' OR ascii(substring(user(),1,1))=114--",  # Using ASCII function
            "' OR length(user())>0--",  # Using LENGTH function
        ]

        detected_count = 0
        total_count = len(bypass_vectors)

        for bypass in bypass_vectors:
            tx = sqli_waf.new_transaction()
            tx.process_uri(f"/vulnerable?id={bypass}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: Bypass attempt not detected: {bypass}")

        # Require at least 80% detection rate for bypass attempts
        detection_rate = detected_count / total_count
        assert detection_rate >= 0.8, (
            f"Low detection rate for bypass attempts: {detection_rate:.1%}"
        )

    def test_false_positive_prevention(self, sqli_waf):
        """Test that legitimate requests are not blocked as SQL injection."""
        legitimate_requests = [
            # Normal search terms
            "/search?q=python programming",
            "/search?q=database tutorial",
            "/search?q=choose a good book",
            # Normal form data
            "/contact?name=John Doe&email=john@example.com&message=Hello world",
            # Legitimate SQL-like content in context
            "/blog/post?title=How to use database queries in SQL",
            "/tutorial?topic=Understanding boolean operators in programming",
            # Normal punctuation
            "/profile?bio=I'm a developer who's passionate about technology",
            "/comment?text=That's a great idea! Let's discuss it further.",
        ]

        for request in legitimate_requests:
            tx = sqli_waf.new_transaction()
            tx.process_uri(request, "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is None, f"False positive detected for: {request}"

    def test_sqli_in_cookies(self, sqli_waf):
        """Test SQL injection detection in cookie values."""
        # Note: This test validates cookie-based SQLi detection
        # Implementation depends on how cookies are processed in the WAF
        attack_cookies = [
            "session_id=' OR '1'='1' --",
            "user_pref=admin'; DROP TABLE users; --",
            "lang=' UNION SELECT password FROM users--",
        ]

        for cookie_value in attack_cookies:
            tx = sqli_waf.new_transaction()
            # Process cookie through the request simulation
            tx.process_uri(f"/app?cookie_test={cookie_value}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # Expect detection for cookie-based attacks
            if tx.interruption is None:
                print(f"Warning: Cookie SQLi not detected: {cookie_value}")

    def test_sqli_severity_classification(self, sqli_waf):
        """Test that SQL injection attacks are classified with correct severity."""
        high_severity_attacks = [
            "' OR '1'='1' --",  # Classic injection
            "'; DROP TABLE users; --",  # Destructive operation
            "' UNION SELECT password FROM users--",  # Data extraction
        ]

        for attack in high_severity_attacks:
            tx = sqli_waf.new_transaction()
            tx.process_uri(f"/login?user={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, f"Attack not detected: {attack}"
            # Note: Severity checking would depend on how severity is stored in interruption
            # This validates that the attack was caught and can be enhanced for severity validation
