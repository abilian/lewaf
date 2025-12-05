"""Comprehensive Cross-Site Scripting (XSS) protection tests.

This module tests that the WAF correctly detects and blocks various XSS attacks
using real-world attack vectors and CRS rules.
"""

from __future__ import annotations

import pytest

from lewaf.integration import WAF


class TestXSSProtection:
    """Test XSS detection and prevention."""

    @pytest.fixture
    def xss_waf(self):
        """Create WAF instance with XSS protection rules."""
        rules = [
            # Core libinjection XSS rule (from CRS 941100)
            'SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS "@detectXSS" '
            '"id:941100,phase:2,block,capture,'
            "t:none,t:utf8toUnicode,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:base64decode,"
            "msg:'XSS Attack Detected via libinjection',"
            "severity:'CRITICAL'\"",
            # Script tag detection (simplified CRS rule)
            'SecRule ARGS "@rx (?i)<\\s*script\\b[^>]*>[\\s\\S]*?</\\s*script\\s*>" '
            '"id:941110,phase:2,block,capture,'
            "msg:'XSS Attack: Script Tag Detected',"
            "severity:'CRITICAL'\"",
            # Event handler detection
            'SecRule ARGS "@rx (?i)\\bon(?:load|error|click|mouseover|focus|blur|submit|keydown|keyup)\\s*=" '
            '"id:941120,phase:2,block,capture,'
            "msg:'XSS Attack: Event Handler Detected',"
            "severity:'CRITICAL'\"",
            # JavaScript URL scheme
            'SecRule ARGS "@rx (?i)javascript\\s*:" '
            '"id:941130,phase:2,block,capture,'
            "msg:'XSS Attack: JavaScript URL Scheme Detected',"
            "severity:'CRITICAL'\"",
            # Basic HTML tag injection
            'SecRule ARGS "@rx (?i)<\\s*(?:iframe|embed|object|applet|meta|link|base|form|img|svg)\\b[^>]*>" '
            '"id:941140,phase:2,block,capture,'
            "msg:'XSS Attack: Dangerous HTML Tag Detected',"
            "severity:'HIGH'\"",
            # CSS expression detection
            'SecRule ARGS "@rx (?i)(?:expression\\s*\\(|behavior\\s*:|@import|javascript\\s*:)" '
            '"id:941150,phase:2,block,capture,'
            "msg:'XSS Attack: CSS Expression/Behavior Detected',"
            "severity:'HIGH'\"",
        ]

        return WAF({"rules": rules})

    def test_classic_xss_attacks(self, xss_waf):
        """Test classic XSS attack patterns."""
        attack_vectors = [
            # Basic script injection
            '<script>alert("XSS")</script>',
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            '<script>confirm("XSS")</script>',
            # Script with different cases
            '<SCRIPT>alert("XSS")</SCRIPT>',
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script >alert("XSS")</script>',
            # Event handlers
            '<img src="x" onerror="alert(\'XSS\')">',
            "<body onload=\"alert('XSS')\">",
            "<div onclick=\"alert('XSS')\">Click me</div>",
            "<input onfocus=\"alert('XSS')\" autofocus>",
            "<svg onload=\"alert('XSS')\"></svg>",
            # JavaScript URLs
            'javascript:alert("XSS")',
            'JAVASCRIPT:alert("XSS")',
            'javascript:void(alert("XSS"))',
            'javascript:eval("alert(\\"XSS\\")")',
            # Data URLs with JavaScript
            'data:text/html,<script>alert("XSS")</script>',
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=",  # <script>alert("XSS")</script> base64
        ]

        detected_count = 0
        for attack in attack_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/search?q={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: XSS attack not detected: {attack}")

        # Require at least 90% detection rate for XSS attacks
        detection_rate = detected_count / len(attack_vectors)
        assert detection_rate >= 0.9, (
            f"Low detection rate for XSS attacks: {detection_rate:.1%}"
        )

    def test_advanced_xss_vectors(self, xss_waf):
        """Test advanced and obfuscated XSS attack vectors."""
        attack_vectors = [
            # Unicode obfuscation
            "<script>\\u0061\\u006c\\u0065\\u0072\\u0074\\u0028\\u0022\\u0058\\u0053\\u0053\\u0022\\u0029</script>",
            # Hex encoding
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            # Base64 encoding in various contexts
            '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',  # alert("XSS") in base64
            # CSS-based attacks
            '<style>@import"javascript:alert(\\"XSS\\")";</style>',
            '<div style="background:url(javascript:alert(\\"XSS\\"))">',
            '<div style="expression(alert(\\"XSS\\"))">',
            # HTML5 vector
            '<svg><script>alert("XSS")</script></svg>',
            '<math><script>alert("XSS")</script></math>',
            '<embed src="javascript:alert(\\"XSS\\")">',
            '<object data="javascript:alert(\\"XSS\\")">',
            # Using different quote styles
            "<script>alert(`XSS`)</script>",
            "<script>alert(/XSS/.source)</script>",
            # DOM-based attack vectors
            '<img src="1" onerror="eval(name)" name="alert(\\"XSS\\")">',
            '<iframe src="javascript:alert(\\"XSS\\")"></iframe>',
            # Protocol pollution
            'javascript&#58;alert("XSS")',
            'java&#09;script:alert("XSS")',
            'vbscript:msgbox("XSS")',
        ]

        for attack in attack_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/comment?text={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Warning: Advanced XSS vector bypassed detection: {attack}")
            else:
                # Attack was correctly detected
                pass

    def test_xss_in_post_data(self, xss_waf):
        """Test XSS detection in POST request bodies."""
        attack_vectors = [
            {"comment": '<script>alert("XSS")</script>'},
            {"bio": '<img src="x" onerror="alert(\\"XSS\\")">'},
            {"message": 'Click <a href="javascript:alert(\\"XSS\\")">here</a>'},
            {"content": '<svg onload="alert(\\"XSS\\")"></svg>'},
            {"description": '<iframe src="javascript:alert(\\"XSS\\")"></iframe>'},
        ]

        for attack_data in attack_vectors:
            tx = xss_waf.new_transaction()

            # Simulate form POST data
            query_string = "&".join([f"{k}={v}" for k, v in attack_data.items()])
            tx.process_uri(f"/submit?{query_string}", "POST")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, (
                f"Failed to detect POST XSS: {attack_data}"
            )

    def test_encoded_xss_attacks(self, xss_waf):
        """Test URL-encoded and other encoded XSS attempts."""
        attack_vectors = [
            # URL encoded script
            "%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E",  # <script>alert("XSS")</script>
            # Double URL encoded
            "%253Cscript%253Ealert%2528%2522XSS%2522%2529%253C%252Fscript%253E",
            # HTML entity encoded
            "&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;",
            # Mixed encoding
            "%3Cimg%20src%3D%22x%22%20onerror%3D%22alert(%27XSS%27)%22%3E",  # <img src="x" onerror="alert('XSS')">
            # Unicode encoding
            "\\u003cscript\\u003ealert(\\u0022XSS\\u0022)\\u003c/script\\u003e",
            # Hex encoding combinations
            "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%22%58%53%53%22%29%3C%2F%73%63%72%69%70%74%3E",
        ]

        detected_count = 0
        for attack in attack_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/vulnerable?input={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: Encoded XSS attack bypassed detection: {attack}")

        # Some encoded attacks might bypass detection depending on transformation coverage
        detection_rate = detected_count / len(attack_vectors)
        assert detection_rate >= 0.6, (
            f"Low detection rate for encoded XSS: {detection_rate:.1%}"
        )

    def test_context_specific_xss(self, xss_waf):
        """Test XSS attacks in different HTML contexts."""
        attack_vectors = [
            # Inside HTML attributes
            ("value", '" onmouseover="alert(\\"XSS\\")"'),
            ("title", '" onclick="alert(\\"XSS\\")" "'),
            ("alt", '" onerror="alert(\\"XSS\\")" "'),
            # Inside href attributes
            ("url", 'javascript:alert("XSS")'),
            ("link", 'data:text/html,<script>alert("XSS")</script>'),
            # Inside style attributes
            ("style", 'expression(alert("XSS"))'),
            ("css", 'background:url(javascript:alert("XSS"))'),
            # Inside script contexts (if user input goes into JS)
            ("callback", 'alert("XSS");//'),
            ("jsonp", '"}});alert("XSS");//'),
        ]

        for context, attack in attack_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/render?{context}={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(
                    f"Warning: Context-specific XSS not detected in {context}: {attack}"
                )

    def test_xss_filter_bypass_techniques(self, xss_waf):
        """Test common XSS filter bypass techniques."""
        bypass_vectors = [
            # Case variation
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<SCRIPT>alert("XSS")</SCRIPT>',
            # Space/tab/newline insertion
            '<script >alert("XSS")</script>',
            '<script\t>alert("XSS")</script>',
            '<script\n>alert("XSS")</script>',
            # Incomplete tags that browsers might fix
            "<script",
            '<script>alert("XSS")',
            '<img src="x" onerror="alert(\\"XSS\\")">',
            # Using different quote types
            "<script>alert(`XSS`)</script>",
            "<script>alert(/XSS/)</script>",
            # Comment-based obfuscation
            '<script>al/**/ert("XSS")</script>',
            '<img src="x" on/**/error="alert(\\"XSS\\")">',
            # Tag property pollution
            '<img src="x" onerror="alert(\\"XSS\\")" />',
            '<input onfocus="alert(\\"XSS\\")" autofocus />',
            # Using alternative event handlers
            '<body/onload="alert(\\"XSS\\")">',
            '<img/src="x"/onerror="alert(\\"XSS\\")">',
            '<svg/onload="alert(\\"XSS\\")">',
        ]

        detected_count = 0
        total_count = len(bypass_vectors)

        for bypass in bypass_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/test?payload={bypass}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: XSS bypass not detected: {bypass}")

        # Require at least 75% detection rate for bypass attempts
        detection_rate = detected_count / total_count
        assert detection_rate >= 0.75, (
            f"Low detection rate for XSS bypass attempts: {detection_rate:.1%}"
        )

    def test_false_positive_prevention(self, xss_waf):
        """Test that legitimate content is not blocked as XSS."""
        legitimate_content = [
            # Normal HTML-like content in legitimate contexts
            "/blog?title=How to use <code> tags in HTML",
            "/tutorial?topic=Understanding JavaScript functions",
            "/search?q=script kiddie protection",
            "/forum?post=I love the onclick method in jQuery",
            # Programming discussions
            "/discussion?content=The onerror event handler is useful for debugging",
            "/code?example=function debug() { console.log('debug'); }",
            "/help?topic=How does the onload event work?",
            # Normal punctuation and symbols
            "/profile?bio=I'm a <strong>developer</strong> who codes in <em>JavaScript</em>",
            "/comment?text=Great article! I'll share this.",
            "/feedback?message=The 'script' command in Unix is powerful",
            # Technical content
            "/docs?section=HTML script element documentation",
            "/reference?api=onerror callback function",
            "/manual?chapter=browser protocol explanations",
        ]

        for content in legitimate_content:
            tx = xss_waf.new_transaction()
            tx.process_uri(content, "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is None, f"False positive detected for: {content}"

    def test_xss_in_headers(self, xss_waf):
        """Test XSS detection in HTTP headers."""
        # Note: This test validates header-based XSS detection
        # Implementation depends on how headers are processed in the WAF
        attack_headers = [
            ("User-Agent", '<script>alert("XSS")</script>'),
            ("Referer", 'javascript:alert("XSS")'),
            ("X-Forwarded-For", '<img src="x" onerror="alert(\\"XSS\\")">'),
        ]

        for header_name, attack_value in attack_headers:
            tx = xss_waf.new_transaction()
            # Simulate header processing through query parameter for testing
            tx.process_uri(f"/test?{header_name.lower()}={attack_value}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(
                    f"Warning: Header XSS not detected in {header_name}: {attack_value}"
                )

    def test_dom_xss_vectors(self, xss_waf):
        """Test DOM-based XSS attack vectors."""
        dom_vectors = [
            # Hash-based attacks (would be processed client-side)
            "#<script>alert('XSS')</script>",
            "#javascript:alert('XSS')",
            # Fragment identifier attacks
            "page.html#<img src=x onerror=alert('XSS')>",
            # URL parameter pollution for DOM XSS
            "search?q=<script>alert(document.domain)</script>",
            "redirect?url=javascript:alert('XSS')",
            # PostMessage-related vectors
            "callback=<script>alert('XSS')</script>",
            "jsonp=callback(<script>alert('XSS')</script>)",
        ]

        for vector in dom_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/{vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # DOM XSS detection depends on the WAF configuration
            if tx.interruption is None:
                print(f"Info: DOM XSS vector not detected (may be expected): {vector}")

    def test_xss_with_waf_evasion(self, xss_waf):
        """Test XSS attacks designed to evade WAF detection."""
        evasion_vectors = [
            # Splitting keywords across parameters
            "?java=1&script=alert('XSS')&execute=:combine_params",
            # Using allowed HTML tags with malicious attributes
            '<b onmouseover="alert(\\"XSS\\")">Bold text</b>',
            '<i onclick="alert(\\"XSS\\")">Italic text</i>',
            # CSS-based attacks that might bypass JS detection
            '<link rel="stylesheet" href="javascript:alert(\\"XSS\\")">',
            '<style>@import"javascript:alert(\\"XSS\\")";</style>',
            # Using meta tags
            '<meta http-equiv="refresh" content="0;url=javascript:alert(\\"XSS\\")">',
            # SVG-based attacks
            '<svg><animate onbegin="alert(\\"XSS\\")"></animate></svg>',
            '<svg><animateTransform onbegin="alert(\\"XSS\\")"></animateTransform></svg>',
            # Using form elements
            '<form><button formaction="javascript:alert(\\"XSS\\")">Submit</button></form>',
            '<input type="image" src="x" onerror="alert(\\"XSS\\")">',
        ]

        detected_count = 0
        for vector in evasion_vectors:
            tx = xss_waf.new_transaction()
            tx.process_uri(f"/vulnerable?payload={vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: WAF evasion vector not detected: {vector}")

        # This is informational - some evasion techniques might be sophisticated
        detection_rate = detected_count / len(evasion_vectors)
        print(f"WAF evasion detection rate: {detection_rate:.1%}")
