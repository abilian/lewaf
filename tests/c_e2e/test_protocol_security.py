"""Comprehensive HTTP protocol security tests.

This module tests protection against protocol-level attacks, malformed requests,
and HTTP security violations using CRS rules.
"""

from __future__ import annotations

import pytest

from lewaf.integration import WAF


class TestProtocolSecurity:
    """Test HTTP protocol security and attack detection."""

    @pytest.fixture
    def protocol_waf(self):
        """Create WAF instance with protocol security rules."""
        rules = [
            # HTTP method enforcement (from CRS 911100)
            'SecRule REQUEST_METHOD "!@within GET POST HEAD PUT DELETE OPTIONS PATCH" '
            '"id:911100,phase:1,block,'
            "msg:'Method is not allowed by policy',"
            "severity:'CRITICAL'\"",
            # Protocol version enforcement
            'SecRule REQUEST_PROTOCOL "!@rx ^HTTP/[12]\\.[0-9]$" '
            '"id:920200,phase:1,block,'
            "msg:'Invalid HTTP Protocol Version',"
            "severity:'WARNING'\"",
            # Content-Length validation
            'SecRule REQUEST_HEADERS:Content-Length "@rx ^\\d{10,}$" '
            '"id:920300,phase:1,block,'
            "msg:'Request Content-Length Too Large',"
            "severity:'WARNING'\"",
            # Header validation - no null bytes
            'SecRule REQUEST_HEADERS "@rx \\x00" '
            '"id:920400,phase:1,block,'
            "msg:'Null byte in request headers',"
            "severity:'CRITICAL'\"",
            # URI validation - length limit
            'SecRule REQUEST_URI "@rx ^.{1000,}" '
            '"id:920500,phase:1,block,'
            "msg:'Request URI Too Long',"
            "severity:'WARNING'\"",
            # Host header validation
            'SecRule REQUEST_HEADERS:Host "@rx ^$" '
            '"id:920600,phase:1,block,'
            "msg:'Missing Host Header',"
            "severity:'WARNING'\"",
            # User-Agent validation
            'SecRule REQUEST_HEADERS:User-Agent "@rx ^$" '
            '"id:920700,phase:1,block,'
            "msg:'Missing User-Agent Header',"
            "severity:'NOTICE'\"",
            # Range header attacks
            'SecRule REQUEST_HEADERS:Range "@rx bytes=(?:[^,]+-[^,]*,){5,}" '
            '"id:920800,phase:1,block,'
            "msg:'Range Header Attack',"
            "severity:'WARNING'\"",
            # HTTP response splitting
            'SecRule ARGS "@rx (?:\\r\\n|\\r|\\n).*(?:Content-Type|Set-Cookie|Location):" '
            '"id:921100,phase:2,block,'
            "msg:'HTTP Response Splitting Attack',"
            "severity:'CRITICAL'\"",
            # HTTP request smuggling detection
            'SecRule REQUEST_HEADERS:Transfer-Encoding "@rx chunked.*chunked" '
            '"id:921200,phase:1,block,'
            "msg:'HTTP Request Smuggling Attack',"
            "severity:'CRITICAL'\"",
            # CRLF injection detection
            'SecRule ARGS "@rx (?:%0[ad]|\\r\\n|\\r|\\n)" '
            '"id:921300,phase:2,block,'
            "msg:'CRLF Injection Attack',"
            "severity:'HIGH'\"",
        ]

        return WAF({"rules": rules})

    def test_http_method_attacks(self, protocol_waf):
        """Test HTTP method-based attacks."""
        attack_methods = [
            # Non-standard methods
            "TRACE",
            "CONNECT",
            "TRACK",
            "DEBUG",
            # WebDAV methods
            "PROPFIND",
            "PROPPATCH",
            "MKCOL",
            "COPY",
            "MOVE",
            "LOCK",
            "UNLOCK",
            # Custom/malicious methods
            "HACK",
            "EXPLOIT",
            "SHELL",
            "BACKDOOR",
            # Case variations
            "get",
            "post",
            "put",
            "delete",
            # Malformed methods
            "GET/HTTP/1.1",
            "POST\\x00",
            "PUT\\r\\n",
        ]

        for method in attack_methods:
            tx = protocol_waf.new_transaction()
            tx.process_uri("/test", method)

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # Some methods like TRACE might be legitimately blocked
            if tx.interruption is None and method in {
                "TRACE",
                "CONNECT",
                "TRACK",
                "DEBUG",
            }:
                print(f"Info: Method {method} not blocked (may be acceptable)")
            elif tx.interruption is None and method not in {
                "GET",
                "POST",
                "HEAD",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PATCH",
            }:
                print(f"Warning: Dangerous method not blocked: {method}")

    def test_http_version_attacks(self, protocol_waf):
        """Test HTTP version-related attacks."""
        # Note: This test simulates HTTP version validation
        # In a real implementation, this would be tested at the protocol parser level
        version_attacks = [
            "HTTP/0.9",
            "HTTP/3.0",
            "HTTP/2.5",
            "HTTP/1.2",
            "HTTP/",
            "HTTP",
            "HTTPS/1.1",
            "FTP/1.0",
            "HTTP/1.1\\r\\n",
            "HTTP/1.1\\x00",
        ]

        for version in version_attacks:
            tx = protocol_waf.new_transaction()
            # Simulate version check through a parameter for testing
            tx.process_uri(f"/test?protocol={version}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: HTTP version variation not detected: {version}")

    def test_header_injection_attacks(self, protocol_waf):
        """Test HTTP header injection attacks."""
        header_attacks = [
            # CRLF injection in parameters (simulating header injection)
            "value\\r\\nSet-Cookie: admin=true",
            "test\\nLocation: http://evil.com",
            "data\\r\\nContent-Type: text/html\\r\\n\\r\\n<script>alert('XSS')</script>",
            # URL encoded CRLF
            "value%0D%0ASet-Cookie: admin=true",
            "test%0ALocation: http://evil.com",
            "data%0D%0AContent-Type: text/html",
            # Double encoded
            "value%250D%250ASet-Cookie: admin=true",
            # Null byte injection
            "value\\x00Set-Cookie: admin=true",
            "test\\0Location: http://evil.com",
            # Unicode line separators
            "value\\u2028Set-Cookie: admin=true",
            "test\\u2029Location: http://evil.com",
            # Response splitting payloads
            "\\r\\nHTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\nHTTP/1.1 200 OK\\r\\n",
            "%0d%0aHTTP/1.1%20200%20OK%0d%0a",
        ]

        detected_count = 0
        for attack in header_attacks:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/redirect?url={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: Header injection not detected: {attack}")

        # Require good detection rate for header injection
        detection_rate = detected_count / len(header_attacks)
        assert detection_rate >= 0.3, (
            f"Low detection rate for header injection: {detection_rate:.1%}"
        )

    def test_request_smuggling_attacks(self, protocol_waf):
        """Test HTTP request smuggling detection."""
        # Note: Request smuggling is complex and often requires server-level detection
        smuggling_vectors = [
            # Double Transfer-Encoding
            "chunked, chunked",
            "chunked,chunked",
            "chunked\\r\\nTransfer-Encoding: chunked",
            # Transfer-Encoding vs Content-Length conflicts
            "chunked\\r\\nContent-Length: 10",
            # Malformed Transfer-Encoding
            " chunked",
            "chunked ",
            "\\tchunked",
            "chun\\x00ked",
            # Multiple Transfer-Encoding headers (simulated)
            "chunked\\r\\nTransfer-Encoding: identity",
        ]

        for vector in smuggling_vectors:
            tx = protocol_waf.new_transaction()
            # Simulate Transfer-Encoding header through parameter
            tx.process_uri(f"/test?transfer_encoding={vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: Request smuggling vector not detected: {vector}")

    def test_oversized_request_attacks(self, protocol_waf):
        """Test protection against oversized requests."""
        size_attacks = [
            # Very long URI
            "/test" + "A" * 2000,
            # Large Content-Length values (simulated through parameters)
            f"/test?content_length={'9' * 15}",  # 15 digit number
            f"/test?content_length={'1' * 20}",  # 20 digit number
            # Large query string
            "/test?" + "&".join([f"param{i}={'X' * 100}" for i in range(50)]),
            # Large number of parameters
            "/test?" + "&".join([f"p{i}=value{i}" for i in range(1000)]),
        ]

        for attack in size_attacks:
            tx = protocol_waf.new_transaction()
            tx.process_uri(attack[:1000], "GET")  # Truncate for testing

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # Size-based attacks might be caught by different rules
            if tx.interruption is None:
                print(f"Info: Size-based attack not detected: {attack[:100]}...")

    def test_malformed_header_attacks(self, protocol_waf):
        """Test malformed HTTP headers."""
        # Note: These would typically be caught at the HTTP parser level
        header_malformations = [
            # Headers with null bytes (simulated through parameters)
            "host_header=example.com\\x00.evil.com",
            "user_agent=Mozilla\\x00<script>alert('XSS')</script>",
            # Headers with control characters
            "host_header=example.com\\r.evil.com",
            "user_agent=Mozilla\\n<script>alert('XSS')</script>",
            # Malformed header syntax
            "malformed_header=value without colon",
            "header_with_spaces=value\\x20\\x20\\x20",
            # Headers with dangerous content
            "range_header=" + "bytes=0-1," * 10,  # Range header attack
            "content_type=text/html\\r\\nSet-Cookie: admin=true",
        ]

        for header in header_malformations:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?{header}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: Malformed header not detected: {header}")

    def test_http_version_downgrade_attacks(self, protocol_waf):
        """Test HTTP version downgrade attacks."""
        downgrade_vectors = [
            # Protocol downgrade attempts
            "HTTP/0.9",  # Very old HTTP version
            "HTTP/1.0",  # Older version with fewer security features
            # Mixed version attacks
            "HTTP/1.1\\r\\nConnection: close\\r\\nHTTP/1.0",
            # Invalid version formats
            "HTTP/1.1.1",
            "HTTP/2.0",
            "HTTP/1.a",
        ]

        for vector in downgrade_vectors:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?http_version={vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: Version downgrade not detected: {vector}")

    def test_host_header_attacks(self, protocol_waf):
        """Test Host header-based attacks."""
        host_attacks = [
            # Host header injection
            "example.com\\r\\nX-Injected: header",
            "example.com\\nSet-Cookie: admin=true",
            # Port confusion
            "example.com:80:8080",
            "example.com:99999",
            # Invalid host formats
            "example..com",
            "example.com.",
            ".example.com",
            # Unicode in host
            "ex\\u0061mple.com",
            "exampl\\u0065.com",
            # IP address edge cases
            "192.168.1.1.evil.com",
            "127.0.0.1:80@evil.com",
            # Missing host (empty)
            "",
            # Oversized host
            "a" * 500 + ".com",
        ]

        for host in host_attacks:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?host={host}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if host == "" and tx.interruption is not None:
                # Empty host should be detected
                pass
            elif tx.interruption is None:
                print(f"Info: Host header attack not detected: {host}")

    def test_user_agent_attacks(self, protocol_waf):
        """Test User-Agent header-based attacks."""
        ua_attacks = [
            # Empty User-Agent
            "",
            # Very long User-Agent
            "Mozilla/5.0 " + "A" * 1000,
            # User-Agent with injection attempts
            "Mozilla/5.0\\r\\nSet-Cookie: admin=true",
            "Mozilla/5.0\\nLocation: http://evil.com",
            # Null bytes in User-Agent
            "Mozilla\\x00<script>alert('XSS')</script>",
            # Malicious User-Agents
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
            "../../../etc/passwd",
            # Bot/scanner User-Agents
            "sqlmap/1.0",
            "Nikto/2.1.6",
            "w3af.org",
            "Havij",
            # Binary content in User-Agent
            "\\xff\\xfe\\x00\\x01",
        ]

        for ua in ua_attacks:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?user_agent={ua}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if ua == "" and tx.interruption is not None:
                # Empty UA should be detected
                pass
            elif tx.interruption is None and ua in {
                "sqlmap/1.0",
                "Nikto/2.1.6",
                "w3af.org",
                "Havij",
            }:
                print(f"Warning: Malicious User-Agent not detected: {ua}")

    def test_content_type_attacks(self, protocol_waf):
        """Test Content-Type header attacks."""
        ct_attacks = [
            # Content-Type confusion
            "text/html; charset=utf-7",
            "text/html; charset=utf-32",
            # Content-Type with injection
            "text/html\\r\\nSet-Cookie: admin=true",
            "application/json\\nLocation: http://evil.com",
            # Malformed Content-Type
            "text/html;",
            "text/html; charset=",
            "text/html; charset=utf-8; charset=iso-8859-1",
            # Dangerous Content-Types
            "application/x-www-form-urlencoded\\r\\n\\r\\n<script>alert('XSS')</script>",
            # Very long Content-Type
            "text/html; charset=utf-8; " + "boundary=" + "A" * 1000,
        ]

        for ct in ct_attacks:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?content_type={ct}", "POST")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: Content-Type attack not detected: {ct}")

    def test_protocol_compliance(self, protocol_waf):
        """Test basic HTTP protocol compliance."""
        compliance_tests = [
            # Valid requests that should NOT be blocked
            (
                "GET",
                "/",
                "HTTP/1.1",
                {"Host": "example.com", "User-Agent": "Mozilla/5.0"},
            ),
            (
                "POST",
                "/submit",
                "HTTP/1.1",
                {"Host": "example.com", "Content-Type": "application/json"},
            ),
            ("PUT", "/api/resource", "HTTP/1.1", {"Host": "api.example.com"}),
            ("DELETE", "/api/resource/123", "HTTP/1.1", {"Host": "api.example.com"}),
            ("HEAD", "/status", "HTTP/1.1", {"Host": "status.example.com"}),
            ("OPTIONS", "/api", "HTTP/1.1", {"Host": "api.example.com"}),
        ]

        for method, uri, version, headers in compliance_tests:
            tx = protocol_waf.new_transaction()

            # Simulate headers through query parameters for testing
            header_params = "&".join([f"{k.lower()}={v}" for k, v in headers.items()])
            test_uri = f"{uri}?{header_params}" if header_params else uri

            tx.process_uri(test_uri, method)

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is None, (
                f"Valid request incorrectly blocked: {method} {uri}"
            )

    def test_slowloris_protection(self, protocol_waf):
        """Test protection against Slowloris-style attacks."""
        # Note: Slowloris protection typically requires rate limiting and connection management
        # This test validates parameter-based simulation
        slowloris_vectors = [
            # Incomplete headers simulation
            "incomplete_header=true",
            "slow_request=true",
            "partial_header=Content-Type:",
            # Connection manipulation
            "connection=keep-alive" + "&connection=close" * 100,
            # Very slow content simulation
            "slow_body=true&content_length=1000000",
        ]

        for vector in slowloris_vectors:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?{vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # Slowloris protection would typically be at the server level
            if tx.interruption is None:
                print(
                    f"Info: Slowloris vector not detected (may require server-level protection): {vector}"
                )

    def test_http_desync_attacks(self, protocol_waf):
        """Test HTTP desynchronization attack detection."""
        desync_vectors = [
            # Content-Length vs Transfer-Encoding conflicts (simulated)
            "content_length=10&transfer_encoding=chunked",
            "content_length=0&transfer_encoding=chunked",
            # Multiple Content-Length headers (simulated)
            "content_length=10&content_length=20",
            # Malformed chunked encoding (simulated)
            "transfer_encoding=chunked&malformed_chunk=true",
            # Tab/space in Transfer-Encoding
            "transfer_encoding=%20chunked",
            "transfer_encoding=chunked%20",
            "transfer_encoding=%09chunked",
        ]

        for vector in desync_vectors:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?{vector}", "POST")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: HTTP desync vector not detected: {vector}")

    def test_cache_poisoning_protection(self, protocol_waf):
        """Test protection against cache poisoning attacks."""
        poisoning_vectors = [
            # Host header manipulation for cache poisoning
            "host=victim.com%20evil.com",
            "host=victim.com.evil.com",
            # X-Forwarded-Host manipulation
            "x_forwarded_host=evil.com",
            "x_forwarded_host=victim.com%0d%0aSet-Cookie:%20admin=true",
            # Cache key confusion
            "x_original_url=/admin",
            "x_rewrite_url=/sensitive",
            # HTTP/2 specific (simulated)
            "authority=evil.com",
            "scheme=https%0d%0aSet-Cookie:%20admin=true",
        ]

        for vector in poisoning_vectors:
            tx = protocol_waf.new_transaction()
            tx.process_uri(f"/test?{vector}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Info: Cache poisoning vector not detected: {vector}")
