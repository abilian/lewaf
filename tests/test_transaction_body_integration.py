"""Tests for Transaction body processor integration."""

from lewaf.integration import WAF


def test_urlencoded_body_integration():
    """Test URLEncoded body processing in transaction."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set URLEncoded body
    body = b"username=admin&password=secret123&action=login"
    tx.add_request_body(body, "application/x-www-form-urlencoded")

    # Process body
    tx.process_request_body()

    # Verify ARGS_POST populated
    assert tx.variables.args_post.get("username") == ["admin"]
    assert tx.variables.args_post.get("password") == ["secret123"]
    assert tx.variables.args_post.get("action") == ["login"]

    # Verify processor name set
    assert tx.variables.reqbody_processor.get() == "URLENCODED"

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_json_body_integration():
    """Test JSON body processing in transaction."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set JSON body
    body = b'{"user": {"name": "admin", "id": 123}, "action": "login"}'
    tx.add_request_body(body, "application/json")

    # Process body
    tx.process_request_body()

    # Verify ARGS_POST populated (flattened)
    assert tx.variables.args_post.get("user.name") == ["admin"]
    assert tx.variables.args_post.get("user.id") == ["123"]
    assert tx.variables.args_post.get("action") == ["login"]

    # Verify ARGS_POST_NAMES populated
    assert "user.name" in tx.variables.args_post_names._data
    assert "action" in tx.variables.args_post_names._data

    # Verify processor name set
    assert tx.variables.reqbody_processor.get() == "JSON"

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_xml_body_integration():
    """Test XML body processing in transaction."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set XML body
    body = b"<user><name>admin</name><id>123</id></user>"
    tx.add_request_body(body, "text/xml")

    # Process body
    tx.process_request_body()

    # Verify processor name set
    assert tx.variables.reqbody_processor.get() == "XML"

    # Verify XML collection has root element
    assert "_root" in tx.variables.xml._data

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_multipart_file_upload():
    """Test multipart file upload processing."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set multipart body
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"file content here\r\n"
        b"------WebKitFormBoundary--\r\n"
    )
    tx.add_request_body(body, f"multipart/form-data; boundary={boundary}")

    # Process body
    tx.process_request_body()

    # Verify ARGS_POST populated (form fields)
    assert tx.variables.args_post.get("username") == ["admin"]

    # Verify FILES collections populated
    files = tx.variables.files.get_files("file")
    assert len(files) == 1
    assert files[0].filename == "test.txt"
    assert files[0].content == b"file content here"
    assert files[0].content_type == "text/plain"

    # Verify FILES_NAMES
    assert tx.variables.files_names.get("file") == ["file"]

    # Verify FILES_SIZES and FILES_COMBINED_SIZE
    assert tx.variables.files_sizes.get("file") == ["17"]  # len("file content here")
    assert tx.variables.files_combined_size.get() == "17"

    # Verify processor name set
    assert tx.variables.reqbody_processor.get() == "MULTIPART"

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_malformed_json_error_handling():
    """Test error handling for malformed JSON."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set malformed JSON body
    body = b'{"invalid": json}'
    tx.add_request_body(body, "application/json")

    # Process body - should set error variables
    tx.process_request_body()

    # Verify error variables set
    assert tx.variables.reqbody_error.get() == "1"
    assert "Invalid JSON" in tx.variables.reqbody_error_msg.get()
    assert tx.variables.reqbody_processor_error.get() == "1"


def test_invalid_xml_error_handling():
    """Test error handling for invalid XML."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set malformed XML body
    body = b"<root><unclosed>"
    tx.add_request_body(body, "text/xml")

    # Process body - should set error variables
    tx.process_request_body()

    # Verify error variables set
    assert tx.variables.reqbody_error.get() == "1"
    assert "Invalid XML" in tx.variables.reqbody_error_msg.get()


def test_oversized_xml_error_handling():
    """Test error handling for oversized XML."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set oversized XML body (>1MB)
    large_xml = b"<root>" + b"<item>data</item>" * 100000 + b"</root>"
    tx.add_request_body(large_xml, "application/xml")

    # Process body - should set error variables
    tx.process_request_body()

    # Verify error variables set
    assert tx.variables.reqbody_error.get() == "1"
    assert "too large" in tx.variables.reqbody_error_msg.get()


def test_no_body_no_error():
    """Test that missing body doesn't cause errors."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Don't set body, but set Content-Type
    tx.variables.request_headers.add("content-type", "application/json")

    # Process body - should not crash
    tx.process_request_body()

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""
    assert tx.variables.reqbody_processor.get() == ""


def test_unknown_content_type():
    """Test that unknown Content-Type is handled gracefully."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Set body with unknown content type
    body = b"some binary data"
    tx.add_request_body(body, "application/octet-stream")

    # Process body - should not crash
    tx.process_request_body()

    # Verify processor not selected
    assert tx.variables.reqbody_processor.get() == ""

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_crs_sql_injection_urlencoded():
    """Test CRS-style SQL injection rule with URLEncoded body."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS_POST "@rx (?i:union.*select)" "id:1001,phase:2,deny,msg:\'SQL Injection\'"'
            ]
        }
    )
    tx = waf.new_transaction()

    # Malicious URLEncoded payload
    body = b"username=admin&query=SELECT+*+FROM+users+WHERE+1%3D1+UNION+SELECT+password"
    tx.add_request_body(body, "application/x-www-form-urlencoded")

    # Process body - should trigger rule
    result = tx.process_request_body()

    assert result is not None
    assert result["rule_id"] == 1001


def test_crs_sql_injection_json():
    """Test CRS-style SQL injection rule with JSON body."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS_POST "@rx (?i:union.*select)" "id:1002,phase:2,deny,msg:\'SQL Injection\'"'
            ]
        }
    )
    tx = waf.new_transaction()

    # Malicious JSON payload
    body = (
        b'{"username": "admin", "query": "SELECT * FROM users UNION SELECT password"}'
    )
    tx.add_request_body(body, "application/json")

    # Process body - should trigger rule
    result = tx.process_request_body()

    assert result is not None
    assert result["rule_id"] == 1002


def test_crs_xss_detection_json():
    """Test CRS-style XSS detection in JSON body."""
    waf = WAF(
        {
            "rules": [
                'SecRule ARGS_POST "@rx <script" "id:1003,phase:2,deny,msg:\'XSS Attack\'"'
            ]
        }
    )
    tx = waf.new_transaction()

    # XSS payload in JSON
    body = b'{"comment": "<script>alert(1)</script>", "user": "attacker"}'
    tx.add_request_body(body, "application/json")

    # Process body - should trigger rule
    result = tx.process_request_body()

    assert result is not None
    assert result["rule_id"] == 1003


def test_crs_file_extension_restriction():
    """Test CRS-style file extension restriction."""
    waf = WAF(
        {
            "rules": [
                'SecRule FILES "@rx (?i:\\.(?:exe|dll|bat|cmd|sh))$" "id:1004,phase:2,deny,msg:\'Dangerous file extension\'"'
            ]
        }
    )
    tx = waf.new_transaction()

    # Upload file with dangerous extension
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="malware.exe"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n"
        b"MZ binary content\r\n"
        b"------WebKitFormBoundary--\r\n"
    )
    tx.add_request_body(body, f"multipart/form-data; boundary={boundary}")

    # Process body - should trigger rule
    result = tx.process_request_body()

    assert result is not None
    assert result["rule_id"] == 1004


def test_multiple_files_upload():
    """Test multiple file uploads."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Multiple files in multipart body
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file1"; filename="doc1.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"content1\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file2"; filename="doc2.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"content2\r\n"
        b"------WebKitFormBoundary--\r\n"
    )
    tx.add_request_body(body, f"multipart/form-data; boundary={boundary}")

    # Process body
    tx.process_request_body()

    # Verify both files uploaded
    files1 = tx.variables.files.get_files("file1")
    files2 = tx.variables.files.get_files("file2")

    assert len(files1) == 1
    assert len(files2) == 1
    assert files1[0].filename == "doc1.txt"
    assert files2[0].filename == "doc2.txt"

    # Verify combined size
    assert tx.variables.files_combined_size.get() == "16"  # 8 + 8


def test_nested_json_flattening():
    """Test nested JSON structure flattening."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Nested JSON structure
    body = b'{"user": {"profile": {"name": "admin", "age": 30}, "id": 123}}'
    tx.add_request_body(body, "application/json")

    # Process body
    tx.process_request_body()

    # Verify flattened keys
    assert tx.variables.args_post.get("user.profile.name") == ["admin"]
    assert tx.variables.args_post.get("user.profile.age") == ["30"]
    assert tx.variables.args_post.get("user.id") == ["123"]


def test_json_array_flattening():
    """Test JSON array flattening."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # JSON with arrays
    body = b'{"users": [{"name": "alice", "age": 30}, {"name": "bob", "age": 25}]}'
    tx.add_request_body(body, "application/json")

    # Process body
    tx.process_request_body()

    # Verify array indexing
    assert tx.variables.args_post.get("users[0].name") == ["alice"]
    assert tx.variables.args_post.get("users[0].age") == ["30"]
    assert tx.variables.args_post.get("users[1].name") == ["bob"]
    assert tx.variables.args_post.get("users[1].age") == ["25"]


def test_content_type_with_charset():
    """Test Content-Type with charset parameter."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Content-Type with charset
    body = b'{"key": "value"}'
    tx.add_request_body(body, "application/json; charset=utf-8")

    # Process body
    tx.process_request_body()

    # Verify JSON processor selected
    assert tx.variables.reqbody_processor.get() == "JSON"
    assert tx.variables.args_post.get("key") == ["value"]


def test_empty_urlencoded_body():
    """Test empty URLEncoded body."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Empty URLEncoded body
    body = b""
    tx.add_request_body(body, "application/x-www-form-urlencoded")

    # Process body - should not crash
    tx.process_request_body()

    # Verify no errors
    assert tx.variables.reqbody_error.get() == ""


def test_processor_selection_case_insensitive():
    """Test Content-Type matching is case-insensitive."""
    waf = WAF({"rules": []})
    tx = waf.new_transaction()

    # Mixed case Content-Type
    body = b'{"key": "value"}'
    tx.add_request_body(body, "Application/JSON")

    # Process body
    tx.process_request_body()

    # Verify JSON processor selected
    assert tx.variables.reqbody_processor.get() == "JSON"
    assert tx.variables.args_post.get("key") == ["value"]
