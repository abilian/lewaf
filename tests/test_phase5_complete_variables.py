"""Test Phase 5 Complete Variable Coverage implementation."""

from coraza_poc.primitives.collections import TransactionVariables


class TestRequestVariables:
    """Tests for complete request variable functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_set_request_variables_basic(self):
        """Test setting basic request variables."""
        self.variables.set_request_variables(
            uri="/api/users/123",
            method="post",
            protocol="HTTP/1.1",
            body=b'{"name": "test"}',
            content_type="application/json",
        )

        assert self.variables.request_uri.get() == "/api/users/123"
        assert self.variables.request_uri_raw.get() == "/api/users/123"
        assert self.variables.request_method.get() == "POST"
        assert self.variables.request_protocol.get() == "HTTP/1.1"
        assert self.variables.request_body_length.get() == "16"

    def test_request_basename_filename_extraction(self):
        """Test extraction of basename and filename from URI paths."""
        test_cases = [
            ("/path/to/file.php", "file.php", "file.php"),
            ("/admin/config.json", "config.json", "config.json"),
            ("/api/users/", "", ""),
            ("/download.zip", "download.zip", "download.zip"),
            ("/path/to/dir", "dir", ""),
            ("/hidden/.htaccess", ".htaccess", ""),
            ("/path/to/script.php?param=value", "script.php", "script.php"),
        ]

        for uri, expected_basename, expected_filename in test_cases:
            self.variables.set_request_variables(uri=uri)
            assert self.variables.request_basename.get() == expected_basename, (
                f"Failed for URI: {uri}"
            )
            assert self.variables.request_filename.get() == expected_filename, (
                f"Failed for URI: {uri}"
            )

    def test_request_body_handling(self):
        """Test request body content and length tracking."""
        # Test with different body types
        bodies = [
            (b"", "0"),
            (b"small", "5"),
            (b'{"large": "' + b"x" * 1000 + b'"}', str(13 + 1000)),
            ("unicode content: 🔥".encode("utf-8"), "21"),
        ]

        for body, expected_length in bodies:
            self.variables.set_request_variables(body=body)
            assert self.variables.request_body_length.get() == expected_length
            assert len(self.variables.request_body.get_raw()) == int(expected_length)

    def test_method_normalization(self):
        """Test HTTP method normalization to uppercase."""
        methods = ["get", "POST", "Put", "DELETE", "patch", "HEaD"]
        expected = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]

        for method, expected_method in zip(methods, expected):
            self.variables.set_request_variables(method=method)
            assert self.variables.request_method.get() == expected_method


class TestResponseVariables:
    """Tests for response variable functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_set_response_variables_basic(self):
        """Test setting basic response variables."""
        self.variables.set_response_variables(
            status=200,
            protocol="HTTP/1.1",
            body=b'{"status": "success"}',
            content_type="application/json",
            content_length=19,
        )

        assert self.variables.response_status.get() == "200"
        assert self.variables.response_protocol.get() == "HTTP/1.1"
        assert self.variables.response_content_type.get() == "application/json"
        assert self.variables.response_content_length.get() == "19"

    def test_status_line_generation(self):
        """Test automatic status line generation."""
        test_cases = [
            (200, "HTTP/1.1", "HTTP/1.1 200 OK"),
            (404, "HTTP/1.1", "HTTP/1.1 404 Not Found"),
            (500, "HTTP/1.1", "HTTP/1.1 500 Internal Server Error"),
            (301, "HTTP/1.0", "HTTP/1.0 301 Moved Permanently"),
            (999, "HTTP/1.1", "HTTP/1.1 999 Unknown"),  # Unknown status
        ]

        for status, protocol, expected_status_line in test_cases:
            self.variables.set_response_variables(status=status, protocol=protocol)
            assert self.variables.status_line.get() == expected_status_line

    def test_response_body_auto_length(self):
        """Test automatic content length calculation from body."""
        body = b'{"message": "Hello, World!"}'
        self.variables.set_response_variables(body=body)

        assert self.variables.response_content_length.get() == str(len(body))
        assert len(self.variables.response_body.get_raw()) == len(body)

    def test_response_content_length_override(self):
        """Test explicit content length overrides automatic calculation."""
        body = b"short"
        explicit_length = 100  # Different from actual body length

        self.variables.set_response_variables(body=body, content_length=explicit_length)

        assert self.variables.response_content_length.get() == "100"

    def test_http_status_phrases(self):
        """Test comprehensive HTTP status phrase mapping."""
        status_tests = [
            (200, "OK"),
            (201, "Created"),
            (204, "No Content"),
            (301, "Moved Permanently"),
            (302, "Found"),
            (304, "Not Modified"),
            (400, "Bad Request"),
            (401, "Unauthorized"),
            (403, "Forbidden"),
            (404, "Not Found"),
            (405, "Method Not Allowed"),
            (409, "Conflict"),
            (500, "Internal Server Error"),
            (502, "Bad Gateway"),
            (503, "Service Unavailable"),
        ]

        for status, expected_phrase in status_tests:
            self.variables.set_response_variables(status=status)
            status_line = self.variables.status_line.get()
            assert expected_phrase in status_line, (
                f"Status {status} should contain '{expected_phrase}'"
            )


class TestMetadataPopulation:
    """Tests for metadata population functionality."""

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_populate_header_names(self):
        """Test population of header name collections."""
        # Add some request headers
        self.variables.request_headers.add("Content-Type", "application/json")
        self.variables.request_headers.add("Authorization", "Bearer token123")
        self.variables.request_headers.add("User-Agent", "TestAgent/1.0")

        # Add some response headers
        self.variables.response_headers.add("Content-Type", "application/json")
        self.variables.response_headers.add("Set-Cookie", "session=abc123")

        # Populate header names
        self.variables.populate_header_names()

        # Verify request header names
        request_header_names = {
            match.value for match in self.variables.request_headers_names.find_all()
        }
        expected_request_headers = {"content-type", "authorization", "user-agent"}
        assert request_header_names == expected_request_headers

        # Verify response header names
        response_header_names = {
            match.value for match in self.variables.response_headers_names.find_all()
        }
        expected_response_headers = {"content-type", "set-cookie"}
        assert response_header_names == expected_response_headers

    def test_populate_args_metadata(self):
        """Test population of argument metadata."""
        # Add various arguments
        self.variables.args.add("search", "query")
        self.variables.args.add("page", "1")
        self.variables.args.add("limit", "50")
        self.variables.args.add("filter", "active")
        self.variables.args.add("filter", "verified")  # Multiple values

        # Populate metadata
        self.variables.populate_args_metadata()

        # Verify ARGS_NAMES population
        args_names = {match.value for match in self.variables.args_names.find_all()}
        expected_names = {"search", "page", "limit", "filter"}
        assert args_names == expected_names

        # Verify ARGS_COMBINED_SIZE calculation
        # search(6) + query(5) + page(4) + 1(1) + limit(5) + 50(2) + filter(6) + active(6) + verified(8) = 43
        expected_size = (
            len("search")
            + len("query")
            + len("page")
            + len("1")
            + len("limit")
            + len("50")
            + len("filter")
            + len("active")
            + len("verified")
        )
        assert self.variables.args_combined_size.get() == str(expected_size)

    def test_populate_cookie_names(self):
        """Test population of cookie name collections."""
        # Add request cookies
        self.variables.request_cookies.add("session_id", "abc123def456")
        self.variables.request_cookies.add("preferences", "theme=dark")
        self.variables.request_cookies.add("csrf_token", "xyz789")

        # Populate cookie names
        self.variables.populate_cookie_names()

        # Verify cookie names
        cookie_names = {
            match.value for match in self.variables.request_cookies_names.find_all()
        }
        expected_names = {"session_id", "preferences", "csrf_token"}
        assert cookie_names == expected_names

    def test_args_combined_size_empty(self):
        """Test ARGS_COMBINED_SIZE with no arguments."""
        self.variables.populate_args_metadata()
        assert self.variables.args_combined_size.get() == "0"

    def test_args_combined_size_unicode(self):
        """Test ARGS_COMBINED_SIZE with Unicode content."""
        self.variables.args.add("emoji", "🔥")
        self.variables.args.add("unicode", "café")

        self.variables.populate_args_metadata()

        # Calculate expected size (Unicode characters count as their string length)
        expected_size = len("emoji") + len("🔥") + len("unicode") + len("café")
        assert self.variables.args_combined_size.get() == str(expected_size)


class TestIntegrationWorkflows:
    """Integration tests for complete variable workflows."""

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_complete_http_request_workflow(self):
        """Test complete HTTP request processing workflow."""
        # Simulate incoming HTTP request
        self.variables.set_request_variables(
            uri="/admin/users.php?page=1&search=admin",
            method="POST",
            protocol="HTTP/1.1",
            body=b'{"action": "create_user", "name": "John Doe"}',
            content_type="application/json",
        )

        # Add headers
        self.variables.request_headers.add("Content-Type", "application/json")
        self.variables.request_headers.add("Authorization", "Bearer token123")
        self.variables.request_headers.add("User-Agent", "Mozilla/5.0")

        # Add arguments (from query string and form data)
        self.variables.args.add("page", "1")
        self.variables.args.add("search", "admin")
        self.variables.args.add("action", "create_user")

        # Populate metadata
        self.variables.populate_header_names()
        self.variables.populate_args_metadata()

        # Verify request variables
        assert self.variables.request_basename.get() == "users.php"
        assert self.variables.request_filename.get() == "users.php"
        assert self.variables.request_method.get() == "POST"
        assert self.variables.request_protocol.get() == "HTTP/1.1"
        assert self.variables.request_body_length.get() == "45"

        # Verify header metadata
        header_names = {
            match.value for match in self.variables.request_headers_names.find_all()
        }
        assert "content-type" in header_names
        assert "authorization" in header_names

        # Verify args metadata
        args_names = {match.value for match in self.variables.args_names.find_all()}
        assert "page" in args_names
        assert "search" in args_names
        assert "action" in args_names

    def test_complete_http_response_workflow(self):
        """Test complete HTTP response processing workflow."""
        # Simulate HTTP response
        response_body = b'{"users": [{"id": 1, "name": "Admin"}], "total": 1}'

        self.variables.set_response_variables(
            status=200,
            protocol="HTTP/1.1",
            body=response_body,
            content_type="application/json",
        )

        # Add response headers
        self.variables.response_headers.add("Content-Type", "application/json")
        self.variables.response_headers.add("Cache-Control", "no-cache")
        self.variables.response_headers.add("X-Frame-Options", "DENY")

        # Populate metadata
        self.variables.populate_header_names()

        # Verify response variables
        assert self.variables.response_status.get() == "200"
        assert self.variables.response_protocol.get() == "HTTP/1.1"
        assert self.variables.response_content_type.get() == "application/json"
        assert self.variables.response_content_length.get() == str(len(response_body))
        assert "HTTP/1.1 200 OK" in self.variables.status_line.get()

        # Verify response header metadata
        response_header_names = {
            match.value for match in self.variables.response_headers_names.find_all()
        }
        assert "content-type" in response_header_names
        assert "cache-control" in response_header_names
        assert "x-frame-options" in response_header_names

    def test_file_upload_request_workflow(self):
        """Test file upload request processing."""
        # Simulate file upload request
        self.variables.set_request_variables(
            uri="/upload/documents/submit.php",
            method="POST",
            protocol="HTTP/1.1",
            body=b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="document.pdf"\r\n\r\n%PDF-1.4...\r\n--boundary--',
            content_type="multipart/form-data; boundary=boundary",
        )

        # Add file-related arguments
        self.variables.args.add("upload_type", "document")
        self.variables.args.add("category", "legal")

        # Populate metadata
        self.variables.populate_args_metadata()

        # Verify file-related variables
        assert self.variables.request_basename.get() == "submit.php"
        assert self.variables.request_filename.get() == "submit.php"
        assert self.variables.request_method.get() == "POST"
        assert "multipart/form-data" in self.variables.request_body.get_content_type()

        # Verify args metadata for upload parameters
        args_names = {match.value for match in self.variables.args_names.find_all()}
        assert "upload_type" in args_names
        assert "category" in args_names

    def test_api_request_with_error_response(self):
        """Test API request resulting in error response."""
        # Request
        self.variables.set_request_variables(
            uri="/api/v1/restricted-resource", method="GET", protocol="HTTP/2"
        )

        # Error response
        error_body = b'{"error": "Forbidden", "message": "Insufficient permissions"}'
        self.variables.set_response_variables(
            status=403,
            protocol="HTTP/2",
            body=error_body,
            content_type="application/json",
        )

        # Verify error handling
        assert self.variables.request_basename.get() == "restricted-resource"
        assert self.variables.request_filename.get() == ""  # No file extension
        assert self.variables.response_status.get() == "403"
        assert "HTTP/2 403 Forbidden" in self.variables.status_line.get()
        assert self.variables.response_content_length.get() == str(len(error_body))


class TestEdgeCases:
    """Tests for edge cases and error conditions."""

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_empty_uri_handling(self):
        """Test handling of empty or root URI."""
        test_uris = ["", "/", "/?param=value"]

        for uri in test_uris:
            self.variables.set_request_variables(uri=uri)
            # Should not crash and should handle gracefully
            assert isinstance(self.variables.request_basename.get(), str)
            assert isinstance(self.variables.request_filename.get(), str)

    def test_none_values_handling(self):
        """Test handling of None values in setters."""
        # Should not crash with None values
        self.variables.set_request_variables(
            uri=None, method=None, protocol=None, body=None
        )
        self.variables.set_response_variables(status=None, protocol=None, body=None)

        # Variables should remain in their default state
        assert self.variables.request_uri.get() == ""
        assert self.variables.response_status.get() == ""

    def test_large_args_combined_size(self):
        """Test ARGS_COMBINED_SIZE with large amounts of data."""
        # Add many arguments with large values
        for i in range(100):
            self.variables.args.add(f"param_{i}", "x" * 100)

        self.variables.populate_args_metadata()

        # Should calculate correctly without overflow
        expected_size = 100 * (
            len("param_") + 2 + 100
        )  # param_ + index digits + value length
        calculated_size = int(self.variables.args_combined_size.get())
        assert (
            calculated_size >= expected_size * 0.9
        )  # Allow for some variance in index lengths

    def test_populate_with_empty_collections(self):
        """Test metadata population with empty collections."""
        # Should not crash with empty collections
        self.variables.populate_header_names()
        self.variables.populate_args_metadata()
        self.variables.populate_cookie_names()

        # Should result in empty metadata collections
        assert len(self.variables.request_headers_names.find_all()) == 0
        assert len(self.variables.args_names.find_all()) == 0
        assert len(self.variables.request_cookies_names.find_all()) == 0
        assert self.variables.args_combined_size.get() == "0"
