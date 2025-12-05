"""Tests for WSGI integration example."""

from __future__ import annotations

import json
from io import BytesIO
from urllib.parse import urlencode

from .conftest import EXAMPLES_DIR, import_module_from_file


class TestWSGIExample:
    """Test WSGI integration example."""

    def test_wsgi_import(self):
        """Test that WSGI example can be imported."""
        wsgi_example = EXAMPLES_DIR / "integrations" / "wsgi_example.py"
        module = import_module_from_file("wsgi_example_test", wsgi_example)

        assert hasattr(module, "LeWAFMiddleware")
        assert hasattr(module, "application")
        assert hasattr(module, "simple_wsgi_app")

    def test_wsgi_application_callable(self):
        """Test that WSGI application is callable."""
        wsgi_example = EXAMPLES_DIR / "integrations" / "wsgi_example.py"
        module = import_module_from_file("wsgi_example_test2", wsgi_example)

        # WSGI applications should be callable with (environ, start_response)
        assert callable(module.application)

    def test_wsgi_allows_safe_requests(self):
        """Test that WSGI example allows safe requests."""
        wsgi_example = EXAMPLES_DIR / "integrations" / "wsgi_example.py"
        module = import_module_from_file("wsgi_safe_test", wsgi_example)

        # Test homepage
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "wsgi.input": BytesIO(b""),
        }
        response_status = []
        response_headers = []

        def start_response(status, headers, exc_info=None):
            response_status.append(status)
            response_headers.extend(headers)

        response = module.application(environ, start_response)
        body = b"".join(response)

        assert "200 OK" in response_status[0]
        assert b"Hello from WSGI" in body

        # Test API endpoint
        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/api/users",
            "QUERY_STRING": "",
            "wsgi.input": BytesIO(b""),
        }
        response_status = []
        response_headers = []
        response = module.application(environ, start_response)
        body = b"".join(response)

        assert "200 OK" in response_status[0]
        data = json.loads(body)
        assert "users" in data
        assert len(data["users"]) == 2

    def test_wsgi_blocks_admin_access(self):
        """Test that WSGI example blocks admin parameter."""
        wsgi_example = EXAMPLES_DIR / "integrations" / "wsgi_example.py"
        module = import_module_from_file("wsgi_admin_test", wsgi_example)

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "QUERY_STRING": "admin=true",
            "wsgi.input": BytesIO(b""),
        }
        response_status = []
        response_headers = []

        def start_response(status, headers, exc_info=None):
            response_status.append(status)
            response_headers.extend(headers)

        response = module.application(environ, start_response)
        body = b"".join(response)

        assert "403 Forbidden" in response_status[0]
        data = json.loads(body)
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9001
        assert data["message"] == "deny"

    def test_wsgi_blocks_xss_attacks(self):
        """Test that WSGI example blocks XSS attacks in form data."""
        wsgi_example = EXAMPLES_DIR / "integrations" / "wsgi_example.py"
        module = import_module_from_file("wsgi_xss_test", wsgi_example)

        # Test XSS in POST form data (Phase 2 rule checks ARGS, which includes form data)
        form_data = urlencode({"test": "<script>alert(1)</script>"})
        body_data = form_data.encode("utf-8")

        environ = {
            "REQUEST_METHOD": "POST",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "CONTENT_LENGTH": str(len(body_data)),
            "wsgi.input": BytesIO(body_data),
        }
        response_status = []
        response_headers = []

        def start_response(status, headers, exc_info=None):
            response_status.append(status)
            response_headers.extend(headers)

        response = module.application(environ, start_response)
        body = b"".join(response)

        assert "403 Forbidden" in response_status[0]
        data = json.loads(body)
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9002
        assert data["message"] == "deny"
