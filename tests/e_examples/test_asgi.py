"""Tests for ASGI example application."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from .conftest import EXAMPLES_DIR, import_module_from_file


class TestASGIExample:
    """Test ASGI example application."""

    def test_asgi_example_import(self):
        """Test that ASGI example can be imported."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_example_test", asgi_example)

        assert hasattr(module, "app")
        assert hasattr(module, "waf_config")

    def test_asgi_example_homepage(self):
        """Test homepage renders correctly."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_example_test2", asgi_example)

        client = TestClient(module.app)

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200
        assert b"LeWAF ASGI Middleware Demo" in response.content
        assert b"Safe endpoint" in response.content

    def test_asgi_example_safe_endpoint(self):
        """Test safe endpoint works."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_example_test3", asgi_example)

        client = TestClient(module.app)

        # Test safe endpoint
        response = client.get("/safe")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "safe" in data["message"].lower()

    def test_asgi_example_api_user_safe(self):
        """Test API user endpoint with safe input."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_example_test4", asgi_example)

        client = TestClient(module.app)

        # Test with safe user ID
        response = client.get("/api/user?id=123")
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == "123"
        assert "User" in data["name"]

    def test_asgi_example_blocks_xss_in_query(self):
        """Test that XSS attacks in query parameters are blocked."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_xss_query_test", asgi_example)

        client = TestClient(module.app)

        # Test XSS attack is blocked
        response = client.get("/api/user?id=<script>alert(1)</script>")
        assert response.status_code == 403

    def test_asgi_example_blocks_admin_path(self):
        """Test that admin path is blocked."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_admin_test", asgi_example)

        client = TestClient(module.app)

        # Test admin path is blocked
        response = client.get("/admin")
        assert response.status_code == 403

    def test_asgi_example_blocks_sql_injection(self):
        """Test that SQL injection attempts are blocked."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_sqli_test", asgi_example)

        client = TestClient(module.app)

        # Test SQL injection is blocked
        response = client.get("/api/user?id=1' UNION SELECT * FROM users--")
        assert response.status_code == 403

    def test_asgi_example_post_safe_data(self):
        """Test POST endpoint with safe data."""
        pytest.importorskip("multipart")  # Requires python-multipart
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_post_safe_test", asgi_example)

        client = TestClient(module.app)

        # Test safe POST
        response = client.post(
            "/api/submit", data={"comment": "This is a normal comment"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "This is a normal comment" in data["comment_received"]

    def test_asgi_example_blocks_xss_in_post(self):
        """Test that XSS attacks in POST data are blocked."""
        pytest.importorskip("multipart")  # Requires python-multipart
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_xss_post_test", asgi_example)

        client = TestClient(module.app)

        # Test XSS in POST form data
        response = client.post(
            "/api/submit", data={"comment": "<script>alert('xss')</script>"}
        )
        assert response.status_code == 403

    def test_asgi_example_config_valid(self):
        """Test that WAF configuration is valid."""
        asgi_example = EXAMPLES_DIR / "integrations" / "asgi_example.py"
        module = import_module_from_file("asgi_config_test", asgi_example)

        config = module.waf_config
        assert "rules" in config
        assert isinstance(config["rules"], list)
        assert len(config["rules"]) == 5  # XSS (2), admin, SQL injection (2) rules
        assert "rule_files" in config
