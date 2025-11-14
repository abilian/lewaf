"""Tests for Django integration example."""

from __future__ import annotations

import pytest

from .conftest import EXAMPLES_DIR, import_module_from_file


class TestDjangoExample:
    """Test Django integration example."""

    def test_django_import(self):
        """Test that Django example can be imported."""
        pytest.importorskip("django")
        django_example = EXAMPLES_DIR / "integrations" / "django_example.py"
        module = import_module_from_file("django_example_test", django_example)

        assert hasattr(module, "LeWAFMiddleware")
        assert hasattr(module, "application")

    def test_django_middleware_callable(self):
        """Test that Django middleware is properly configured."""
        pytest.importorskip("django")
        django_example = EXAMPLES_DIR / "integrations" / "django_example.py"
        module = import_module_from_file("django_example_test2", django_example)

        # Test middleware class exists and is callable
        assert callable(module.LeWAFMiddleware)

    def test_django_allows_safe_requests(self):
        """Test that Django example allows safe requests."""
        pytest.importorskip("django")
        from django.test import Client

        django_example = EXAMPLES_DIR / "integrations" / "django_example.py"
        module = import_module_from_file("django_safe_test", django_example)

        client = Client()

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200
        assert b"Hello from Django" in response.content

        # Test API endpoint
        response = client.get("/api/users/")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert len(data["users"]) == 2

        # Test health endpoint
        response = client.get("/health/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_django_blocks_admin_access(self):
        """Test that Django example blocks admin parameter."""
        pytest.importorskip("django")
        from django.test import Client

        django_example = EXAMPLES_DIR / "integrations" / "django_example.py"
        module = import_module_from_file("django_admin_test", django_example)

        client = Client()

        # Test admin parameter is blocked
        response = client.get("/?admin=true")
        assert response.status_code == 403

        data = response.json()
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9001
        assert data["message"] == "deny"

    def test_django_blocks_xss_attacks(self):
        """Test that Django example blocks XSS attacks in form data."""
        pytest.importorskip("django")
        from django.test import Client

        django_example = EXAMPLES_DIR / "integrations" / "django_example.py"
        module = import_module_from_file("django_xss_test", django_example)

        client = Client()

        # Test XSS in POST form data (Phase 2 rule checks ARGS, which includes form data)
        response = client.post("/", data={"test": "<script>alert(1)</script>"})
        assert response.status_code == 403

        data = response.json()
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9002
        assert data["message"] == "deny"
