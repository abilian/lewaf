"""Tests for example files.

This module tests that all example files can be imported and their
basic functionality works correctly.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

# Get examples directory
EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


def import_module_from_file(module_name: str, file_path: Path):
    """Import a module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    msg = f"Could not load module from {file_path}"
    raise ImportError(msg)


class TestFlaskExample:
    """Test Flask integration example."""

    def test_flask_import(self):
        """Test that Flask example can be imported."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_example_test", flask_example)

        assert hasattr(module, "app")
        assert hasattr(module, "WAF")
        assert hasattr(module, "WAF_CONFIG")

    def test_flask_routes_defined(self):
        """Test that Flask routes are defined."""
        flask = pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_example_test2", flask_example)

        # Test that routes exist
        assert isinstance(module.app, flask.Flask)

        # Get registered routes
        routes = [rule.rule for rule in module.app.url_map.iter_rules()]

        assert "/" in routes
        assert "/api/users" in routes
        assert "/health" in routes
        assert "/api/search" in routes

    def test_flask_allows_safe_requests(self):
        """Test that Flask example allows safe requests."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_safe_test", flask_example)

        with module.app.test_client() as client:
            # Test homepage
            response = client.get("/")
            assert response.status_code == 200
            assert b"Hello from Flask" in response.data

            # Test API endpoint
            response = client.get("/api/users")
            assert response.status_code == 200
            data = response.get_json()
            assert "users" in data
            assert len(data["users"]) == 2

            # Test health endpoint
            response = client.get("/health")
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] == "healthy"

    def test_flask_blocks_admin_access(self):
        """Test that Flask example blocks admin parameter."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_admin_test", flask_example)

        with module.app.test_client() as client:
            # Test admin parameter is blocked
            response = client.get("/?admin=true")
            assert response.status_code == 403

            data = response.get_json()
            assert data["error"] == "Request blocked by WAF"
            assert data["rule_id"] == 9001
            assert data["message"] == "deny"

    def test_flask_blocks_xss_attacks(self):
        """Test that Flask example blocks XSS attacks."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_xss_test", flask_example)

        with module.app.test_client() as client:
            # Test XSS in query parameter
            response = client.get("/?test=<script>alert(1)</script>")
            assert response.status_code == 403

            data = response.get_json()
            assert data["error"] == "Request blocked by WAF"
            assert data["rule_id"] == 9002
            assert data["message"] == "deny"


class TestFastAPIExample:
    """Test FastAPI integration example."""

    def test_fastapi_import(self):
        """Test that FastAPI example can be imported."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_example_test", fastapi_example)

        assert hasattr(module, "app")
        assert hasattr(module, "WAF")
        assert hasattr(module, "WAF_CONFIG")
        assert hasattr(module, "LeWAFMiddleware")

    def test_fastapi_routes(self):
        """Test FastAPI routes work."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_example_test2", fastapi_example)

        client = TestClient(module.app)

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200
        assert "message" in response.json()

        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_fastapi_allows_safe_requests(self):
        """Test that FastAPI example allows safe requests."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_safe_test", fastapi_example)

        client = TestClient(module.app)

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data

        # Test API endpoint
        response = client.get("/api/users")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 3

        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_fastapi_blocks_admin_access(self):
        """Test that FastAPI example blocks admin parameter."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_admin_block_test", fastapi_example)

        client = TestClient(module.app)

        # Test admin parameter is blocked
        response = client.get("/?admin=true")
        assert response.status_code == 403

        data = response.json()
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9001
        assert data["message"] == "deny"

    def test_fastapi_blocks_xss_attacks(self):
        """Test that FastAPI example blocks XSS attacks."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_xss_block_test", fastapi_example)

        client = TestClient(module.app)

        # Test XSS in query parameter
        response = client.get("/?test=<script>alert(1)</script>")
        assert response.status_code == 403

        data = response.json()
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9002
        assert data["message"] == "deny"


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


class TestAuditLoggingExample:
    """Test audit logging example."""

    def test_audit_logging_import(self):
        """Test that audit logging example can be imported."""
        audit_example = EXAMPLES_DIR / "audit_logging_example.py"
        module = import_module_from_file("audit_logging_test", audit_example)

        assert hasattr(module, "basic_audit_logging_example")
        assert hasattr(module, "attack_detection_example")
        assert hasattr(module, "performance_monitoring_example")

    def test_audit_logging_functions_callable(self):
        """Test that all example functions are callable."""
        audit_example = EXAMPLES_DIR / "audit_logging_example.py"
        module = import_module_from_file("audit_logging_test2", audit_example)

        functions = [
            "basic_audit_logging_example",
            "attack_detection_example",
            "global_logging_configuration",
            "performance_monitoring_example",
            "configuration_change_example",
            "error_logging_example",
            "sensitive_data_masking_example",
        ]

        for func_name in functions:
            assert hasattr(module, func_name)
            assert callable(getattr(module, func_name))


class TestASGIDemo:
    """Test ASGI demo application."""

    def test_asgi_demo_import(self):
        """Test that ASGI demo can be imported."""
        asgi_demo = EXAMPLES_DIR / "asgi_demo.py"
        module = import_module_from_file("asgi_demo_test", asgi_demo)

        assert hasattr(module, "app")

    def test_asgi_demo_routes(self):
        """Test ASGI demo routes work."""
        asgi_demo = EXAMPLES_DIR / "asgi_demo.py"
        module = import_module_from_file("asgi_demo_test2", asgi_demo)

        client = TestClient(module.app)

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200
        assert b"LeWAF ASGI Demo" in response.content

        # Test safe endpoint
        response = client.get("/safe")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


class TestProductionApp:
    """Test production application example."""

    def test_production_app_import(self):
        """Test that production app can be imported."""
        prod_app = EXAMPLES_DIR / "production" / "app.py"
        module = import_module_from_file("production_app_test", prod_app)

        assert hasattr(module, "app")
        assert hasattr(module, "WAF_CONFIG")

    def test_production_app_routes(self):
        """Test production app routes work."""
        prod_app = EXAMPLES_DIR / "production" / "app.py"
        module = import_module_from_file("production_app_test2", prod_app)

        client = TestClient(module.app)

        # Test homepage
        response = client.get("/")
        assert response.status_code == 200

        # Test health check
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

        # Test metrics endpoint
        response = client.get("/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "waf" in data
        assert "app" in data


class TestExamplesWAFProtection:
    """Test that WAF protection works in examples."""

    def test_fastapi_blocks_admin(self):
        """Test that FastAPI example blocks admin access."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_admin_test", fastapi_example)

        client = TestClient(module.app)

        # Test admin access is blocked (Phase 1 rule)
        response = client.get("/?admin=true")
        assert response.status_code == 403

    def test_asgi_demo_blocks_xss(self):
        """Test that ASGI demo blocks XSS attacks."""
        asgi_demo = EXAMPLES_DIR / "asgi_demo.py"
        module = import_module_from_file("asgi_xss_test", asgi_demo)

        client = TestClient(module.app)

        # Test XSS attack is blocked
        response = client.get("/api/user?id=<script>alert(1)</script>")
        assert response.status_code == 403

    def test_asgi_demo_blocks_admin(self):
        """Test that ASGI demo blocks admin path."""
        asgi_demo = EXAMPLES_DIR / "asgi_demo.py"
        module = import_module_from_file("asgi_admin_test", asgi_demo)

        client = TestClient(module.app)

        # Test admin path is blocked
        response = client.get("/admin")
        assert response.status_code == 403

    def test_production_app_allows_safe_requests(self):
        """Test that production app allows safe requests."""
        prod_app = EXAMPLES_DIR / "production" / "app.py"
        module = import_module_from_file("production_safe_test", prod_app)

        client = TestClient(module.app)

        # Test safe requests pass through
        response = client.get("/api/users")
        assert response.status_code == 200
        data = response.json()
        assert "users" in data
        assert len(data["users"]) == 2


class TestExamplesConfiguration:
    """Test example configurations are valid."""

    def test_flask_config_valid(self):
        """Test Flask example has valid WAF config."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_config_test", flask_example)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)

    def test_fastapi_config_valid(self):
        """Test FastAPI example has valid WAF config."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_config_test", fastapi_example)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)

    def test_production_config_valid(self):
        """Test production app has valid WAF config."""
        prod_app = EXAMPLES_DIR / "production" / "app.py"
        module = import_module_from_file("production_config_test", prod_app)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
