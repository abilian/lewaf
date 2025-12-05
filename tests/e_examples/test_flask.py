"""Tests for Flask integration example."""

from __future__ import annotations

import pytest

from .conftest import EXAMPLES_DIR, import_module_from_file


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

    def test_flask_config_valid(self):
        """Test Flask example has valid WAF config."""
        pytest.importorskip("flask")
        flask_example = EXAMPLES_DIR / "integrations" / "flask_example.py"
        module = import_module_from_file("flask_config_test", flask_example)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)
