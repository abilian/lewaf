"""Tests for production application example."""

from __future__ import annotations

from starlette.testclient import TestClient

from .conftest import EXAMPLES_DIR, import_module_from_file


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

    def test_production_config_valid(self):
        """Test production app has valid WAF config."""
        prod_app = EXAMPLES_DIR / "production" / "app.py"
        module = import_module_from_file("production_config_test", prod_app)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)
