"""Tests for FastAPI integration example."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from .conftest import EXAMPLES_DIR, import_module_from_file


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
        """Test that FastAPI example blocks XSS attacks in form data."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_xss_block_test", fastapi_example)

        client = TestClient(module.app)

        # Test XSS in POST form data (Phase 2 rule checks ARGS, which includes form data)
        response = client.post("/", data={"test": "<script>alert(1)</script>"})
        assert response.status_code == 403

        data = response.json()
        assert data["error"] == "Request blocked by WAF"
        assert data["rule_id"] == 9002
        assert data["message"] == "deny"

    def test_fastapi_config_valid(self):
        """Test FastAPI example has valid WAF config."""
        pytest.importorskip("fastapi")
        fastapi_example = EXAMPLES_DIR / "integrations" / "fastapi_example.py"
        module = import_module_from_file("fastapi_config_test", fastapi_example)

        config = module.WAF_CONFIG
        assert "rules" in config
        assert isinstance(config["rules"], list)
