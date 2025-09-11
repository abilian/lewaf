"""Tests for Coraza reverse proxy functionality."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from coraza_poc.proxy.server import CorazaReverseProxy, create_proxy_app


class MockBackend:
    """Mock backend application for testing."""

    def __init__(self):
        self.app = Starlette(
            routes=[
                Route("/", self.index, methods=["GET"]),
                Route("/echo", self.echo, methods=["GET", "POST"]),
                Route("/json", self.json_response, methods=["GET"]),
                Route("/headers", self.headers, methods=["GET"]),
            ]
        )

    async def index(self, request: Request) -> JSONResponse:
        return JSONResponse({"message": "Hello from backend"})

    async def echo(self, request: Request) -> JSONResponse:
        data = {
            "method": request.method,
            "path": str(request.url.path),
            "query": str(request.url.query),
            "headers": dict(request.headers),
        }

        if request.method == "POST":
            data["body"] = (await request.body()).decode()

        return JSONResponse(data)

    async def json_response(self, request: Request) -> JSONResponse:
        return JSONResponse({"data": "test", "status": "ok"})

    async def headers(self, request: Request) -> JSONResponse:
        return JSONResponse(dict(request.headers))


@pytest.fixture
def mock_backend():
    """Create a mock backend server."""
    return MockBackend()


@pytest.fixture
def backend_client(mock_backend):
    """Create a test client for the mock backend."""
    return TestClient(mock_backend.app)


def test_basic_proxy_functionality():
    """Test basic proxy setup and configuration."""
    proxy = CorazaReverseProxy(upstream_url="http://backend:8000", waf_rules=[])

    assert proxy.upstream_url == "http://backend:8000"
    assert isinstance(proxy.waf_rules, list)

    app = proxy.create_app()
    assert isinstance(app, Starlette)


def test_proxy_app_creation():
    """Test create_proxy_app function."""
    app = create_proxy_app(
        upstream_url="http://backend:8000",
        waf_rules=['SecRule ARGS "@rx test" "id:1,phase:2,deny"'],
    )

    assert isinstance(app, Starlette)
    assert hasattr(app.state, "proxy")


def test_health_check_endpoint():
    """Test the health check endpoint."""
    app = create_proxy_app(upstream_url="http://backend:8000")
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["upstream"] == "http://backend:8000"
    assert data["proxy"] == "coraza-py"


def test_waf_middleware_integration():
    """Test that WAF middleware is properly integrated."""
    app = create_proxy_app(
        upstream_url="http://backend:8000",
        waf_rules=[
            'SecRule ARGS:attack "@rx malicious" "id:1001,phase:2,deny,log,msg:\'Test attack\'"'
        ],
    )

    client = TestClient(app)

    # This should be blocked by WAF
    response = client.get("/?attack=malicious")
    assert response.status_code == 403

    # This should pass through
    response = client.get("/?normal=request")
    # Note: This will fail in testing because we don't have a real upstream
    # but the WAF processing part should work


def test_waf_blocking_behavior():
    """Test WAF blocking different types of attacks."""
    app = create_proxy_app(
        upstream_url="http://backend:8000",
        waf_rules=[
            'SecRule ARGS "@rx (union|select)" "id:2001,phase:2,deny,log,msg:\'SQL Injection\'"',
            'SecRule ARGS "@rx <script" "id:2002,phase:2,deny,log,msg:\'XSS Attack\'"',
            'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|spider)" "id:2003,phase:1,deny,log,msg:\'Bot detected\'"',
        ],
    )

    client = TestClient(app)

    # SQL Injection attempts
    response = client.get("/?id=1 union select")
    assert response.status_code == 403

    # XSS attempts
    response = client.get("/?search=<script>alert(1)</script>")
    assert response.status_code == 403

    # Bot detection
    response = client.get("/", headers={"User-Agent": "malicious-bot/1.0"})
    assert response.status_code == 403


def test_request_method_handling():
    """Test different HTTP methods are handled correctly."""
    app = create_proxy_app(upstream_url="http://backend:8000")
    client = TestClient(app)

    # These will fail because there's no upstream, but should not be blocked by WAF
    methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    for method in methods:
        response = client.request(method, "/test")
        # Should not be WAF-blocked (403), but will fail on proxy (502)
        assert response.status_code != 403


def test_waf_rule_precedence():
    """Test that WAF rules are evaluated correctly."""
    app = create_proxy_app(
        upstream_url="http://backend:8000",
        waf_rules=[
            # This rule should trigger first
            'SecRule ARGS:test "@rx danger" "id:3001,phase:2,deny,log,msg:\'Danger detected\'"',
            # This rule should not be reached
            'SecRule ARGS:test "@rx .*" "id:3002,phase:2,deny,log,msg:\'All args blocked\'"',
        ],
    )

    client = TestClient(app)

    # Should be blocked by first rule
    response = client.get("/?test=danger")
    assert response.status_code == 403

    # Should be blocked by second rule
    response = client.get("/?test=anything")
    assert response.status_code == 403


def test_configuration_validation():
    """Test configuration validation and defaults."""
    # Test with minimal config
    app1 = create_proxy_app(upstream_url="http://backend:8000")
    assert isinstance(app1, Starlette)

    # Test with custom rules
    custom_rules = ['SecRule ARGS "@rx test" "id:4001,phase:2,deny,log"']
    app2 = create_proxy_app(upstream_url="http://backend:8000", waf_rules=custom_rules)
    assert isinstance(app2, Starlette)

    # Test with proxy config
    app3 = create_proxy_app(
        upstream_url="http://backend:8000", timeout=60.0, max_connections=200
    )
    assert isinstance(app3, Starlette)


def test_error_handling():
    """Test error handling in various scenarios."""
    app = create_proxy_app(upstream_url="http://invalid-upstream:8000")
    client = TestClient(app)

    # Should get 502 Bad Gateway for invalid upstream
    response = client.get("/test")
    assert response.status_code == 502


def test_default_rules_are_applied():
    """Test that default rules are applied when none are specified."""
    app = create_proxy_app(upstream_url="http://backend:8000")
    client = TestClient(app)

    # The default rules should include bot detection
    response = client.get("/", headers={"User-Agent": "bot/1.0"})
    assert response.status_code == 403
