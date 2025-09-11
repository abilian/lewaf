"""Tests for Starlette Coraza integration."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from coraza_poc.integration import WAF
from coraza_poc.integrations.starlette import CorazaMiddleware, create_waf_app


@pytest.fixture
def sample_app():
    """Create a simple Starlette app for testing."""

    async def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"message": "Hello World"})

    async def echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "method": request.method,
                "path": str(request.url.path),
                "query": dict(request.query_params),
                "headers": dict(request.headers),
            }
        )

    app = Starlette(
        routes=[
            Route("/", homepage, methods=["GET"]),
            Route("/echo", echo, methods=["GET", "POST"]),
        ]
    )

    return app


def test_coraza_middleware_init():
    """Test CorazaMiddleware initialization."""
    app = Starlette()

    # Test with rules
    rules = ['SecRule ARGS "@rx test" "id:1,phase:2,deny"']
    middleware = CorazaMiddleware(app, rules=rules)

    assert middleware.waf is not None
    assert middleware.block_response_status == 403


def test_middleware_with_custom_waf():
    """Test middleware with pre-configured WAF."""
    app = Starlette()

    waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1001,phase:2,deny"']})
    middleware = CorazaMiddleware(app, waf=waf)

    assert middleware.waf is waf


def test_create_waf_app_function():
    """Test the create_waf_app helper function."""
    base_app = Starlette()

    rules = ['SecRule ARGS "@rx malicious" "id:2001,phase:2,deny"']
    waf_app = create_waf_app(base_app, rules=rules)

    assert isinstance(waf_app, Starlette)


def test_basic_request_passthrough(sample_app):
    """Test that normal requests pass through without blocking."""
    # Add WAF with no blocking rules
    waf_app = create_waf_app(sample_app, rules=[])
    client = TestClient(waf_app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "Hello World"


def test_malicious_request_blocking(sample_app):
    """Test that malicious requests are blocked."""
    rules = [
        'SecRule ARGS:attack "@rx malicious" "id:3001,phase:2,deny,log,msg:\'Attack detected\'"'
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Normal request should pass
    response = client.get("/echo?normal=data")
    assert response.status_code == 200

    # Malicious request should be blocked
    response = client.get("/echo?attack=malicious")
    assert response.status_code == 403

    # Verify block response format
    data = response.json()
    assert "error" in data
    assert "rule_id" in data
    assert data["rule_id"] == 3001


def test_post_request_handling(sample_app):
    """Test POST request handling through WAF."""
    rules = [
        'SecRule ARGS "@rx (union|select)" "id:3002,phase:2,deny,log,msg:\'SQL Injection\'"'
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Normal POST should pass
    response = client.post("/echo", json={"data": "normal"})
    assert response.status_code == 200

    # Malicious POST should be blocked (in query params)
    response = client.post("/echo?injection=union select")
    assert response.status_code == 403


def test_header_based_rules(sample_app):
    """Test WAF rules based on request headers."""
    rules = [
        'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler)" "id:3003,phase:1,deny,log,msg:\'Bot detected\'"'
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Normal user agent should pass
    response = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
    assert response.status_code == 200

    # Bot user agent should be blocked
    response = client.get("/", headers={"User-Agent": "malicious-bot/1.0"})
    assert response.status_code == 403


def test_custom_block_response():
    """Test custom block response configuration."""
    app = Starlette()
    rules = ['SecRule ARGS "@rx blocked" "id:3004,phase:2,deny"']

    # Custom block response
    waf_app = create_waf_app(
        app, rules=rules, block_response_status=429, block_response_body="Rate limited"
    )

    client = TestClient(waf_app)

    response = client.get("/?test=blocked")
    assert response.status_code == 429
    assert response.text == "Rate limited"


def test_query_parameter_processing(sample_app):
    """Test that query parameters are properly processed by WAF."""
    rules = [
        'SecRule ARGS:id "@rx ^[0-9]+$" "id:3005,phase:2,pass,log"',  # Allow only numbers
        'SecRule ARGS:id "@rx [^0-9]" "id:3006,phase:2,deny,log,msg:\'Invalid ID format\'"',  # Block non-numbers
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Valid numeric ID should pass
    response = client.get("/echo?id=123")
    assert response.status_code == 200

    # Invalid ID format should be blocked
    response = client.get("/echo?id=abc123")
    assert response.status_code == 403


def test_multiple_rule_evaluation(sample_app):
    """Test that multiple rules are evaluated correctly."""
    rules = [
        'SecRule ARGS:test1 "@rx danger" "id:3007,phase:2,deny,log,msg:\'Test1 danger\'"',
        'SecRule ARGS:test2 "@rx evil" "id:3008,phase:2,deny,log,msg:\'Test2 evil\'"',
        'SecRule ARGS:test3 "@rx safe" "id:3009,phase:2,pass,log,msg:\'Test3 safe\'"',
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Should be blocked by first rule
    response = client.get("/echo?test1=danger")
    assert response.status_code == 403

    # Should be blocked by second rule
    response = client.get("/echo?test2=evil")
    assert response.status_code == 403

    # Should pass with safe value
    response = client.get("/echo?test3=safe")
    assert response.status_code == 200


def test_error_handling_in_middleware():
    """Test middleware behavior when WAF encounters errors."""
    app = Starlette()

    # Create middleware with invalid config to trigger potential errors
    waf_app = create_waf_app(app, rules=[])
    client = TestClient(waf_app)

    # Should not crash on normal requests even with edge cases
    response = client.get("/", headers={"Host": "test.example.com"})
    # Might be 404 (no routes) but shouldn't be 500
    assert response.status_code != 500


def test_uri_processing(sample_app):
    """Test URI-based WAF rules."""
    rules = [
        'SecRule REQUEST_URI "@rx admin" "id:3010,phase:1,deny,log,msg:\'Admin access denied\'"'
    ]

    waf_app = create_waf_app(sample_app, rules=rules)
    client = TestClient(waf_app)

    # Normal path should pass
    response = client.get("/echo")
    assert response.status_code == 200

    # Admin path should be blocked
    response = client.get("/admin/panel")
    assert response.status_code == 403
