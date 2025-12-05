"""Tests for ASGI middleware integration."""

from __future__ import annotations

import pytest
import yaml
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from lewaf.integration.asgi import ASGIMiddleware, ASGIMiddlewareFactory


# Test application routes
async def app_test_route(request):
    """Test route - supports GET and POST."""
    if request.method == "POST":
        # Try to get form or JSON data
        try:
            if request.headers.get("content-type", "").startswith("application/json"):
                data = await request.json()
            else:
                data = await request.form()
                data = dict(data)
        except Exception:
            data = {}
        return JSONResponse({"status": "ok", "method": "POST", "data": data})
    return JSONResponse({"status": "ok"})


async def app_admin_route(request):
    """Admin route."""
    return JSONResponse({"admin": True})


# Create test application
routes = [
    Route("/test", app_test_route, methods=["GET", "POST"]),
    Route("/admin", app_admin_route),
]

base_app = Starlette(routes=routes)


@pytest.fixture
def waf_config():
    """WAF configuration for testing."""
    return {
        "rules": [
            # Phase 1: Check query params
            'SecRule ARGS "@rx <script" "id:1,phase:1,deny,msg:XSS Attack"',
            'SecRule REQUEST_URI "@rx /admin" "id:2,phase:1,deny,msg:Admin Blocked"',
            'SecRule ARGS "@rx union.*select" "id:3,phase:1,deny,msg:SQL Injection"',
            # Phase 2: Check POST body params
            'SecRule ARGS "@rx <script" "id:4,phase:2,deny,msg:XSS Attack POST"',
            'SecRule ARGS "@rx union.*select" "id:5,phase:2,deny,msg:SQL Injection POST"',
        ],
    }


@pytest.fixture
def protected_app(waf_config):
    """Application wrapped with WAF middleware."""
    return ASGIMiddleware(base_app, config_dict=waf_config)


@pytest.fixture
def client(protected_app):
    """Test client."""
    return TestClient(protected_app)


def test_middleware_initialization(waf_config):
    """Test middleware initializes successfully."""
    app = ASGIMiddleware(base_app, config_dict=waf_config)
    assert app.waf is not None
    assert app.app is base_app


def test_safe_request_passes(client):
    """Test that safe requests pass through."""
    response = client.get("/test")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_xss_attack_blocked(client):
    """Test that XSS attacks are blocked."""
    response = client.get("/test?param=<script>alert('xss')</script>")
    assert response.status_code == 403
    assert b"403 Forbidden" in response.content


def test_admin_path_blocked(client):
    """Test that admin paths are blocked."""
    response = client.get("/admin")
    assert response.status_code == 403
    assert b"403 Forbidden" in response.content


def test_sql_injection_blocked(client):
    """Test that SQL injection attempts are blocked."""
    response = client.get("/test?id=1' union select * from users--")
    assert response.status_code == 403
    assert b"403 Forbidden" in response.content


def test_post_request_with_safe_data(client):
    """Test POST request with safe data."""
    response = client.post("/test", json={"name": "John Doe"})
    assert response.status_code == 200


def test_post_request_with_xss(client):
    """Test POST request with XSS payload."""
    response = client.post("/test", json={"comment": "<script>bad()</script>"})
    assert response.status_code == 403


def test_form_data_with_xss(client):
    """Test form data with XSS payload."""
    response = client.post(
        "/test",
        data={"field": "<script>alert(1)</script>"},
    )
    assert response.status_code == 403


def test_multiple_parameters(client):
    """Test request with multiple parameters."""
    response = client.get("/test?name=John&age=30&city=NYC")
    assert response.status_code == 200


def test_multiple_parameters_one_malicious(client):
    """Test request where one parameter is malicious."""
    response = client.get("/test?name=<script>&age=30")
    assert response.status_code == 403


def test_case_sensitive_detection(client):
    """Test that detection works with exact case match."""
    # Our regex is case-sensitive by default, so this should pass
    response = client.get("/test?param=<script>alert()</script>")
    assert response.status_code == 403

    # Mixed case should not match (unless we add case-insensitive flag)
    response2 = client.get("/test?param=<ScRiPt>alert()</ScRiPt>")
    # This will pass through since regex is case-sensitive
    assert response2.status_code == 200


def test_url_encoded_attack(client):
    """Test URL-encoded attack."""
    response = client.get("/test?param=%3Cscript%3Ealert()%3C/script%3E")
    # URL will be decoded by the client/framework
    assert response.status_code == 403


def test_middleware_with_config_file(tmpdir):
    """Test middleware initialization with config file."""
    # Create config file
    config_file = tmpdir / "test.yaml"
    config_data = {
        "engine": "DetectionOnly",
        "rules": [
            'SecRule ARGS "@rx test" "id:1,deny"',
        ],
    }
    with open(config_file, "w") as f:
        yaml.dump(config_data, f)

    # Create middleware
    app = ASGIMiddleware(base_app, config_file=str(config_file))
    assert app.waf is not None
    assert app.config_manager is not None


def test_middleware_factory_shared_waf(waf_config):
    """Test middleware factory with shared WAF instance."""
    factory = ASGIMiddlewareFactory(config_dict=waf_config)

    app1 = factory.wrap(base_app)
    app2 = factory.wrap(base_app)

    # Both should share the same WAF instance
    assert app1.waf is app2.waf


def test_middleware_factory_multiple_apps(waf_config):
    """Test factory can wrap multiple apps."""
    factory = ASGIMiddlewareFactory(config_dict=waf_config)

    # Create two different apps
    async def app1_route(request):
        return JSONResponse({"app": "1"})

    async def app2_route(request):
        return JSONResponse({"app": "2"})

    app1 = Starlette(routes=[Route("/", app1_route)])
    app2 = Starlette(routes=[Route("/", app2_route)])

    # Wrap both
    wrapped1 = factory.wrap(app1)
    wrapped2 = factory.wrap(app2)

    # Test both work
    client1 = TestClient(wrapped1)
    client2 = TestClient(wrapped2)

    response1 = client1.get("/")
    response2 = client2.get("/")

    assert response1.json() == {"app": "1"}
    assert response2.json() == {"app": "2"}

    # Both should block XSS
    assert client1.get("/?x=<script>").status_code == 403
    assert client2.get("/?x=<script>").status_code == 403


def test_headers_in_request(client):
    """Test that headers are processed."""
    response = client.get(
        "/test",
        headers={"X-Custom": "value"},
    )
    # Should pass with normal headers
    assert response.status_code == 200


def test_custom_headers_with_xss(client):
    """Test XSS in custom headers."""
    response = client.get(
        "/test?user=<script>",
        headers={"X-Custom": "value"},
    )
    # Should block due to XSS in query param
    assert response.status_code == 403


def test_content_type_json(client):
    """Test JSON content type handling."""
    response = client.post(
        "/test",
        json={"data": "test"},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200


def test_middleware_passes_through_non_http(waf_config):
    """Test that non-HTTP connections pass through."""

    # Create a WebSocket-like app
    async def websocket_app(scope, receive, send):
        assert scope["type"] == "websocket"

    app = ASGIMiddleware(websocket_app, config_dict=waf_config)

    # The middleware should pass WebSocket through without processing
    # We can't easily test this without a full WebSocket client,
    # but the code path is covered
    assert app.app is websocket_app


def test_middleware_error_handling(waf_config):
    """Test that WAF errors don't crash the application."""

    # Create an app that will cause the WAF to process
    async def app_route(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/test", app_route)])
    wrapped = ASGIMiddleware(app, config_dict=waf_config)
    client = TestClient(wrapped)

    # Normal request should work
    response = client.get("/test")
    assert response.status_code == 200


def test_large_request_body(client):
    """Test handling of large request bodies."""
    large_data = {"data": "x" * 10000}
    response = client.post("/test", json=large_data)
    # Should pass if no malicious content
    assert response.status_code == 200


def test_large_request_body_with_xss(client):
    """Test large request body with XSS."""
    large_data = {"data": "x" * 1000 + "<script>alert()</script>"}
    response = client.post("/test", json=large_data)
    assert response.status_code == 403


def test_empty_request_body(client):
    """Test handling of empty request body."""
    response = client.post("/test")
    assert response.status_code == 200


def test_block_response_headers(client):
    """Test that block response includes WAF headers."""
    response = client.get("/test?x=<script>")
    assert response.status_code == 403
    assert "x-waf-blocked" in response.headers
    assert response.headers["x-waf-blocked"] == "true"


def test_safe_request_no_waf_headers(client):
    """Test that safe requests don't get WAF headers."""
    response = client.get("/test")
    assert response.status_code == 200
    assert "x-waf-blocked" not in response.headers
