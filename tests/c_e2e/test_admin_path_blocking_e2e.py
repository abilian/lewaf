"""End-to-end tests for admin path blocking with HTTP server and client.

This module tests the complete stack: HTTP server, WAF middleware,
rule evaluation, and HTTP responses using Starlette TestClient.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from lewaf.integration import WAF
from lewaf.integrations.starlette import create_waf_app


def create_test_app():
    """Create test application with various endpoints."""

    async def homepage(request: Request) -> JSONResponse:
        return JSONResponse({
            "message": "Welcome to homepage",
            "path": str(request.url.path),
        })

    async def admin_panel(request: Request) -> JSONResponse:
        return JSONResponse({"message": "Admin panel", "admin": True})

    async def user_page(request: Request) -> JSONResponse:
        return JSONResponse({"message": "User page", "path": str(request.url.path)})

    async def api_endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"message": "API endpoint", "path": str(request.url.path)})

    return Starlette(
        routes=[
            Route("/", homepage, methods=["GET"]),
            Route("/admin", admin_panel, methods=["GET", "POST", "PUT", "DELETE"]),
            Route("/user", user_page, methods=["GET"]),
            Route("/api/users", api_endpoint, methods=["GET", "POST"]),
        ]
    )


@pytest.fixture
def admin_blocking_app():
    """Create application with WAF that blocks /admin paths."""
    base_app = create_test_app()
    rules = [
        'SecRule REQUEST_URI "@streq /admin" '
        "\"id:101,phase:1,t:lowercase,deny,msg:'ADMIN PATH forbidden'\""
    ]
    return create_waf_app(base_app, rules=rules)


def test_e2e_blocks_lowercase_admin(admin_blocking_app):
    """E2E: Test HTTP client receives 403 for /admin."""
    client = TestClient(admin_blocking_app)

    response = client.get("/admin")

    assert response.status_code == 403
    data = response.json()
    assert "error" in data
    assert data["rule_id"] == 101
    # Note: message comes from middleware's block_response_body, not rule's msg
    assert data["message"] == "Request blocked by WAF"


def test_e2e_blocks_uppercase_admin(admin_blocking_app):
    """E2E: Test HTTP client receives 403 for /ADMIN."""
    client = TestClient(admin_blocking_app)

    response = client.get("/ADMIN")

    assert response.status_code == 403
    data = response.json()
    assert data["rule_id"] == 101


def test_e2e_blocks_mixed_case_admin(admin_blocking_app):
    """E2E: Test HTTP client receives 403 for /Admin."""
    client = TestClient(admin_blocking_app)

    response = client.get("/Admin")

    assert response.status_code == 403
    data = response.json()
    assert data["rule_id"] == 101


def test_e2e_blocks_all_case_variations(admin_blocking_app):
    """E2E: Test all case variations of /admin are blocked."""
    client = TestClient(admin_blocking_app)

    case_variations = ["/admin", "/ADMIN", "/Admin", "/aDmIn", "/AdMiN"]

    for path in case_variations:
        response = client.get(path)
        assert response.status_code == 403, f"Path {path} should be blocked"
        assert response.json()["rule_id"] == 101


def test_e2e_allows_homepage(admin_blocking_app):
    """E2E: Test homepage is accessible."""
    client = TestClient(admin_blocking_app)

    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Welcome to homepage"


def test_e2e_allows_user_page(admin_blocking_app):
    """E2E: Test user page is accessible."""
    client = TestClient(admin_blocking_app)

    response = client.get("/user")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "User page"


def test_e2e_allows_api_endpoint(admin_blocking_app):
    """E2E: Test API endpoint is accessible."""
    client = TestClient(admin_blocking_app)

    response = client.get("/api/users")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "API endpoint"


def test_e2e_blocks_admin_all_http_methods(admin_blocking_app):
    """E2E: Test /admin is blocked for all HTTP methods."""
    client = TestClient(admin_blocking_app)

    # Test GET
    response = client.get("/admin")
    assert response.status_code == 403

    # Test POST
    response = client.post("/admin", json={"test": "data"})
    assert response.status_code == 403

    # Test PUT
    response = client.put("/admin", json={"test": "data"})
    assert response.status_code == 403

    # Test DELETE
    response = client.delete("/admin")
    assert response.status_code == 403


def test_e2e_response_format(admin_blocking_app):
    """E2E: Test that blocked response has correct format."""
    client = TestClient(admin_blocking_app)

    response = client.get("/admin")

    assert response.status_code == 403
    assert response.headers["content-type"] == "application/json"

    data = response.json()
    assert "error" in data
    assert "rule_id" in data
    assert "message" in data
    assert data["error"] == "Request blocked by WAF"
    assert data["rule_id"] == 101
    assert data["message"] == "Request blocked by WAF"


def test_e2e_multiple_requests_independent(admin_blocking_app):
    """E2E: Test multiple HTTP requests are independent."""
    client = TestClient(admin_blocking_app)

    # First request: blocked
    response1 = client.get("/admin")
    assert response1.status_code == 403

    # Second request: allowed
    response2 = client.get("/user")
    assert response2.status_code == 200

    # Third request: blocked (different case)
    response3 = client.get("/ADMIN")
    assert response3.status_code == 403

    # Fourth request: allowed
    response4 = client.get("/")
    assert response4.status_code == 200


def test_e2e_with_request_headers(admin_blocking_app):
    """E2E: Test admin blocking with various request headers."""
    client = TestClient(admin_blocking_app)

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Authorization": "Bearer token123",
    }

    response = client.get("/admin", headers=headers)

    # Should still be blocked regardless of headers
    assert response.status_code == 403


def test_e2e_admin_with_query_string(admin_blocking_app):
    """E2E: Test /admin with query string.

    Note: REQUEST_URI only contains the path, not query string in Starlette.
    """
    client = TestClient(admin_blocking_app)

    response = client.get("/admin?user=test&action=view")

    # REQUEST_URI = "/admin" (path only), so this WILL be blocked
    assert response.status_code == 403


def test_e2e_concurrent_requests_simulation(admin_blocking_app):
    """E2E: Simulate concurrent requests to test thread safety."""
    client = TestClient(admin_blocking_app)

    # Simulate multiple concurrent requests
    responses = []
    for i in range(10):
        if i % 2 == 0:
            responses.append(client.get("/admin"))
        else:
            responses.append(client.get("/user"))

    # Check results
    for i, response in enumerate(responses):
        if i % 2 == 0:
            assert response.status_code == 403, (
                f"Request {i} to /admin should be blocked"
            )
        else:
            assert response.status_code == 200, (
                f"Request {i} to /user should be allowed"
            )


def test_e2e_with_multiple_blocking_rules():
    """E2E: Test application with multiple path blocking rules."""
    base_app = create_test_app()
    rules = [
        'SecRule REQUEST_URI "@streq /admin" '
        "\"id:101,phase:1,t:lowercase,deny,msg:'Admin blocked'\"",
        'SecRule REQUEST_URI "@streq /root" '
        "\"id:102,phase:1,t:lowercase,deny,msg:'Root blocked'\"",
    ]
    waf_app = create_waf_app(base_app, rules=rules)
    client = TestClient(waf_app)

    # Test /admin blocked
    response = client.get("/admin")
    assert response.status_code == 403
    assert response.json()["rule_id"] == 101

    # Test /ADMIN blocked
    response = client.get("/ADMIN")
    assert response.status_code == 403
    assert response.json()["rule_id"] == 101

    # Test /root blocked (not defined in routes, but WAF blocks it first)
    response = client.get("/root")
    assert response.status_code == 403
    assert response.json()["rule_id"] == 102

    # Test /user allowed
    response = client.get("/user")
    assert response.status_code == 200


def test_e2e_custom_block_status_code():
    """E2E: Test custom block response status code."""
    from lewaf.integrations.starlette import CorazaMiddleware

    base_app = create_test_app()
    rules = [
        'SecRule REQUEST_URI "@streq /admin" '
        "\"id:101,phase:1,t:lowercase,deny,msg:'Admin blocked'\""
    ]

    # Create WAF
    waf = WAF({"rules": rules})

    # Create middleware with custom status code
    app = CorazaMiddleware(base_app, waf=waf, block_response_status=401)

    client = TestClient(app)

    response = client.get("/admin")

    # Should use custom status code (401 instead of 403)
    assert response.status_code == 401
    # When status is not 403, response is text/plain
    assert response.text == "Request blocked by WAF"


def test_e2e_options_method(admin_blocking_app):
    """E2E: Test OPTIONS method to /admin."""
    client = TestClient(admin_blocking_app)

    response = client.options("/admin")

    # OPTIONS should also be blocked
    assert response.status_code == 403


def test_e2e_admin_path_performance(admin_blocking_app):
    """E2E: Test performance of admin path blocking (should be fast)."""
    import time

    client = TestClient(admin_blocking_app)

    # Measure time for 100 blocked requests
    start = time.perf_counter()
    for _ in range(100):
        client.get("/admin")
    end = time.perf_counter()

    avg_time = (end - start) / 100

    # Each request should take < 10ms (very generous threshold)
    assert avg_time < 0.01, f"Average request time {avg_time * 1000:.2f}ms is too slow"


def test_e2e_full_request_lifecycle(admin_blocking_app):
    """E2E: Test full request lifecycle from client to server."""
    client = TestClient(admin_blocking_app)

    # 1. Make request
    response = client.get("/ADMIN")

    # 2. Verify WAF intercepted before reaching application
    assert response.status_code == 403

    # 3. Verify response metadata
    assert "content-type" in response.headers
    assert response.headers["content-type"] == "application/json"

    # 4. Verify response body
    data = response.json()
    assert isinstance(data, dict)
    assert "error" in data
    assert "rule_id" in data
    assert data["rule_id"] == 101

    # 5. Make another request that should succeed
    response2 = client.get("/user")
    assert response2.status_code == 200
    data2 = response2.json()
    assert data2["message"] == "User page"
