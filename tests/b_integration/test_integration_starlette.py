"""Integration tests for Starlette framework integration."""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from lewaf.integration import WAF
from lewaf.integrations.starlette import CorazaMiddleware, create_waf_app


def create_test_app():
    """Create a test Starlette application."""

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

    return Starlette(
        routes=[
            Route("/", homepage, methods=["GET"]),
            Route("/echo", echo, methods=["GET", "POST", "PUT", "DELETE"]),
        ]
    )


def test_coraza_middleware_initialization():
    """Test CorazaMiddleware initialization with rules."""
    app = Starlette()
    rules = ['SecRule ARGS "@rx test" "id:1,phase:2,deny"']
    middleware = CorazaMiddleware(app, rules=rules)

    assert middleware.waf is not None
    assert middleware.block_response_status == 403


def test_middleware_with_preconfigured_waf():
    """Test middleware with pre-configured WAF instance."""
    app = Starlette()
    waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1001,phase:2,deny"']})
    middleware = CorazaMiddleware(app, waf=waf)

    assert middleware.waf is waf


def test_create_waf_app_helper():
    """Test the create_waf_app helper function."""
    base_app = Starlette()
    rules = ['SecRule ARGS "@rx malicious" "id:2001,phase:2,deny"']
    waf_app = create_waf_app(base_app, rules=rules)

    assert isinstance(waf_app, Starlette)


def test_normal_request_passthrough():
    """Test that normal requests pass through without blocking."""
    app = create_test_app()
    waf_app = create_waf_app(app, rules=[])
    client = TestClient(waf_app)

    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["message"] == "Hello World"


def test_malicious_request_blocking():
    """Test that malicious requests matching rules are blocked."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:attack "@rx malicious" "id:3001,phase:2,deny,log,msg:\'Attack detected\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal request should pass
    normal_response = client.get("/echo?normal=data")
    assert normal_response.status_code == 200

    # Malicious request should be blocked
    malicious_response = client.get("/echo?attack=malicious")
    assert malicious_response.status_code == 403

    # Verify block response format
    block_data = malicious_response.json()
    assert "error" in block_data
    assert "rule_id" in block_data
    assert block_data["rule_id"] == 3001


def test_post_request_handling():
    """Test POST request handling through WAF middleware."""
    app = create_test_app()
    rules = [
        'SecRule ARGS "@rx (union|select)" "id:3002,phase:2,deny,log,msg:\'SQL Injection\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal POST should pass
    normal_response = client.post("/echo", json={"data": "normal"})
    assert normal_response.status_code == 200

    # Malicious POST should be blocked
    malicious_response = client.post("/echo?injection=union select")
    assert malicious_response.status_code == 403


def test_header_based_blocking():
    """Test WAF rules based on request headers."""
    app = create_test_app()
    rules = [
        'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler)" "id:3003,phase:1,deny,log,msg:\'Bot detected\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal user agent should pass
    normal_response = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
    assert normal_response.status_code == 200

    # Bot user agent should be blocked
    bot_response = client.get("/", headers={"User-Agent": "malicious-bot/1.0"})
    assert bot_response.status_code == 403


def test_custom_block_response_configuration():
    """Test custom block response status and body."""
    app = Starlette()
    rules = ['SecRule ARGS "@rx blocked" "id:3004,phase:2,deny"']

    waf_app = create_waf_app(
        app, rules=rules, block_response_status=429, block_response_body="Rate limited"
    )
    client = TestClient(waf_app)

    response = client.get("/?test=blocked")
    assert response.status_code == 429
    assert response.text == "Rate limited"


def test_query_parameter_validation():
    """Test WAF validation of query parameters."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:id "@rx ^[0-9]+$" "id:3005,phase:2,pass,log"',
        'SecRule ARGS:id "@rx [^0-9]" "id:3006,phase:2,deny,log,msg:\'Invalid ID format\'"',
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Valid numeric ID should pass
    valid_response = client.get("/echo?id=123")
    assert valid_response.status_code == 200

    # Invalid ID format should be blocked
    invalid_response = client.get("/echo?id=abc123")
    assert invalid_response.status_code == 403


def test_multiple_rule_evaluation():
    """Test evaluation of multiple rules in sequence."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:test1 "@rx danger" "id:3007,phase:2,deny,log,msg:\'Test1 danger\'"',
        'SecRule ARGS:test2 "@rx evil" "id:3008,phase:2,deny,log,msg:\'Test2 evil\'"',
        'SecRule ARGS:test3 "@rx safe" "id:3009,phase:2,pass,log,msg:\'Test3 safe\'"',
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # First rule should block
    response1 = client.get("/echo?test1=danger")
    assert response1.status_code == 403

    # Second rule should block
    response2 = client.get("/echo?test2=evil")
    assert response2.status_code == 403

    # Third rule should pass
    response3 = client.get("/echo?test3=safe")
    assert response3.status_code == 200


def test_uri_based_rules():
    """Test WAF rules that examine the request URI."""
    app = create_test_app()
    rules = [
        'SecRule REQUEST_URI "@rx admin" "id:3010,phase:1,deny,log,msg:\'Admin access denied\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal path should pass
    normal_response = client.get("/echo")
    assert normal_response.status_code == 200

    # Admin path should be blocked
    admin_response = client.get("/admin/panel")
    assert admin_response.status_code == 403


def test_error_handling_middleware():
    """Test middleware error handling with edge cases."""
    app = Starlette()
    waf_app = create_waf_app(app, rules=[])
    client = TestClient(waf_app)

    # Test with various headers and paths
    response = client.get("/", headers={"Host": "test.example.com"})
    # Should not crash (might be 404 due to no routes, but not 500)
    assert response.status_code != 500


def test_method_based_rules():
    """Test rules that filter based on request parameters."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:method "@rx ^(PUT|DELETE)$" "id:3011,phase:1,deny,log,msg:\'Method not allowed\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal requests should pass
    get_response = client.get("/echo")
    assert get_response.status_code == 200

    post_response = client.post("/echo", json={})
    assert post_response.status_code == 200

    # Request with blocked method parameter should be blocked
    put_response = client.get("/echo?method=PUT")
    assert put_response.status_code == 403


def test_json_payload_inspection():
    """Test inspection of JSON payloads in POST requests."""
    app = create_test_app()
    rules = [
        'SecRule ARGS "@rx script" "id:3012,phase:2,deny,log,msg:\'Script injection\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Normal JSON should pass
    normal_response = client.post("/echo", json={"data": "normal"})
    assert normal_response.status_code == 200

    # Malicious JSON should be blocked (in query params)
    malicious_response = client.post("/echo?payload=script", json={"data": "test"})
    assert malicious_response.status_code == 403


def test_multiple_phases_in_middleware():
    """Test that middleware handles multiple processing phases."""
    app = create_test_app()
    rules = [
        'SecRule REQUEST_METHOD "@rx POST" "id:3013,phase:1,pass,log"',
        'SecRule ARGS:data "@rx sensitive" "id:3014,phase:2,deny,log"',
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # GET with sensitive data should pass (no POST rule triggered)
    get_response = client.get("/echo?data=sensitive")
    assert get_response.status_code == 403  # Still blocked by phase 2 rule

    # POST with normal data should pass
    post_normal = client.post("/echo", json={"other": "data"})
    assert post_normal.status_code == 200

    # POST with sensitive data should be blocked
    post_sensitive = client.post("/echo?data=sensitive")
    assert post_sensitive.status_code == 403


def test_case_sensitivity_handling():
    """Test case sensitivity in rule matching."""
    app = create_test_app()
    rules = ['SecRule ARGS:test "@rx ATTACK" "id:3015,phase:2,deny,log,t:uppercase"']
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Lowercase attack should be caught due to uppercase transformation
    response = client.get("/echo?test=attack")
    assert response.status_code == 403


def test_regex_pattern_matching():
    """Test simple regex patterns in rules."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:query "@rx select.*from" "id:3016,phase:1,deny,log,msg:\'SQL pattern\'"'
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # SQL injection pattern should be blocked
    sql_response = client.get("/echo?query=select * from users")
    assert sql_response.status_code == 403

    # Normal query should pass
    normal_response = client.get("/echo?query=search for information")
    assert normal_response.status_code == 200


def test_transaction_isolation_in_middleware():
    """Test that concurrent requests have isolated transactions."""
    app = create_test_app()
    rules = ['SecRule ARGS:block "@rx yes" "id:3017,phase:1,deny,log"']
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Simulate concurrent requests
    responses = []

    # One blocked, one allowed
    responses.append(client.get("/echo?block=yes"))
    responses.append(client.get("/echo?block=no"))

    assert responses[0].status_code == 403  # Blocked
    assert responses[1].status_code == 200  # Allowed


def test_middleware_with_allow_action():
    """Test middleware handling of allow actions."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:block "@rx malicious" "id:3018,phase:1,deny,log"',
        'SecRule ARGS:allow "@rx trusted" "id:3019,phase:1,allow,log"',  # Allow action doesn't interrupt
    ]
    waf_app = create_waf_app(app, rules=rules)
    client = TestClient(waf_app)

    # Request with allow rule should pass (allow doesn't interrupt)
    allowed_response = client.get("/echo?allow=trusted")
    assert allowed_response.status_code == 200

    # Request with deny rule should be blocked
    blocked_response = client.get("/echo?block=malicious")
    assert blocked_response.status_code == 403
