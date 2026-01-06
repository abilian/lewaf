"""Integration tests for Flask framework integration."""

from __future__ import annotations

import pytest

from lewaf.integration import WAF
from lewaf.integrations.flask import FlaskWAFMiddleware, create_flask_waf

# Skip all tests if Flask is not installed
flask = pytest.importorskip("flask")
from flask import Flask, jsonify, request


def create_test_app() -> Flask:
    """Create a test Flask application."""
    app = Flask(__name__)

    @app.route("/")
    def homepage():
        return jsonify({"message": "Hello World"})

    @app.route("/echo", methods=["GET", "POST", "PUT", "DELETE"])
    def echo():
        return jsonify({
            "method": request.method,
            "path": request.path,
            "query": dict(request.args),
            "headers": dict(request.headers),
        })

    @app.route("/api/data", methods=["POST"])
    def api_data():
        data = request.get_json() or {}
        return jsonify({"received": data})

    return app


def test_flask_middleware_initialization():
    """Test FlaskWAFMiddleware initialization with rules."""
    app = create_test_app()
    rules = ['SecRule ARGS "@rx test" "id:1,phase:2,deny"']
    app.wsgi_app = FlaskWAFMiddleware(app.wsgi_app, rules=rules)

    assert app.wsgi_app.waf is not None
    assert app.wsgi_app.block_status == "403 Forbidden"


def test_middleware_with_preconfigured_waf():
    """Test middleware with pre-configured WAF instance."""
    app = create_test_app()
    waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1001,phase:2,deny"']})
    app.wsgi_app = FlaskWAFMiddleware(app.wsgi_app, waf=waf)

    assert app.wsgi_app.waf is waf


def test_create_flask_waf_helper():
    """Test the create_flask_waf helper function."""
    app = create_test_app()
    rules = ['SecRule ARGS "@rx malicious" "id:2001,phase:2,deny"']
    waf_app = create_flask_waf(app, rules=rules)

    assert isinstance(waf_app, Flask)
    assert isinstance(waf_app.wsgi_app, FlaskWAFMiddleware)


def test_normal_request_passthrough():
    """Test that normal requests pass through without blocking."""
    app = create_test_app()
    create_flask_waf(app, rules=[])
    client = app.test_client()

    response = client.get("/")

    assert response.status_code == 200
    assert response.json["message"] == "Hello World"


def test_malicious_request_blocking():
    """Test that malicious requests matching rules are blocked."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:attack "@rx malicious" "id:3001,phase:2,deny,log,msg:\'Attack detected\'"'
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal request should pass
    normal_response = client.get("/echo?normal=data")
    assert normal_response.status_code == 200

    # Malicious request should be blocked
    malicious_response = client.get("/echo?attack=malicious")
    assert malicious_response.status_code == 403


def test_post_request_handling():
    """Test POST request handling through WAF middleware."""
    app = create_test_app()
    rules = [
        'SecRule ARGS "@rx (union|select)" "id:3002,phase:2,deny,log,msg:\'SQL Injection\'"'
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal POST should pass
    normal_response = client.post("/api/data", json={"data": "normal"})
    assert normal_response.status_code == 200

    # Malicious query param should be blocked
    malicious_response = client.post("/echo?injection=union select")
    assert malicious_response.status_code == 403


def test_header_based_blocking():
    """Test WAF rules based on request headers."""
    app = create_test_app()
    rules = [
        'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler)" "id:3003,phase:1,deny,log,msg:\'Bot detected\'"'
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal user agent should pass
    normal_response = client.get("/", headers={"User-Agent": "Mozilla/5.0"})
    assert normal_response.status_code == 200

    # Bot user agent should be blocked
    bot_response = client.get("/", headers={"User-Agent": "malicious-bot/1.0"})
    assert bot_response.status_code == 403


def test_custom_block_response_configuration():
    """Test custom block response status and body."""
    app = create_test_app()
    rules = ['SecRule ARGS "@rx blocked" "id:3004,phase:2,deny"']

    app.wsgi_app = FlaskWAFMiddleware(
        app.wsgi_app,
        rules=rules,
        block_status="429 Too Many Requests",
        block_body=b"Rate limited",
    )
    client = app.test_client()

    response = client.get("/?test=blocked")
    assert response.status_code == 429
    assert response.data == b"Rate limited"


def test_query_parameter_validation():
    """Test WAF validation of query parameters."""
    app = create_test_app()
    rules = [
        'SecRule ARGS:id "@rx [^0-9]" "id:3006,phase:2,deny,log,msg:\'Invalid ID format\'"',
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

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
    create_flask_waf(app, rules=rules)
    client = app.test_client()

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
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal path should pass
    normal_response = client.get("/echo")
    assert normal_response.status_code == 200

    # Admin path should be blocked
    admin_response = client.get("/admin/panel")
    assert admin_response.status_code == 403


def test_request_body_inspection():
    """Test inspection of request body content."""
    app = create_test_app()
    rules = [
        'SecRule REQUEST_BODY "@rx malicious" "id:3020,phase:2,deny,log,msg:\'Malicious body\'"'
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal body should pass
    normal_response = client.post(
        "/echo",
        data="normal content",
        content_type="text/plain",
    )
    assert normal_response.status_code == 200

    # Malicious body should be blocked
    malicious_response = client.post(
        "/echo",
        data="this is malicious content",
        content_type="text/plain",
    )
    assert malicious_response.status_code == 403


def test_json_body_inspection():
    """Test inspection of JSON body content."""
    app = create_test_app()
    rules = [
        'SecRule ARGS "@rx attack" "id:3021,phase:2,deny,log,msg:\'Attack in JSON\'"'
    ]
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Normal JSON should pass
    normal_response = client.post(
        "/api/data",
        json={"data": "normal"},
    )
    assert normal_response.status_code == 200


def test_case_sensitivity_handling():
    """Test case sensitivity in rule matching."""
    app = create_test_app()
    rules = ['SecRule ARGS:test "@rx ATTACK" "id:3015,phase:2,deny,log,t:uppercase"']
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # Lowercase attack should be caught due to uppercase transformation
    response = client.get("/echo?test=attack")
    assert response.status_code == 403


def test_transaction_isolation():
    """Test that concurrent requests have isolated transactions."""
    app = create_test_app()
    rules = ['SecRule ARGS:block "@rx yes" "id:3017,phase:1,deny,log"']
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # One blocked, one allowed
    blocked_response = client.get("/echo?block=yes")
    allowed_response = client.get("/echo?block=no")

    assert blocked_response.status_code == 403
    assert allowed_response.status_code == 200


def test_error_handling():
    """Test middleware error handling."""
    app = create_test_app()
    create_flask_waf(app, rules=[])
    client = app.test_client()

    # Should not crash with unusual inputs
    response = client.get("/", headers={"Host": "test.example.com"})
    assert response.status_code != 500


def test_request_body_reset():
    """Test that request body is available to the application after WAF inspection."""
    app = create_test_app()
    rules = []  # No blocking rules
    create_flask_waf(app, rules=rules)
    client = app.test_client()

    # The JSON should be readable by the app
    response = client.post("/api/data", json={"test": "data"})
    assert response.status_code == 200
    assert response.json["received"] == {"test": "data"}
