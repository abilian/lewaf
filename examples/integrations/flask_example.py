"""
Flask integration example for LeWAF.

This example shows how to integrate LeWAF with Flask using before_request
and after_request hooks.
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, g, jsonify, request

from lewaf.engine import WAF

# Flask application
app = Flask(__name__)

# WAF Configuration
WAF_CONFIG = {
    "engine": "DetectionOnly",
    "rule_files": [
        str(Path(__file__).parent.parent.parent / "coraza.conf"),
    ],
    "request_body_limit": 13107200,
    "custom_rules": [
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
    ],
}

# Initialize WAF
waf = WAF(**WAF_CONFIG)


@app.before_request
def lewaf_before_request():
    """
    Process request through LeWAF before handling.

    This hook runs before every request and creates a WAF transaction
    stored in Flask's g object.
    """
    # Create WAF transaction
    tx = waf.new_transaction()
    g.lewaf_tx = tx

    # Process request headers
    headers = dict(request.headers)
    tx.process_request_headers(
        method=request.method,
        uri=request.full_path,
        protocol=request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        headers=headers,
    )

    # Check for interruption after headers
    if tx.interruption:
        return _blocked_response(tx)

    # Process request body if present
    if request.data:
        tx.process_request_body(request.data)

        # Check for interruption after body
        if tx.interruption:
            return _blocked_response(tx)

    # Continue to view
    return None


@app.after_request
def lewaf_after_request(response):
    """
    Process response through LeWAF after handling.

    This hook runs after every request and processes the response
    through the WAF transaction.
    """
    # Get WAF transaction
    tx = g.get("lewaf_tx")
    if not tx:
        return response

    # Process response headers
    response_headers = dict(response.headers)
    tx.process_response_headers(
        status=response.status_code,
        headers=response_headers,
    )

    # Process response body
    if response.data:
        tx.process_response_body(response.data)

    # Check for interruption after response
    if tx.interruption:
        return _blocked_response(tx)

    return response


def _blocked_response(tx):
    """Generate a blocked response."""
    return jsonify({
        "error": "Request blocked by WAF",
        "rule_id": tx.interruption.rule_id if tx.interruption else None,
        "message": tx.interruption.action if tx.interruption else "Unknown",
    }), 403


# Routes
@app.route("/")
def home():
    """Home page."""
    return "Hello from Flask with LeWAF protection!"


@app.route("/api/users")
def api_users():
    """Example API endpoint."""
    return jsonify({
        "users": [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"},
        ]
    })


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "flask-lewaf",
    })


@app.route("/api/search")
def search():
    """Search endpoint (to test query parameters)."""
    query = request.args.get("q", "")
    return jsonify({
        "query": query,
        "results": ["result1", "result2"],
    })


if __name__ == "__main__":
    # Run development server
    app.run(host="0.0.0.0", port=8000, debug=True)
