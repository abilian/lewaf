"""
Flask integration example for LeWAF.

This example shows how to integrate LeWAF with Flask using before_request
and after_request hooks.
"""

from __future__ import annotations

from flask import Flask, g, jsonify, request

from lewaf.integration import WAF

# Flask application
app = Flask(__name__)

# WAF Configuration
WAF_CONFIG = {
    "rules": [
        'SecRule ARGS:admin "@rx ^true$" "id:9001,phase:1,deny,msg:\'Admin access forbidden\'"',
        'SecRule ARGS "@rx <script" "id:9002,phase:2,deny,msg:\'XSS Attack\'"',
    ],
    "rule_files": [],
}

# Initialize WAF
waf = WAF(WAF_CONFIG)


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

    # Set URI and method
    tx.process_uri(request.full_path, request.method)

    # Add request headers
    for key, value in request.headers:
        tx.variables.request_headers.add(key.lower(), value)

    # Process Phase 1 (request headers)
    tx.process_request_headers()

    # Check for interruption after headers
    if tx.interruption:
        return _blocked_response(tx)

    # Process request body if present
    if request.data:
        content_type = request.headers.get("Content-Type", "")
        tx.add_request_body(request.data, content_type)
        tx.process_request_body()

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

    # Add response status
    tx.add_response_status(response.status_code)

    # Add response headers
    for key, value in response.headers:
        tx.add_response_headers({key.lower(): value})

    # Process Phase 3 (response headers)
    tx.process_response_headers()

    # Process response body
    if response.data:
        tx.add_response_body(response.data)
        tx.process_response_body()

    # Check for interruption after response
    if tx.interruption:
        return _blocked_response(tx)

    return response


def _blocked_response(tx):
    """Generate a blocked response."""
    response = jsonify({
        "error": "Request blocked by WAF",
        "rule_id": tx.interruption.get("rule_id") if tx.interruption else None,
        "message": tx.interruption.get("action", "Unknown")
        if tx.interruption
        else "Unknown",
    })
    response.status_code = 403
    return response


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
