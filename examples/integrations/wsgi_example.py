"""
WSGI integration example for LeWAF.

This example shows how to integrate LeWAF with any WSGI application
using a WSGI middleware wrapper.
"""

import json
from io import BytesIO
from pathlib import Path

from lewaf.engine import WAF

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


class LeWAFMiddleware:
    """
    WSGI middleware for LeWAF integration.

    This middleware wraps any WSGI application and processes
    requests/responses through LeWAF.
    """

    def __init__(self, app, waf_config=None):
        """
        Initialize middleware.

        Args:
            app: The WSGI application to wrap
            waf_config: WAF configuration dict
        """
        self.app = app
        self.waf = WAF(**(waf_config or WAF_CONFIG))

    def __call__(self, environ, start_response):
        """
        WSGI application interface.

        Args:
            environ: WSGI environment dict
            start_response: WSGI start_response callable

        Returns:
            Response iterable
        """
        # Create WAF transaction
        tx = self.waf.new_transaction()

        # Extract request information
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        query_string = environ.get("QUERY_STRING", "")
        uri = f"{path}?{query_string}" if query_string else path
        protocol = environ.get("SERVER_PROTOCOL", "HTTP/1.1")

        # Extract headers
        headers = {}
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").title()
                headers[header_name] = value

        # Also include Content-Type and Content-Length if present
        if "CONTENT_TYPE" in environ:
            headers["Content-Type"] = environ["CONTENT_TYPE"]
        if "CONTENT_LENGTH" in environ:
            headers["Content-Length"] = environ["CONTENT_LENGTH"]

        # Process request headers
        tx.process_request_headers(
            method=method,
            uri=uri,
            protocol=protocol,
            headers=headers,
        )

        # Check for interruption after headers
        if tx.interruption:
            return self._blocked_response(tx, start_response)

        # Process request body if present
        content_length = environ.get("CONTENT_LENGTH")
        if content_length and int(content_length) > 0:
            body = environ["wsgi.input"].read(int(content_length))

            # Replace wsgi.input with a new BytesIO so the app can still read it
            environ["wsgi.input"] = BytesIO(body)

            # Process through WAF
            tx.process_request_body(body)

            # Check for interruption after body
            if tx.interruption:
                return self._blocked_response(tx, start_response)

        # Capture response
        response_status = []
        response_headers = []

        def capturing_start_response(status, headers, exc_info=None):
            response_status.append(status)
            response_headers.extend(headers)
            return start_response(status, headers, exc_info)

        # Call wrapped application
        try:
            response = self.app(environ, capturing_start_response)
            response_body = b"".join(response)
        except Exception as e:
            # Handle application errors
            return self._error_response(str(e), start_response)

        # Process response headers
        status_code = int(response_status[0].split()[0]) if response_status else 500
        response_headers_dict = dict(response_headers)

        tx.process_response_headers(
            status=status_code,
            headers=response_headers_dict,
        )

        # Process response body
        if response_body:
            tx.process_response_body(response_body)

        # Check for interruption after response
        if tx.interruption:
            return self._blocked_response(tx, start_response)

        # Return response
        return [response_body]

    def _blocked_response(self, tx, start_response):
        """Generate a blocked response."""
        response_data = {
            "error": "Request blocked by WAF",
            "rule_id": tx.interruption.rule_id if tx.interruption else None,
            "message": tx.interruption.action if tx.interruption else "Unknown",
        }

        body = json.dumps(response_data).encode("utf-8")

        start_response(
            "403 Forbidden",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )

        return [body]

    def _error_response(self, error_message, start_response):
        """Generate an error response."""
        response_data = {
            "error": "Internal server error",
            "message": error_message,
        }

        body = json.dumps(response_data).encode("utf-8")

        start_response(
            "500 Internal Server Error",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )

        return [body]


# Example WSGI application
def simple_wsgi_app(environ, start_response):
    """
    Simple WSGI application for demonstration.

    This is a minimal WSGI app that handles a few routes.
    """
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/":
        body = b"Hello from WSGI with LeWAF protection!"
        start_response(
            "200 OK",
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    elif path == "/api/users" and method == "GET":
        response_data = {
            "users": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"},
            ]
        }
        body = json.dumps(response_data).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    elif path == "/health":
        response_data = {
            "status": "healthy",
            "service": "wsgi-lewaf",
        }
        body = json.dumps(response_data).encode("utf-8")
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]

    else:
        body = b"Not Found"
        start_response(
            "404 Not Found",
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


# Create protected WSGI application
application = LeWAFMiddleware(simple_wsgi_app, WAF_CONFIG)


if __name__ == "__main__":
    # Run with gunicorn or any WSGI server
    # Example: gunicorn wsgi_example:application
    from wsgiref.simple_server import make_server

    print("Starting WSGI server with LeWAF on http://localhost:8000")
    server = make_server("0.0.0.0", 8000, application)
    server.serve_forever()
