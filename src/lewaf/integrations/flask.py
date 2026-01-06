"""Flask WSGI middleware for LeWAF.

This module provides native WSGI middleware for Flask applications,
offering better performance than ASGI bridge approaches.

Example:
    from flask import Flask
    from lewaf import WAF
    from lewaf.integrations.flask import FlaskWAFMiddleware

    app = Flask(__name__)
    waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1,phase:1,deny"']})
    app.wsgi_app = FlaskWAFMiddleware(app.wsgi_app, waf)
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from io import BytesIO
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lewaf.integration import WAF

logger = logging.getLogger(__name__)

# Type aliases for WSGI
WSGIEnviron = dict[str, Any]
StartResponse = Callable[[str, list[tuple[str, str]]], Callable[[bytes], None]]
WSGIApp = Callable[[WSGIEnviron, StartResponse], Iterable[bytes]]


class FlaskWAFMiddleware:
    """WSGI middleware for Flask applications.

    This middleware wraps a WSGI application to provide WAF protection,
    inspecting requests according to configured rules.

    Public API (stable for 1.0):
        __init__(app, waf, ...) - Create middleware
        __call__(environ, start_response) - WSGI interface

    Example:
        from flask import Flask
        from lewaf import WAF
        from lewaf.integrations.flask import FlaskWAFMiddleware

        app = Flask(__name__)

        # Option 1: With pre-configured WAF
        waf = WAF({"rules": [...]})
        app.wsgi_app = FlaskWAFMiddleware(app.wsgi_app, waf)

        # Option 2: With inline rules
        app.wsgi_app = FlaskWAFMiddleware(
            app.wsgi_app,
            rules=['SecRule ARGS "@rx attack" "id:1,phase:1,deny"']
        )

        # Option 3: With config file
        app.wsgi_app = FlaskWAFMiddleware(
            app.wsgi_app,
            config_file="config/lewaf.yaml"
        )
    """

    def __init__(
        self,
        app: WSGIApp,
        waf: WAF | None = None,
        config_file: str | None = None,
        rules: list[str] | None = None,
        block_status: str = "403 Forbidden",
        block_body: bytes = b"Request blocked by WAF",
        block_content_type: str = "text/plain",
    ):
        """Initialize Flask WAF middleware.

        Args:
            app: WSGI application to wrap
            waf: Pre-configured WAF instance (takes precedence)
            config_file: Path to YAML/JSON configuration file
            rules: List of SecLang rule strings
            block_status: HTTP status for blocked requests
            block_body: Response body for blocked requests
            block_content_type: Content-Type for blocked responses
        """
        self.app = app
        self.block_status = block_status
        self.block_body = block_body
        self.block_content_type = block_content_type

        if waf is not None:
            self.waf = waf
        elif config_file:
            from pathlib import Path  # noqa: PLC0415

            from lewaf.config.loader import ConfigLoader  # noqa: PLC0415
            from lewaf.integration import WAF  # noqa: PLC0415

            loader = ConfigLoader()
            config = loader.load_from_file(Path(config_file))
            self.waf = WAF({"rules": config.rules, "rule_files": config.rule_files})
        elif rules:
            from lewaf.integration import WAF  # noqa: PLC0415

            self.waf = WAF({"rules": rules})
        else:
            from lewaf.integration import WAF  # noqa: PLC0415

            self.waf = WAF({"rules": []})

    def __call__(
        self, environ: WSGIEnviron, start_response: StartResponse
    ) -> Iterable[bytes]:
        """Process request through WAF.

        Args:
            environ: WSGI environment dictionary
            start_response: WSGI start_response callable

        Returns:
            Response iterable
        """
        tx = self.waf.new_transaction()

        try:
            # Extract request information
            method = environ.get("REQUEST_METHOD", "GET")
            path = environ.get("PATH_INFO", "/")
            query_string = environ.get("QUERY_STRING", "")

            # Build URI with query string
            uri = f"{path}?{query_string}" if query_string else path

            # Process URI and method
            tx.process_uri(uri, method)

            # Add request headers
            self._add_request_headers(tx, environ)

            # Process Phase 1 (request headers)
            interruption = tx.process_request_headers()
            if interruption:
                logger.warning(
                    "Request blocked in Phase 1 by rule %s", interruption["rule_id"]
                )
                return self._block_response(start_response, interruption)

            # Read and process request body (Phase 2)
            content_length = environ.get("CONTENT_LENGTH")
            if content_length:
                try:
                    length = int(content_length)
                    if length > 0:
                        body = environ["wsgi.input"].read(length)
                        # Reset input stream for downstream app
                        environ["wsgi.input"] = BytesIO(body)
                        content_type = environ.get("CONTENT_TYPE", "")
                        tx.add_request_body(body, content_type)
                except (ValueError, KeyError):
                    pass

            interruption = tx.process_request_body()
            if interruption:
                logger.warning(
                    "Request blocked in Phase 2 by rule %s", interruption["rule_id"]
                )
                return self._block_response(start_response, interruption)

            # Request passed WAF, continue to application
            return self.app(environ, start_response)

        except Exception as e:
            logger.error("Error in FlaskWAFMiddleware: %s", e)
            # Fail open - allow request on error
            return self.app(environ, start_response)

    def _add_request_headers(self, tx: Any, environ: WSGIEnviron) -> None:
        """Extract and add HTTP headers from WSGI environ.

        Args:
            tx: Transaction instance
            environ: WSGI environment dictionary
        """
        # Standard headers from environ
        for key, value in environ.items():
            if key.startswith("HTTP_"):
                # Convert HTTP_HEADER_NAME to header-name
                header_name = key[5:].replace("_", "-").lower()
                tx.variables.request_headers.add(header_name, value)

        # Special headers not prefixed with HTTP_
        if "CONTENT_TYPE" in environ:
            tx.variables.request_headers.add("content-type", environ["CONTENT_TYPE"])
        if "CONTENT_LENGTH" in environ:
            tx.variables.request_headers.add(
                "content-length", environ["CONTENT_LENGTH"]
            )

        # Set connection metadata
        tx.variables.remote_addr.set(environ.get("REMOTE_ADDR", ""))
        tx.variables.remote_port.set(environ.get("REMOTE_PORT", "0"))
        tx.variables.server_name.set(environ.get("SERVER_NAME", ""))
        tx.variables.server_port.set(environ.get("SERVER_PORT", "80"))

    def _block_response(
        self, start_response: StartResponse, interruption: dict[str, Any]
    ) -> Iterable[bytes]:
        """Generate blocked request response.

        Args:
            start_response: WSGI start_response callable
            interruption: Interruption dictionary from WAF

        Returns:
            Response body iterable
        """
        # Check for redirect
        redirect_url = interruption.get("redirect_url")
        if redirect_url:
            headers = [
                ("Location", redirect_url),
                ("Content-Type", "text/plain"),
                ("Content-Length", "0"),
            ]
            start_response("302 Found", headers)
            return [b""]

        # Standard block response
        headers = [
            ("Content-Type", self.block_content_type),
            ("Content-Length", str(len(self.block_body))),
        ]
        start_response(self.block_status, headers)
        return [self.block_body]


def create_flask_waf(
    app: Any,
    config_file: str | None = None,
    rules: list[str] | None = None,
    **middleware_kwargs: Any,
) -> Any:
    """Convenience function to add WAF protection to a Flask app.

    Args:
        app: Flask application instance
        config_file: Path to configuration file
        rules: List of SecLang rule strings
        **middleware_kwargs: Additional middleware arguments

    Returns:
        Flask app with WAF middleware applied

    Example:
        from flask import Flask
        from lewaf.integrations.flask import create_flask_waf

        app = Flask(__name__)
        app = create_flask_waf(app, rules=[...])
    """
    app.wsgi_app = FlaskWAFMiddleware(
        app.wsgi_app,
        config_file=config_file,
        rules=rules,
        **middleware_kwargs,
    )
    return app
