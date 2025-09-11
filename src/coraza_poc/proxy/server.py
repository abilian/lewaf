"""Coraza reverse proxy server using Starlette."""

from __future__ import annotations

import logging
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from coraza_poc.integrations.starlette import CorazaMiddleware

from .client import ProxyClient

logger = logging.getLogger(__name__)


class CorazaReverseProxy:
    """Coraza-enabled reverse proxy server."""

    def __init__(
        self,
        upstream_url: str,
        waf_config: dict[str, Any] | None = None,
        waf_rules: list[str] | None = None,
        proxy_config: dict[str, Any] | None = None,
    ):
        """Initialize the reverse proxy.

        Args:
            upstream_url: URL of the upstream server
            waf_config: WAF configuration dictionary
            waf_rules: List of WAF rules
            proxy_config: Proxy client configuration
        """
        self.upstream_url = upstream_url

        # Initialize proxy client
        proxy_config = proxy_config or {}
        self.proxy_client = ProxyClient(upstream_url, **proxy_config)

        # WAF configuration
        self.waf_config = waf_config
        self.waf_rules = waf_rules or []

    async def proxy_handler(self, request: Request) -> Response:
        """Handle proxied requests."""
        try:
            # The WAF middleware will have already processed this request
            # If we get here, the request passed WAF checks
            return await self.proxy_client.proxy_request(request)
        except Exception as e:
            logger.error(f"Error in proxy handler: {e}")
            return JSONResponse(
                status_code=500, content={"error": "Internal proxy error"}
            )

    async def health_check(self, request: Request) -> Response:
        """Health check endpoint."""
        return JSONResponse(
            content={
                "status": "healthy",
                "upstream": self.upstream_url,
                "proxy": "coraza-py",
            }
        )

    def create_app(self) -> Starlette:
        """Create the Starlette application with WAF protection."""

        # Define routes
        routes = [
            Route("/health", self.health_check, methods=["GET"]),
            Route(
                "/{path:path}",
                self.proxy_handler,
                methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
            ),
        ]

        # Create base app
        app = Starlette(routes=routes)

        # Add Coraza WAF middleware
        app.add_middleware(
            CorazaMiddleware,
            rules=self.waf_rules,
            config_file=self.waf_config.get("config_file") if self.waf_config else None,
            block_response_status=403,
        )

        return app

    async def shutdown(self):
        """Cleanup resources."""
        await self.proxy_client.close()


def create_proxy_app(
    upstream_url: str,
    waf_rules: list[str] | None = None,
    waf_config_file: str | None = None,
    **proxy_kwargs: Any,
) -> Starlette:
    """Create a Coraza reverse proxy application.

    Args:
        upstream_url: URL of the upstream server to proxy to
        waf_rules: List of WAF rules to apply
        waf_config_file: Path to WAF configuration file
        **proxy_kwargs: Additional proxy configuration

    Returns:
        Configured Starlette application
    """
    # Default WAF rules if none provided
    if not waf_rules and not waf_config_file:
        waf_rules = [
            # Basic SQL injection detection
            'SecRule ARGS "@rx (union|select|insert|update|delete|drop)" "id:2001,phase:2,deny,log,msg:\'SQL Injection Attack\'"',
            # XSS detection
            'SecRule ARGS "@rx (<script|javascript:|vbscript:)" "id:2002,phase:2,deny,log,msg:\'XSS Attack\'"',
            # User-Agent filtering
            'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|spider|crawler|scanner)" "id:2004,phase:1,deny,log,msg:\'Bot detected\'"',
            # Path traversal
            r'SecRule ARGS "@rx (\.\.\/|\.\.%2f)" "id:2005,phase:2,deny,log,msg:\'Path traversal attack\'"',
            # Command injection
            'SecRule ARGS "@rx ([;&|`])" "id:2006,phase:2,deny,log,msg:\'Command injection attempt\'"',
        ]

    waf_config = {}
    if waf_config_file:
        waf_config["config_file"] = waf_config_file

    # Create proxy instance
    proxy = CorazaReverseProxy(
        upstream_url=upstream_url,
        waf_config=waf_config,
        waf_rules=waf_rules,
        proxy_config=proxy_kwargs,
    )

    app = proxy.create_app()

    # Store proxy instance for cleanup
    app.state.proxy = proxy

    @app.on_event("shutdown")
    async def shutdown_event():
        await proxy.shutdown()

    return app
