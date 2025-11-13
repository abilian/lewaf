"""ASGI middleware for LeWAF integration.

This middleware integrates LeWAF with ASGI applications (Starlette, FastAPI, etc.)
providing request/response filtering and WAF protection.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from lewaf.config.loader import load_config
from lewaf.config.manager import ConfigManager
from lewaf.integration import WAF
from lewaf.transaction import Transaction

logger = logging.getLogger(__name__)

ASGIApp = Callable[[dict, Callable, Callable], Awaitable[None]]


class ASGIMiddleware:
    """ASGI middleware for LeWAF integration.

    This middleware wraps ASGI applications to provide WAF protection,
    inspecting requests and responses according to configured rules.

    Example:
        from starlette.applications import Starlette
        from lewaf.integration.asgi import ASGIMiddleware

        app = Starlette()
        app = ASGIMiddleware(app, config_file="config/lewaf.yaml")
    """

    def __init__(
        self,
        app: ASGIApp,
        config_file: str | None = None,
        config_dict: dict[str, Any] | None = None,
        waf_instance: WAF | None = None,
        enable_hot_reload: bool = False,
    ):
        """Initialize ASGI middleware.

        Args:
            app: ASGI application to wrap
            config_file: Path to configuration file (YAML/JSON)
            config_dict: Configuration dictionary (alternative to file)
            waf_instance: Pre-configured WAF instance (overrides config)
            enable_hot_reload: Enable configuration hot-reload
        """
        self.app = app
        self.enable_hot_reload = enable_hot_reload

        # Initialize WAF
        if waf_instance:
            self.waf = waf_instance
            self.config_manager = None
        elif config_file:
            # Use config manager for hot-reload support
            self.config_manager = ConfigManager(
                config_file=config_file,
                auto_reload_on_signal=enable_hot_reload,
            )
            config = self.config_manager.get_config()
            self.waf = self._create_waf_from_config(config)

            # Register reload callback if hot-reload enabled
            if enable_hot_reload:
                self.config_manager.register_reload_callback(self._on_config_reload)
        elif config_dict:
            # Simple config dict (no hot-reload)
            self.waf = WAF(config_dict)
            self.config_manager = None
        else:
            # Load default config
            default_config = load_config()
            self.waf = self._create_waf_from_config(default_config)
            self.config_manager = None

        logger.info("LeWAF ASGI middleware initialized")

    def _create_waf_from_config(self, config: Any) -> WAF:
        """Create WAF instance from configuration object.

        Args:
            config: WAFConfig instance

        Returns:
            Configured WAF instance
        """
        # Convert WAFConfig to legacy dict format for WAF class
        config_dict = {
            "rules": config.rules,
        }
        return WAF(config_dict)

    def _on_config_reload(self, old_config: Any, new_config: Any) -> None:
        """Handle configuration reload.

        Args:
            old_config: Previous configuration
            new_config: New configuration
        """
        logger.info("Reloading WAF configuration")
        try:
            self.waf = self._create_waf_from_config(new_config)
            logger.info("WAF configuration reloaded successfully")
        except Exception as e:
            logger.error("Failed to reload WAF configuration: %s", e)
            # Keep old WAF instance on failure

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        """ASGI middleware entry point.

        Args:
            scope: ASGI scope dict
            receive: Receive channel
            send: Send channel
        """
        # Only process HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Create WAF transaction
        tx = self.waf.new_transaction()

        try:
            # Process request and get replay receive
            replay_receive = await self._process_request(tx, scope, receive)

            # Check if request was blocked
            if tx.interruption:
                # Send blocking response
                await self._send_block_response(send, tx)
                return

            # Wrap send to intercept response
            async def wrapped_send(message: dict[str, Any]) -> None:
                if message["type"] == "http.response.start":
                    # Process response headers
                    await self._process_response(tx, message)

                    # Check if response was blocked
                    if tx.interruption:
                        # Send blocking response instead
                        await self._send_block_response(send, tx)
                        return

                await send(message)

            # Call wrapped application with replay receive
            await self.app(scope, replay_receive, wrapped_send)

        except Exception:
            logger.exception("WAF middleware error")
            # Continue with original app on WAF errors
            await self.app(scope, receive, send)

    async def _process_request(
        self,
        tx: Transaction,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
    ) -> Callable[[], Awaitable[dict[str, Any]]]:
        """Process incoming request through WAF.

        Args:
            tx: WAF transaction
            scope: ASGI scope
            receive: Receive channel

        Returns:
            Replay receive callable for wrapped app
        """
        # Get request details
        method = scope.get("method", "GET")
        path = scope.get("path", "/")
        query_string = scope.get("query_string", b"").decode("latin-1")

        # Build full URI with query string
        if query_string:
            uri = f"{path}?{query_string}"
        else:
            uri = path

        # Set request URI and method
        tx.process_uri(uri, method)

        # Set headers
        for name, value in scope.get("headers", []):
            name_str = name.decode("latin-1")
            value_str = value.decode("latin-1")
            tx.variables.request_headers.add(name_str.lower(), value_str)

        # Process Phase 1 (request headers)
        result = tx.process_request_headers()
        if result:
            # Request was interrupted
            # Return a receive that signals no body
            async def empty_receive() -> dict[str, Any]:
                return {"type": "http.request", "body": b"", "more_body": False}

            return empty_receive

        # Buffer body messages for replay
        body_messages: list[dict[str, Any]] = []

        # Process body if present
        if method in ("POST", "PUT", "PATCH"):
            body_parts = []

            while True:
                message = await receive()
                body_messages.append(message)

                if message["type"] == "http.request":
                    body = message.get("body", b"")
                    if body:
                        body_parts.append(body)

                    if not message.get("more_body", False):
                        break

            if body_parts:
                full_body = b"".join(body_parts)

                # Get content type
                content_type_values = tx.variables.request_headers.get("content-type")
                content_type = content_type_values[0] if content_type_values else ""

                # Store body using set_content (sets both raw bytes and decoded string)
                tx.variables.request_body.set_content(full_body, content_type)

                # Process Phase 2 (request body)
                result = tx.process_request_body()
                if result:
                    # Request was interrupted
                    # Return a receive that signals no body
                    async def empty_receive() -> dict[str, Any]:
                        return {"type": "http.request", "body": b"", "more_body": False}

                    return empty_receive

        # Create replay receive callable
        body_iter = iter(body_messages)

        async def replay_receive() -> dict[str, Any]:
            try:
                return next(body_iter)
            except StopIteration:
                # If no messages were buffered, return empty body
                return {"type": "http.request", "body": b"", "more_body": False}

        return replay_receive

    async def _process_response(
        self,
        tx: Transaction,
        message: dict[str, Any],
    ) -> None:
        """Process response through WAF.

        Args:
            tx: WAF transaction
            message: ASGI response message
        """
        # Extract status and headers
        status = message.get("status", 200)

        # Set response status
        tx.variables.response_status.set(status)

        # Set response headers
        for name, value in message.get("headers", []):
            name_str = name.decode("latin-1")
            value_str = value.decode("latin-1")
            tx.variables.response_headers.add(name_str.lower(), value_str)

        # Process Phase 3 (response headers)
        result = tx.process_response_headers()
        if result:
            # Response was interrupted
            return

    async def _send_block_response(
        self,
        send: Callable[[dict[str, Any]], Awaitable[None]],
        tx: Transaction,
    ) -> None:
        """Send WAF blocking response.

        Args:
            send: Send channel
            tx: WAF transaction with block details
        """
        # Extract block message from transaction
        block_msg = getattr(tx, "block_message", "Request blocked by WAF")
        rule_id = getattr(tx, "blocked_rule_id", "unknown")

        # Send response headers
        await send({
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"text/plain"),
                (b"x-waf-blocked", b"true"),
                (b"x-waf-rule-id", str(rule_id).encode("latin-1")),
            ],
        })

        # Send response body
        body = f"403 Forbidden\n\n{block_msg}\n".encode("utf-8")
        await send({
            "type": "http.response.body",
            "body": body,
        })


class ASGIMiddlewareFactory:
    """Factory for creating ASGI middleware with shared WAF instance.

    Useful for creating multiple middleware instances that share the
    same WAF configuration and state.

    Example:
        factory = ASGIMiddlewareFactory(config_file="config/lewaf.yaml")
        app1 = factory.wrap(app1)
        app2 = factory.wrap(app2)
    """

    def __init__(
        self,
        config_file: str | None = None,
        config_dict: dict[str, Any] | None = None,
        enable_hot_reload: bool = False,
    ):
        """Initialize middleware factory.

        Args:
            config_file: Path to configuration file
            config_dict: Configuration dictionary
            enable_hot_reload: Enable hot-reload
        """
        # Create shared WAF instance
        if config_file:
            self.config_manager = ConfigManager(
                config_file=config_file,
                auto_reload_on_signal=enable_hot_reload,
            )
            config = self.config_manager.get_config()
            self.waf = self._create_waf_from_config(config)

            if enable_hot_reload:
                self.config_manager.register_reload_callback(self._on_config_reload)
        elif config_dict:
            self.waf = WAF(config_dict)
            self.config_manager = None
        else:
            default_config = load_config()
            self.waf = self._create_waf_from_config(default_config)
            self.config_manager = None

    def _create_waf_from_config(self, config: Any) -> WAF:
        """Create WAF instance from configuration."""
        return WAF({"rules": config.rules})

    def _on_config_reload(self, old_config: Any, new_config: Any) -> None:
        """Handle configuration reload."""
        logger.info("Reloading shared WAF configuration")
        try:
            self.waf = self._create_waf_from_config(new_config)
            logger.info("Shared WAF configuration reloaded")
        except Exception as e:
            logger.error("Failed to reload shared WAF: %s", e)

    def wrap(self, app: ASGIApp) -> ASGIMiddleware:
        """Wrap an ASGI application with middleware.

        Args:
            app: ASGI application to wrap

        Returns:
            Wrapped application with WAF middleware
        """
        return ASGIMiddleware(app, waf_instance=self.waf)
