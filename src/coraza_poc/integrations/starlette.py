"""Starlette integration for Coraza WAF."""

import logging
from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from coraza_poc.integration import WAF

logger = logging.getLogger(__name__)


class CorazaMiddleware(BaseHTTPMiddleware):
    """Starlette middleware for Coraza WAF protection."""

    def __init__(
        self,
        app: Starlette,
        waf: Optional[WAF] = None,
        config_file: Optional[str] = None,
        rules: Optional[list[str]] = None,
        block_response_status: int = 403,
        block_response_body: str = "Request blocked by WAF",
    ):
        super().__init__(app)

        if waf is not None:
            self.waf = waf
        else:
            # Create WAF from config
            config = {}
            if config_file:
                # TODO: Load rules from file
                config["rules"] = []
            elif rules:
                config["rules"] = rules
            else:
                # Default basic rules
                config["rules"] = [
                    'SecRule ARGS:test "@rx attack" "id:1001,phase:1,deny,log,msg:\'Test attack detected\'"',
                    'SecRule REQUEST_HEADERS:User-Agent "@rx (bot|scanner|crawler)" "id:1002,phase:1,deny,log,msg:\'Bot detected\'"',
                ]

            self.waf = WAF(config)

        self.block_response_status = block_response_status
        self.block_response_body = block_response_body

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Process request through WAF before forwarding."""

        # Create transaction
        tx = self.waf.new_transaction()

        try:
            # Process connection info

            tx.process_uri(str(request.url.path), request.method)

            # Add query parameters to ARGS
            if request.url.query:
                query_params = parse_qs(request.url.query)
                for key, values in query_params.items():
                    for value in values:
                        tx.variables.args.add(key, value)

            # Add request headers
            for name, value in request.headers.items():
                tx.variables.request_headers.add(name, value)

            # Process request headers phase
            interruption = tx.process_request_headers()
            if interruption:
                logger.warning(
                    f"Request blocked in headers phase by rule {interruption['rule_id']}"
                )
                return self._create_block_response(interruption)

            # TODO: Process request body if present
            body_interruption = tx.process_request_body()
            if body_interruption:
                logger.warning(
                    f"Request blocked in body phase by rule {body_interruption['rule_id']}"
                )
                return self._create_block_response(body_interruption)

            # Request passed WAF, continue to upstream
            response = await call_next(request)

            # TODO: Process response phase if needed
            return response

        except Exception as e:
            logger.error(f"Error in Coraza middleware: {e}")
            # On error, allow request to proceed (fail open)
            return await call_next(request)

    def _create_block_response(self, interruption: dict[str, Any]) -> Response:
        """Create a blocked request response."""
        if self.block_response_status == 403:
            return JSONResponse(
                status_code=self.block_response_status,
                content={
                    "error": "Request blocked by WAF",
                    "rule_id": interruption["rule_id"],
                    "message": self.block_response_body,
                },
            )
        else:
            return Response(
                content=self.block_response_body,
                status_code=self.block_response_status,
                media_type="text/plain",
            )


def create_waf_app(
    target_app: Starlette,
    config_file: Optional[str] = None,
    rules: Optional[list[str]] = None,
    **middleware_kwargs: Any,
) -> Starlette:
    """Create a Starlette app with WAF protection."""

    # Add Coraza middleware to the target app
    target_app.add_middleware(
        CorazaMiddleware,
        config_file=config_file,
        rules=rules,
        **middleware_kwargs,
    )

    return target_app
