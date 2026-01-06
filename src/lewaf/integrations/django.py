"""Django middleware for LeWAF.

This module provides native Django middleware for WAF protection.

Setup:
    1. Add to MIDDLEWARE in settings.py:
        MIDDLEWARE = [
            'lewaf.integrations.django.LeWAFMiddleware',
            # ... other middleware
        ]

    2. Configure WAF in settings.py:
        LEWAF_CONFIG = {
            'rules': ['SecRule ARGS "@rx attack" "id:1,phase:1,deny"'],
        }
        # Or use a config file:
        LEWAF_CONFIG_FILE = 'config/lewaf.yaml'
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)

# Module-level WAF instance (initialized on first request)
_waf_instance = None


def get_waf() -> Any:
    """Get or create the WAF instance.

    Returns:
        WAF instance configured from Django settings
    """
    global _waf_instance

    if _waf_instance is not None:
        return _waf_instance

    from django.conf import settings  # noqa: PLC0415

    from lewaf.integration import WAF  # noqa: PLC0415

    # Check for config file first
    config_file = getattr(settings, "LEWAF_CONFIG_FILE", None)
    if config_file:
        from pathlib import Path  # noqa: PLC0415

        from lewaf.config.loader import ConfigLoader  # noqa: PLC0415

        loader = ConfigLoader()
        config = loader.load_from_file(Path(config_file))
        _waf_instance = WAF({"rules": config.rules, "rule_files": config.rule_files})
        return _waf_instance

    # Check for inline config
    config = getattr(settings, "LEWAF_CONFIG", None)
    if config:
        _waf_instance = WAF(config)
        return _waf_instance

    # Default: empty WAF (no rules)
    logger.warning(
        "No LEWAF_CONFIG or LEWAF_CONFIG_FILE in Django settings. "
        "WAF initialized with no rules."
    )
    _waf_instance = WAF({"rules": []})
    return _waf_instance


class LeWAFMiddleware:
    """Django middleware for WAF protection.

    This middleware inspects incoming requests and blocks malicious traffic
    based on configured SecLang rules.

    Configuration in settings.py:
        # Option 1: Inline rules
        LEWAF_CONFIG = {
            'rules': [
                'SecRule ARGS "@rx attack" "id:1,phase:1,deny"',
            ]
        }

        # Option 2: Config file
        LEWAF_CONFIG_FILE = 'config/lewaf.yaml'

        # Optional: Custom block response
        LEWAF_BLOCK_STATUS = 403
        LEWAF_BLOCK_MESSAGE = 'Request blocked by WAF'

    Example settings.py:
        MIDDLEWARE = [
            'django.middleware.security.SecurityMiddleware',
            'lewaf.integrations.django.LeWAFMiddleware',  # Add early in chain
            'django.contrib.sessions.middleware.SessionMiddleware',
            # ...
        ]

        LEWAF_CONFIG = {
            'rules': [
                'SecRule ARGS "@rx (union|select|insert|update|delete)" '
                '"id:1001,phase:1,deny,msg:SQL injection attempt"',
            ]
        }
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        """Initialize middleware.

        Args:
            get_response: Django's get_response callable
        """
        self.get_response = get_response
        self.waf = get_waf()

        # Load block response settings
        try:
            from django.conf import settings  # noqa: PLC0415

            self.block_status = getattr(settings, "LEWAF_BLOCK_STATUS", 403)
            self.block_message = getattr(
                settings, "LEWAF_BLOCK_MESSAGE", "Request blocked by WAF"
            )
        except Exception:
            self.block_status = 403
            self.block_message = "Request blocked by WAF"

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request through WAF.

        Args:
            request: Django HttpRequest

        Returns:
            HttpResponse (either from app or block response)
        """
        tx = self.waf.new_transaction()

        try:
            # Build URI with query string
            uri = request.path
            if request.META.get("QUERY_STRING"):
                uri = f"{uri}?{request.META['QUERY_STRING']}"

            # Process URI and method
            tx.process_uri(uri, request.method)

            # Add request headers
            self._add_request_headers(tx, request)

            # Process Phase 1 (request headers)
            interruption = tx.process_request_headers()
            if interruption:
                logger.warning(
                    "Request blocked in Phase 1 by rule %s", interruption["rule_id"]
                )
                return self._block_response(interruption)

            # Process request body (Phase 2)
            if request.body:
                content_type = request.content_type or ""
                tx.add_request_body(request.body, content_type)

            interruption = tx.process_request_body()
            if interruption:
                logger.warning(
                    "Request blocked in Phase 2 by rule %s", interruption["rule_id"]
                )
                return self._block_response(interruption)

            # Request passed WAF, continue to view
            response = self.get_response(request)

            # Process response (Phase 3)
            self._add_response_headers(tx, response)
            tx.add_response_status(response.status_code)

            interruption = tx.process_response_headers()
            if interruption:
                logger.warning(
                    "Response blocked in Phase 3 by rule %s", interruption["rule_id"]
                )
                return self._block_response(interruption)

            return response

        except Exception as e:
            logger.error("Error in LeWAFMiddleware: %s", e)
            # Fail open - allow request on error
            return self.get_response(request)

    def _add_request_headers(self, tx: Any, request: HttpRequest) -> None:
        """Extract and add HTTP headers from Django request.

        Args:
            tx: Transaction instance
            request: Django HttpRequest
        """
        # Django stores headers in META with HTTP_ prefix
        for key, value in request.META.items():
            if key.startswith("HTTP_"):
                header_name = key[5:].replace("_", "-").lower()
                tx.variables.request_headers.add(header_name, value)

        # Special headers
        if "CONTENT_TYPE" in request.META:
            tx.variables.request_headers.add("content-type", request.META["CONTENT_TYPE"])
        if "CONTENT_LENGTH" in request.META:
            tx.variables.request_headers.add(
                "content-length", request.META["CONTENT_LENGTH"]
            )

        # Connection metadata
        tx.variables.remote_addr.set(self._get_client_ip(request))
        tx.variables.server_name.set(request.META.get("SERVER_NAME", ""))
        tx.variables.server_port.set(request.META.get("SERVER_PORT", "80"))

    def _add_response_headers(self, tx: Any, response: HttpResponse) -> None:
        """Add response headers to transaction.

        Args:
            tx: Transaction instance
            response: Django HttpResponse
        """
        for header, value in response.items():
            tx.variables.response_headers.add(header.lower(), value)

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get client IP address, respecting X-Forwarded-For.

        Args:
            request: Django HttpRequest

        Returns:
            Client IP address string
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            # Take first IP in chain
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")

    def _block_response(self, interruption: dict[str, Any]) -> HttpResponse:
        """Generate blocked request response.

        Args:
            interruption: Interruption dictionary from WAF

        Returns:
            Django HttpResponse
        """
        from django.http import HttpResponseRedirect, JsonResponse  # noqa: PLC0415

        # Check for redirect
        redirect_url = interruption.get("redirect_url")
        if redirect_url:
            return HttpResponseRedirect(redirect_url)

        # Return JSON response for API-like requests
        return JsonResponse(
            {
                "error": "Request blocked by WAF",
                "rule_id": interruption["rule_id"],
                "message": self.block_message,
            },
            status=self.block_status,
        )


def reset_waf() -> None:
    """Reset the WAF instance (useful for testing).

    This forces the WAF to be re-initialized from settings on next request.
    """
    global _waf_instance
    _waf_instance = None
