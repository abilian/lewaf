"""URLEncoded body processor for application/x-www-form-urlencoded."""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

from lewaf.bodyprocessors.base import BaseBodyProcessor
from lewaf.exceptions import BodyProcessorError

logger = logging.getLogger(__name__)


class URLEncodedProcessor(BaseBodyProcessor):
    """Process application/x-www-form-urlencoded request bodies.

    This is the default body processor for forms submitted via HTML.
    Populates ARGS_POST variables from the request body.

    Example:
        Content-Type: application/x-www-form-urlencoded
        Body: username=admin&password=secret&submit=Login

        Populates:
        - ARGS_POST:username = "admin"
        - ARGS_POST:password = "secret"
        - ARGS_POST:submit = "Login"
        - REQUEST_BODY = "username=admin&password=secret&submit=Login"
    """

    def read(self, body: bytes, content_type: str) -> None:
        """Parse URLEncoded body.

        Args:
            body: Raw body bytes
            content_type: Content-Type header (not used for URLEncoded)

        Raises:
            BodyProcessorError: If body cannot be decoded as UTF-8
        """
        try:
            # Decode body to string
            body_str = body.decode("utf-8")
        except UnicodeDecodeError as e:
            msg = f"Invalid UTF-8 in URL-encoded body: {e}"
            snippet = body[:100].decode("utf-8", errors="replace")
            raise BodyProcessorError(
                msg, content_type=content_type, body_snippet=snippet, cause=e
            ) from e

        # Store raw body
        self.raw_body = body
        self.content_type = content_type

        # Parse URL-encoded parameters
        args_post = {}
        try:
            parsed = parse_qs(body_str, keep_blank_values=True)
            # parse_qs returns lists, but we want single values (take first)
            for key, values in parsed.items():
                # If multiple values, take the first one
                # (ModSecurity behavior)
                args_post[key] = values[0] if values else ""

        except Exception as e:
            # parse_qs is lenient, but catch any unexpected errors
            logger.warning("Error parsing URL-encoded body: %s", e)
            msg = f"Failed to parse URL-encoded body: {e}"
            snippet = body_str[:100] if len(body_str) > 100 else body_str
            raise BodyProcessorError(
                msg, content_type=content_type, body_snippet=snippet, cause=e
            ) from e

        # Populate collections
        self._set_collection("args_post", args_post)
        self._set_collection("request_body", body_str)
        self.body_parsed = True

        logger.debug(
            f"Parsed URL-encoded body: {len(args_post)} parameters, {len(body)} bytes"
        )
