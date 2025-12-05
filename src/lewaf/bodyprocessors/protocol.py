"""Protocol definition for body processors."""

from __future__ import annotations

from typing import Any, Protocol


class BodyProcessorProtocol(Protocol):
    """Protocol for body processors.

    Body processors parse request/response bodies in different formats and populate
    transaction variables for rule evaluation.

    Implementations must provide:
    - read(): Parse body and populate internal state
    - get_collections(): Return populated variable collections
    - find(): Query body using processor-specific expressions
    """

    def read(self, body: bytes, content_type: str) -> None:
        """Parse body and populate internal state.

        Args:
            body: Raw body bytes
            content_type: Content-Type header value (e.g., "application/json")

        Raises:
            BodyProcessorError: If body is malformed or cannot be parsed
        """
        ...

    def get_collections(self) -> dict[str, Any]:
        """Return populated variable collections.

        Returns:
            Dictionary of collection_name -> values
            Examples:
                {"args_post": {"key": "value", ...}, "files": {...}}

        The returned collections will be merged into the transaction's variables.
        """
        ...

    def find(self, expression: str) -> list[str]:
        """Query body using processor-specific expression.

        Args:
            expression: Query expression (format depends on processor):
                - XML: XPath expression (e.g., "//user/name")
                - JSON: JSONPath expression (e.g., "$.user.name")
                - URLENCODED/MULTIPART: Not supported (returns empty list)

        Returns:
            List of matched values (as strings)
        """
        ...
