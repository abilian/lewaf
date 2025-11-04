"""Base classes for body processors."""

from __future__ import annotations

from typing import Any


class BodyProcessorError(Exception):
    """Exception raised when body processing fails.

    This includes:
    - Malformed JSON/XML
    - Invalid multipart boundaries
    - Size limit violations
    - Encoding errors
    """

    pass


class BaseBodyProcessor:
    """Base class for body processors.

    Provides common functionality for all body processors.
    Subclasses must implement read() method.
    """

    def __init__(self):
        """Initialize body processor."""
        self.collections: dict[str, Any] = {}
        self.body_parsed = False
        self.raw_body: bytes | None = None
        self.content_type: str = ""

    def read(self, body: bytes, content_type: str) -> None:
        """Parse body and populate collections.

        Args:
            body: Raw body bytes
            content_type: Content-Type header value

        Raises:
            BodyProcessorError: If body cannot be parsed
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement read() method"
        )

    def get_collections(self) -> dict[str, Any]:
        """Return populated variable collections.

        Returns:
            Dictionary of collection_name -> values
        """
        return self.collections

    def find(self, expression: str) -> list[str]:
        """Query body using processor-specific expression.

        Args:
            expression: Query expression

        Returns:
            List of matched values (default: empty list)
        """
        # Default implementation: no query support
        return []

    def _set_collection(self, name: str, value: Any) -> None:
        """Set a collection in the internal state.

        Args:
            name: Collection name (e.g., "args_post", "files")
            value: Collection value (dict, list, etc.)
        """
        self.collections[name] = value

    def _add_to_collection(self, name: str, key: str, value: Any) -> None:
        """Add an item to a collection.

        Args:
            name: Collection name
            key: Item key
            value: Item value
        """
        if name not in self.collections:
            self.collections[name] = {}
        self.collections[name][key] = value
