"""JSON body processor for application/json."""

from __future__ import annotations

import json
import logging
from typing import Any

from lewaf.bodyprocessors.base import BaseBodyProcessor
from lewaf.exceptions import InvalidJSONError

logger = logging.getLogger(__name__)


class JSONProcessor(BaseBodyProcessor):
    """Process application/json request bodies.

    Parses JSON bodies and flattens them to ARGS_POST variables.
    Also provides JSONPath-like queries via find() method.

    Example:
        Content-Type: application/json
        Body: {"user": {"name": "admin", "id": 123}, "action": "login"}

        Populates:
        - ARGS_POST:user.name = "admin"
        - ARGS_POST:user.id = "123"
        - ARGS_POST:action = "login"
        - REQUEST_BODY = '{"user": {"name": "admin", "id": 123}, "action": "login"}'

    JSONPath queries:
        find("$.user.name") -> ["admin"]
        find("$.user.id") -> ["123"]
    """

    def __init__(self):
        """Initialize JSON processor."""
        super().__init__()
        self.json_data: dict | list | None = None
        self.max_depth = 10  # Prevent deeply nested JSON bombs

    def read(self, body: bytes, content_type: str) -> None:
        """Parse JSON body.

        Args:
            body: Raw body bytes
            content_type: Content-Type header

        Raises:
            BodyProcessorError: If body is not valid JSON
        """
        try:
            # Decode body to string
            body_str = body.decode("utf-8")
        except UnicodeDecodeError as e:
            msg = f"Invalid UTF-8 in JSON body: {e}"
            # Get snippet for debugging (first 100 bytes)
            snippet = body[:100].decode("utf-8", errors="replace")
            raise InvalidJSONError(msg, body_snippet=snippet, cause=e) from e

        # Store raw body
        self.raw_body = body
        self.content_type = content_type

        # Parse JSON
        try:
            self.json_data = json.loads(body_str)
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON: {e}"
            # Get snippet around error position
            snippet = body_str[:100] if len(body_str) > 100 else body_str
            raise InvalidJSONError(msg, body_snippet=snippet, cause=e) from e

        # Flatten JSON to ARGS_POST
        args_post: dict[str, str] = {}
        if isinstance(self.json_data, dict):
            self._flatten_dict(self.json_data, "", args_post, depth=0)
        elif isinstance(self.json_data, list):
            # Handle JSON arrays at root level
            for i, item in enumerate(self.json_data):
                if isinstance(item, dict):
                    self._flatten_dict(item, f"[{i}]", args_post, depth=0)
                else:
                    args_post[f"[{i}]"] = str(item)
        else:
            # Primitive value at root
            args_post["value"] = str(self.json_data)

        # Populate collections
        self._set_collection("args_post", args_post)
        self._set_collection("request_body", body_str)
        self.body_parsed = True

        logger.debug(
            f"Parsed JSON body: {len(args_post)} parameters, {len(body)} bytes"
        )

    def _flatten_dict(self, data: dict, prefix: str, result: dict, depth: int) -> None:
        """Recursively flatten a dictionary to dot-notation keys.

        Args:
            data: Dictionary to flatten
            prefix: Current key prefix
            result: Result dictionary to populate
            depth: Current nesting depth
        """
        if depth >= self.max_depth:
            logger.warning(f"Max JSON depth ({self.max_depth}) exceeded, truncating")
            return

        for key, value in data.items():
            # Build full key name
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                # Recurse into nested dict
                self._flatten_dict(value, full_key, result, depth + 1)
            elif isinstance(value, list):
                # Flatten arrays
                for i, item in enumerate(value):
                    array_key = f"{full_key}[{i}]"
                    if isinstance(item, dict):
                        self._flatten_dict(item, array_key, result, depth + 1)
                    else:
                        result[array_key] = str(item)
            elif value is None:
                result[full_key] = ""
            else:
                # Primitive value - convert to string
                result[full_key] = str(value)

    def find(self, expression: str) -> list[str]:
        """Query JSON using simple path expression.

        Args:
            expression: Path expression (e.g., "$.user.name", "user.id")

        Returns:
            List of matched values as strings

        Note:
            This is a simplified JSONPath implementation.
            Supports: $.key, $.key.nested, $.key[0]
            Does not support: wildcards, filters, unions
        """
        if not self.json_data:
            return []

        # Remove leading $. or $ if present
        path = expression
        if path.startswith("$."):
            path = path[2:]
        elif path.startswith("$"):
            path = path[1:]

        if not path:
            # Root query
            return [json.dumps(self.json_data)]

        # Simple path traversal
        try:
            result = self._traverse_path(self.json_data, path)
            if result is not None:
                if isinstance(result, (list, dict)):
                    return [json.dumps(result)]
                return [str(result)]
        except (KeyError, IndexError, TypeError):
            pass

        return []

    def _traverse_path(self, data: Any, path: str) -> Any:
        """Traverse a JSON path to find value.

        Args:
            data: Current data node
            path: Remaining path to traverse

        Returns:
            Value at path, or None if not found
        """
        if not path:
            return data

        # Handle array index like "key[0]"
        if "[" in path:
            key, rest = path.split("[", 1)
            if key:
                # Navigate to key first
                if not isinstance(data, dict) or key not in data:
                    return None
                data = data[key]

            # Extract index
            if "]" not in rest:
                return None
            index_str, remaining = rest.split("]", 1)
            try:
                index = int(index_str)
            except ValueError:
                return None

            if not isinstance(data, list) or index >= len(data):
                return None

            data = data[index]

            # Continue with remaining path
            if remaining.startswith("."):
                remaining = remaining[1:]
            return self._traverse_path(data, remaining)

        # Handle simple key navigation
        if "." in path:
            key, rest = path.split(".", 1)
        else:
            key = path
            rest = ""

        if isinstance(data, dict) and key in data:
            if rest:
                return self._traverse_path(data[key], rest)
            return data[key]

        return None
