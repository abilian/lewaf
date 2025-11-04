"""Multipart body processor for multipart/form-data."""

from __future__ import annotations

import logging
import re
from email import message_from_bytes

from lewaf.bodyprocessors.base import BaseBodyProcessor, BodyProcessorError

logger = logging.getLogger(__name__)


class MultipartProcessor(BaseBodyProcessor):
    """Process multipart/form-data request bodies.

    Parses multipart bodies including file uploads and populates:
    - ARGS_POST - form field values
    - FILES - uploaded file contents
    - FILES_NAMES - file field names
    - FILES_SIZES - file sizes in bytes
    - MULTIPART_FILENAME - original filename
    - MULTIPART_NAME - field name

    Security:
        - Limits total body size
        - Limits individual part size
        - Validates content-disposition headers
        - Safe filename handling

    Example:
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
        Body:
        ------WebKitFormBoundary
        Content-Disposition: form-data; name="username"

        admin
        ------WebKitFormBoundary
        Content-Disposition: form-data; name="file"; filename="upload.txt"
        Content-Type: text/plain

        file contents
        ------WebKitFormBoundary--
    """

    def __init__(self):
        """Initialize multipart processor."""
        super().__init__()
        self.parts: list[MultipartPart] = []
        self.max_size = 10 * 1024 * 1024  # 10MB limit
        self.max_part_size = 5 * 1024 * 1024  # 5MB per part

    def read(self, body: bytes, content_type: str) -> None:
        """Parse multipart body.

        Args:
            body: Raw body bytes
            content_type: Content-Type header (must include boundary)

        Raises:
            BodyProcessorError: If body is not valid multipart or too large
        """
        # Check size limit
        if len(body) > self.max_size:
            raise BodyProcessorError(
                f"Multipart body too large: {len(body)} bytes (max: {self.max_size})"
            )

        # Store raw body
        self.raw_body = body
        self.content_type = content_type

        # Extract boundary from Content-Type
        boundary = self._extract_boundary(content_type)
        if not boundary:
            raise BodyProcessorError(
                "Missing boundary in multipart Content-Type header"
            )

        # Parse multipart body
        try:
            self.parts = self._parse_multipart(body, boundary)
        except Exception as e:
            raise BodyProcessorError(f"Failed to parse multipart body: {e}") from e

        # Populate collections
        args_post = {}
        files_dict: dict[str, bytes] = {}
        files_names: dict[str, str] = {}
        files_sizes: dict[str, int] = {}
        multipart_filenames: dict[str, str] = {}
        multipart_names: dict[str, str] = {}

        for part in self.parts:
            if part.filename:
                # File upload
                files_dict[part.name] = part.content
                files_names[part.name] = part.name
                files_sizes[part.name] = len(part.content)
                multipart_filenames[part.name] = part.filename
                multipart_names[part.name] = part.name
            else:
                # Regular form field
                try:
                    args_post[part.name] = part.content.decode("utf-8")
                except UnicodeDecodeError:
                    # Binary data in form field - store as hex
                    args_post[part.name] = part.content.hex()

        self._set_collection("args_post", args_post)
        self._set_collection("files", files_dict)
        self._set_collection("files_names", files_names)
        self._set_collection("files_sizes", files_sizes)
        self._set_collection("multipart_filename", multipart_filenames)
        self._set_collection("multipart_name", multipart_names)
        self._set_collection("request_body", body.decode("utf-8", errors="replace"))
        self.body_parsed = True

        logger.debug(
            f"Parsed multipart body: {len(self.parts)} parts, {len(body)} bytes"
        )

    def _extract_boundary(self, content_type: str) -> str:
        """Extract boundary from Content-Type header.

        Args:
            content_type: Content-Type header value

        Returns:
            Boundary string, or empty string if not found
        """
        # Look for boundary parameter
        match = re.search(r'boundary=([^;,\s]+|"[^"]+")', content_type)
        if not match:
            return ""

        boundary = match.group(1)
        # Remove quotes if present
        if boundary.startswith('"') and boundary.endswith('"'):
            boundary = boundary[1:-1]

        return boundary

    def _parse_multipart(self, body: bytes, boundary: str) -> list[MultipartPart]:
        """Parse multipart body into parts.

        Args:
            body: Raw body bytes
            boundary: Multipart boundary string

        Returns:
            List of parsed multipart parts
        """
        parts = []

        # Split by boundary
        # Multipart boundaries are prefixed with --
        boundary_delimiter = b"--" + boundary.encode("utf-8")

        # Split body into sections
        sections = body.split(boundary_delimiter)

        for section in sections:
            # Skip empty sections (before first boundary)
            if not section:
                continue

            # Skip end marker (-- after final boundary)
            if section.strip() == b"--" or section.strip() == b"":
                continue

            # Each section starts with \r\n after the boundary
            # Strip leading \r\n
            if section.startswith(b"\r\n"):
                section = section[2:]

            # Each section should have headers and content separated by \r\n\r\n
            if b"\r\n\r\n" not in section:
                continue

            # Parse this part
            part = self._parse_part(section)
            if part:
                parts.append(part)

        return parts

    def _parse_part(self, data: bytes) -> MultipartPart | None:
        """Parse a single multipart part.

        Args:
            data: Raw part data (headers + content)

        Returns:
            Parsed MultipartPart, or None if invalid
        """
        # Split headers and content
        if b"\r\n\r\n" not in data:
            return None

        header_data, content = data.split(b"\r\n\r\n", 1)

        # Remove trailing \r\n from content
        if content.endswith(b"\r\n"):
            content = content[:-2]

        # Check part size limit
        if len(content) > self.max_part_size:
            logger.warning(
                f"Multipart part exceeds size limit: {len(content)} bytes (max: {self.max_part_size})"
            )
            # Truncate to max size
            content = content[: self.max_part_size]

        # Parse headers
        try:
            # Create a minimal email message to parse headers
            msg_bytes = header_data + b"\r\n\r\n"
            msg = message_from_bytes(msg_bytes)
        except Exception as e:
            logger.warning(f"Failed to parse multipart headers: {e}")
            return None

        # Extract Content-Disposition
        disposition = msg.get("Content-Disposition", "")
        if not disposition:
            return None

        # Parse name and filename from Content-Disposition
        name = self._extract_param(disposition, "name")
        filename = self._extract_param(disposition, "filename")

        if not name:
            return None

        # Get Content-Type
        content_type = msg.get("Content-Type", "text/plain")

        return MultipartPart(
            name=name,
            filename=filename,
            content_type=content_type,
            content=content,
        )

    def _extract_param(self, header: str, param: str) -> str:
        """Extract a parameter from a header value.

        Args:
            header: Header value (e.g., 'form-data; name="file"')
            param: Parameter name to extract

        Returns:
            Parameter value, or empty string if not found
        """
        # Look for param="value" or param=value
        # Try quoted string first, then unquoted
        pattern = rf'{param}=("([^"]*)"|([^;,\s]+))'
        match = re.search(pattern, header)
        if not match:
            return ""

        # Group 1 is the full match (with or without quotes)
        # Group 2 is the content inside quotes (if quoted)
        # Group 3 is the unquoted value
        if match.group(2) is not None:
            # Quoted value - use the content inside quotes
            return match.group(2)
        elif match.group(3) is not None:
            # Unquoted value
            return match.group(3)

        return ""

    def find(self, expression: str) -> list[str]:
        """Query multipart data.

        Args:
            expression: Query expression
                - "field_name" - get form field value
                - "file:field_name" - get file content (as hex)
                - "filename:field_name" - get filename

        Returns:
            List of matched values
        """
        if expression.startswith("file:"):
            field_name = expression[5:]
            for part in self.parts:
                if part.name == field_name and part.filename:
                    return [part.content.hex()]
            return []

        if expression.startswith("filename:"):
            field_name = expression[9:]
            for part in self.parts:
                if part.name == field_name and part.filename:
                    return [part.filename]
            return []

        # Regular field lookup
        for part in self.parts:
            if part.name == expression and not part.filename:
                try:
                    return [part.content.decode("utf-8")]
                except UnicodeDecodeError:
                    return [part.content.hex()]

        return []


class MultipartPart:
    """Represents a single part in a multipart body.

    Attributes:
        name: Field name from Content-Disposition
        filename: Filename if this is a file upload
        content_type: Content-Type of the part
        content: Raw content bytes
    """

    def __init__(
        self,
        name: str,
        filename: str,
        content_type: str,
        content: bytes,
    ):
        """Initialize multipart part.

        Args:
            name: Field name
            filename: Filename (empty string if not a file)
            content_type: Content-Type
            content: Raw content bytes
        """
        self.name = name
        self.filename = filename
        self.content_type = content_type
        self.content = content

    def __repr__(self) -> str:
        """Return string representation."""
        if self.filename:
            return f"MultipartPart(name={self.name!r}, filename={self.filename!r}, size={len(self.content)})"
        return f"MultipartPart(name={self.name!r}, size={len(self.content)})"
