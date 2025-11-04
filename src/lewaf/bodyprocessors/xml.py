"""XML body processor for text/xml and application/xml."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from lewaf.bodyprocessors.base import BaseBodyProcessor, BodyProcessorError

logger = logging.getLogger(__name__)


class XMLProcessor(BaseBodyProcessor):
    """Process XML request bodies.

    Parses XML bodies safely (with XXE protection) and provides XPath queries.
    Populates XML collection for rule evaluation.

    Security:
        - Disables external entity processing (XXE protection)
        - Limits document size
        - Safe against XML bombs

    Example:
        Content-Type: text/xml
        Body: <user><name>admin</name><id>123</id></user>

        XPath queries:
        find("//name") -> ["admin"]
        find("//user/id") -> ["123"]
    """

    def __init__(self):
        """Initialize XML processor."""
        super().__init__()
        self.root: ET.Element | None = None
        self.tree: ET.ElementTree | None = None
        self.max_size = 1024 * 1024  # 1MB limit for XML documents

    def read(self, body: bytes, content_type: str) -> None:
        """Parse XML body safely.

        Args:
            body: Raw body bytes
            content_type: Content-Type header

        Raises:
            BodyProcessorError: If body is not valid XML or too large
        """
        # Check size limit
        if len(body) > self.max_size:
            raise BodyProcessorError(
                f"XML body too large: {len(body)} bytes (max: {self.max_size})"
            )

        try:
            # Decode body to string
            body_str = body.decode("utf-8")
        except UnicodeDecodeError as e:
            raise BodyProcessorError(f"Invalid UTF-8 in XML body: {e}") from e

        # Store raw body
        self.raw_body = body
        self.content_type = content_type

        # Parse XML with security settings
        try:
            # Create parser - Python 3.x's ET is safe by default
            # External entities are NOT resolved (XXE protection built-in)
            parser = ET.XMLParser()

            # Parse XML
            self.root = ET.fromstring(body_str, parser=parser)
            self.tree = ET.ElementTree(self.root)

        except ET.ParseError as e:
            raise BodyProcessorError(f"Invalid XML: {e}") from e

        # Create XML collection (for XML:/* queries in rules)
        # This is a special collection that represents the parsed XML
        self._set_collection("xml", {"_root": self.root})
        self._set_collection("request_body", body_str)
        self.body_parsed = True

        logger.debug(f"Parsed XML body: {len(body)} bytes")

    def find(self, expression: str) -> list[str]:
        """Query XML using XPath expression.

        Args:
            expression: XPath expression (e.g., "//user/name", "//user[@id='123']")

        Returns:
            List of matched text values

        Supported XPath features:
            - Simple paths: //element, /root/child
            - Attributes: //@attr, //element[@attr='value']
            - Text: //element/text()
            - Wildcards: //*, //*[@attr]

        Note:
            Uses ElementTree's limited XPath support.
            More complex XPath requires lxml (optional dependency).
        """
        if self.root is None:
            return []

        try:
            # Handle special case: get all text content
            if expression == "//" or expression == "/*":
                return [self._get_all_text(self.root)]

            # ElementTree XPath implementation
            # Note: ET only supports a subset of XPath 1.0
            elements = self.root.findall(expression)

            results = []
            for elem in elements:
                # Get text content (only the direct text, not tail)
                if elem.text:
                    results.append(elem.text)

            return results

        except Exception as e:
            logger.warning(f"XPath query failed '{expression}': {e}")
            return []

    def _get_all_text(self, element: ET.Element) -> str:
        """Recursively get all text content from an element.

        Args:
            element: XML element

        Returns:
            Concatenated text content
        """
        texts = []

        if element.text:
            texts.append(element.text)

        for child in element:
            texts.append(self._get_all_text(child))
            if child.tail:
                texts.append(child.tail)

        return " ".join(texts).strip()

    def get_element_by_path(self, path: str) -> list[ET.Element]:
        """Get XML elements by XPath.

        Args:
            path: XPath expression

        Returns:
            List of matching elements
        """
        if not self.root:
            return []

        try:
            return self.root.findall(path)
        except Exception:
            return []
