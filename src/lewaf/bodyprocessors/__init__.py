"""Body processors for parsing request/response bodies in different formats.

This package provides body processors for:
- URLENCODED: application/x-www-form-urlencoded
- JSON: application/json
- XML: text/xml, application/xml
- MULTIPART: multipart/form-data

Each processor parses the body and populates transaction variables for rule evaluation.
"""

from __future__ import annotations

from lewaf.bodyprocessors.base import BodyProcessorError
from lewaf.bodyprocessors.json import JSONProcessor
from lewaf.bodyprocessors.multipart import MultipartProcessor
from lewaf.bodyprocessors.protocol import BodyProcessorProtocol
from lewaf.bodyprocessors.registry import get_body_processor, register_body_processor
from lewaf.bodyprocessors.urlencoded import URLEncodedProcessor
from lewaf.bodyprocessors.xml import XMLProcessor

# Register built-in processors
register_body_processor("URLENCODED", lambda: URLEncodedProcessor())
register_body_processor("JSON", lambda: JSONProcessor())
register_body_processor("XML", lambda: XMLProcessor())
register_body_processor("MULTIPART", lambda: MultipartProcessor())

__all__ = [
    "BodyProcessorError",
    "BodyProcessorProtocol",
    "JSONProcessor",
    "MultipartProcessor",
    "URLEncodedProcessor",
    "XMLProcessor",
    "get_body_processor",
    "register_body_processor",
]
