"""Body processors for parsing request/response bodies in different formats.

This package provides body processors for:
- URLENCODED: application/x-www-form-urlencoded
- JSON: application/json
- XML: text/xml, application/xml
- MULTIPART: multipart/form-data

Each processor parses the body and populates transaction variables for rule evaluation.
"""

from lewaf.bodyprocessors.base import BodyProcessorError
from lewaf.bodyprocessors.protocol import BodyProcessorProtocol
from lewaf.bodyprocessors.registry import get_body_processor, register_body_processor
from lewaf.bodyprocessors.urlencoded import URLEncodedProcessor

# Register built-in processors
register_body_processor("URLENCODED", lambda: URLEncodedProcessor())

__all__ = [
    "BodyProcessorError",
    "BodyProcessorProtocol",
    "get_body_processor",
    "register_body_processor",
    "URLEncodedProcessor",
]
