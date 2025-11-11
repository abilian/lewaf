"""Registry for body processors."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lewaf.bodyprocessors.protocol import BodyProcessorProtocol

logger = logging.getLogger(__name__)

# Registry of body processor factories
_BODY_PROCESSORS: dict[str, Callable[[], BodyProcessorProtocol]] = {}


def register_body_processor(
    name: str, factory: Callable[[], BodyProcessorProtocol]
) -> None:
    """Register a body processor factory.

    Args:
        name: Processor name (e.g., "URLENCODED", "JSON")
        factory: Factory function that returns a BodyProcessorProtocol instance

    Example:
        register_body_processor("JSON", lambda: JSONProcessor())
    """
    name_upper = name.upper()
    _BODY_PROCESSORS[name_upper] = factory
    logger.debug(f"Registered body processor: {name_upper}")


def get_body_processor(name: str) -> BodyProcessorProtocol:
    """Get a body processor by name.

    Args:
        name: Processor name (case-insensitive)

    Returns:
        New BodyProcessorProtocol instance

    Raises:
        ValueError: If processor name is unknown
    """
    name_upper = name.upper()
    factory = _BODY_PROCESSORS.get(name_upper)

    if factory is None:
        available = ", ".join(sorted(_BODY_PROCESSORS.keys()))
        raise ValueError(
            f"Unknown body processor: {name}. Available processors: {available}"
        )

    return factory()


def list_body_processors() -> list[str]:
    """List all registered body processor names.

    Returns:
        Sorted list of processor names
    """
    return sorted(_BODY_PROCESSORS.keys())
