"""Persistent storage for WAF collections.

This module provides persistent storage backends and collection management
for features like rate limiting, session tracking, and user profiling.

Public API:
    StorageBackend - Abstract base class for custom storage backends
    MemoryStorage - In-memory storage (default)

Internal API (configure via WAFConfig instead):
    FileStorage, RedisStorage - Use WAFConfig.storage.backend setting
"""

from __future__ import annotations

# Public API
# Internal API - use WAFConfig.storage settings instead
from lewaf.storage.backends import (
    FileStorage,
    MemoryStorage,
    RedisStorage,
    StorageBackend,
    get_storage_backend,
    set_storage_backend,
)

# Only export the minimal public API
__all__ = [
    # Internal API (configure via WAFConfig instead)
    "FileStorage",
    "MemoryStorage",
    "RedisStorage",
    # Public API (stable for 1.0)
    "StorageBackend",
    "get_storage_backend",
    "set_storage_backend",
]
