"""
Persistent storage for WAF collections.

This module provides persistent storage backends and collection management
for features like rate limiting, session tracking, and user profiling.
"""

from __future__ import annotations

from lewaf.storage.backends import (
    FileStorage,
    MemoryStorage,
    RedisStorage,
    StorageBackend,
    get_storage_backend,
    set_storage_backend,
)

__all__ = [
    "FileStorage",
    "MemoryStorage",
    "RedisStorage",
    "StorageBackend",
    "get_storage_backend",
    "set_storage_backend",
]
