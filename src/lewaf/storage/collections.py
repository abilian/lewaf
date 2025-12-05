"""
Persistent collection management for WAF.

This module manages persistent collections that are loaded via initcol
and persist across requests for tracking user behavior, rate limiting, etc.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lewaf.primitives.collections import MapCollection
    from lewaf.storage.backends import StorageBackend


class PersistentCollectionManager:
    """
    Manages persistent collections for a WAF transaction.

    Handles loading, saving, and lifecycle of persistent collections
    that are initialized via initcol action.
    """

    def __init__(self, storage_backend: StorageBackend):
        """
        Initialize collection manager.

        Args:
            storage_backend: Storage backend to use for persistence
        """
        self.storage = storage_backend
        self.loaded_collections: dict[str, LoadedCollection] = {}
        self.default_ttl = 600  # 10 minutes default TTL

    def init_collection(
        self,
        collection_name: str,
        key: str,
        collection: MapCollection,
        ttl: int = 0,
    ) -> None:
        """
        Initialize a persistent collection.

        Loads existing data from storage or creates new collection.

        Args:
            collection_name: Name of collection type (e.g., "ip", "session", "user")
            key: Unique identifier (e.g., IP address, session ID, user ID)
            collection: MapCollection to populate with persisted data
            ttl: Time-to-live in seconds (0 = use default, -1 = no expiration)

        Example:
            # Initialize IP-based collection
            manager.init_collection("ip", "192.168.1.1", transaction.variables.ip)

            # Initialize session-based collection
            manager.init_collection("session", "abc123", transaction.variables.session)
        """
        # Determine TTL
        effective_ttl = self.default_ttl if ttl == 0 else (0 if ttl == -1 else ttl)

        # Load existing data from storage
        stored_data = self.storage.get(collection_name, key)

        if stored_data:
            # Restore collection data
            collection._data.clear()
            for var_key, values in stored_data.items():
                if isinstance(values, list):
                    for value in values:
                        collection.add(var_key, value)
                else:
                    collection.add(var_key, str(values))

        # Track loaded collection for later saving
        self.loaded_collections[f"{collection_name}:{key}"] = LoadedCollection(
            collection_name=collection_name,
            key=key,
            collection=collection,
            ttl=effective_ttl,
            loaded_at=time.time(),
        )

    def persist_collections(self) -> None:
        """
        Persist all loaded collections back to storage.

        This should be called at the end of transaction processing.
        """
        for loaded in self.loaded_collections.values():
            # Convert collection to storable format
            data = dict(loaded.collection._data.items())

            # Save to storage with TTL
            self.storage.set(
                loaded.collection_name,
                loaded.key,
                data,
                loaded.ttl,
            )

    def get_loaded_collection(
        self, collection_name: str, key: str
    ) -> LoadedCollection | None:
        """
        Get a loaded collection by name and key.

        Args:
            collection_name: Collection type name
            key: Collection key

        Returns:
            LoadedCollection if found, None otherwise
        """
        full_key = f"{collection_name}:{key}"
        return self.loaded_collections.get(full_key)


@dataclass(frozen=True, slots=True)
class LoadedCollection:
    """
    Represents a persistent collection that has been loaded.

    Tracks metadata needed for saving the collection back to storage.

    Attributes:
        collection_name: Collection type name
        key: Collection key
        collection: The MapCollection instance
        ttl: Time-to-live in seconds
        loaded_at: Timestamp when collection was loaded
    """

    collection_name: str
    key: str
    collection: MapCollection
    ttl: int
    loaded_at: float
