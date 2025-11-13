"""
Storage backends for persistent collections.

This module provides storage backends for persistent WAF collections used by
initcol and similar directives. Collections can be persisted across requests
for features like:
- Rate limiting per IP
- Session tracking
- User-based anomaly scores
- Distributed brute force detection
"""

from __future__ import annotations

import json
import pickle
import time
from abc import ABC, abstractmethod
from pathlib import Path
from threading import RLock
from typing import Any


class StorageBackend(ABC):
    """Abstract base class for persistent storage backends."""

    @abstractmethod
    def get(self, collection_name: str, key: str) -> dict[str, Any] | None:
        """
        Retrieve a collection from storage.

        Args:
            collection_name: Name of the collection type (e.g., "ip", "session")
            key: Unique key within the collection (e.g., IP address, session ID)

        Returns:
            Dictionary containing collection data, or None if not found
        """
        pass

    @abstractmethod
    def set(
        self, collection_name: str, key: str, data: dict[str, Any], ttl: int = 0
    ) -> None:
        """
        Store a collection in storage.

        Args:
            collection_name: Name of the collection type
            key: Unique key within the collection
            data: Collection data to store
            ttl: Time-to-live in seconds (0 = no expiration)
        """
        pass

    @abstractmethod
    def delete(self, collection_name: str, key: str) -> None:
        """
        Delete a collection from storage.

        Args:
            collection_name: Name of the collection type
            key: Unique key within the collection
        """
        pass

    @abstractmethod
    def clear_expired(self) -> int:
        """
        Remove expired collections from storage.

        Returns:
            Number of collections removed
        """
        pass


class MemoryStorage(StorageBackend):
    """
    In-memory storage backend.

    Fast but data is lost when the process restarts. Suitable for:
    - Development and testing
    - Single-process deployments
    - Non-critical tracking (will reset on restart)
    """

    def __init__(self):
        """Initialize memory storage."""
        self._storage: dict[str, dict[str, dict[str, Any]]] = {}
        self._expiration: dict[str, dict[str, float]] = {}
        self._lock = RLock()  # Reentrant lock to allow nested acquire

    def get(self, collection_name: str, key: str) -> dict[str, Any] | None:
        """Retrieve a collection from memory."""
        with self._lock:
            # Check expiration first
            if (
                collection_name in self._expiration
                and key in self._expiration[collection_name]
            ):
                if time.time() >= self._expiration[collection_name][key]:
                    # Expired, delete and return None
                    self.delete(collection_name, key)
                    return None

            # Return data if exists
            if (
                collection_name in self._storage
                and key in self._storage[collection_name]
            ):
                return self._storage[collection_name][key].copy()

            return None

    def set(
        self, collection_name: str, key: str, data: dict[str, Any], ttl: int = 0
    ) -> None:
        """Store a collection in memory."""
        with self._lock:
            # Initialize collection type if needed
            if collection_name not in self._storage:
                self._storage[collection_name] = {}
                self._expiration[collection_name] = {}

            # Store data
            self._storage[collection_name][key] = data.copy()

            # Set expiration if TTL provided
            if ttl > 0:
                self._expiration[collection_name][key] = time.time() + ttl
            elif key in self._expiration.get(collection_name, {}):
                # Remove expiration if TTL is 0
                del self._expiration[collection_name][key]

    def delete(self, collection_name: str, key: str) -> None:
        """Delete a collection from memory."""
        with self._lock:
            if (
                collection_name in self._storage
                and key in self._storage[collection_name]
            ):
                del self._storage[collection_name][key]

            if (
                collection_name in self._expiration
                and key in self._expiration[collection_name]
            ):
                del self._expiration[collection_name][key]

    def clear_expired(self) -> int:
        """Remove expired collections from memory."""
        with self._lock:
            removed_count = 0
            current_time = time.time()

            for collection_name in list(self._expiration.keys()):
                expired_keys = [
                    key
                    for key, expiry_time in self._expiration[collection_name].items()
                    if current_time >= expiry_time
                ]

                for key in expired_keys:
                    self.delete(collection_name, key)
                    removed_count += 1

            return removed_count

    def get_stats(self) -> dict[str, Any]:
        """Get storage statistics."""
        with self._lock:
            total_collections = sum(len(items) for items in self._storage.values())
            total_expired = sum(len(items) for items in self._expiration.values())

            return {
                "backend": "memory",
                "total_collections": total_collections,
                "total_with_expiration": total_expired,
                "collection_types": list(self._storage.keys()),
            }


class FileStorage(StorageBackend):
    """
    File-based storage backend.

    Persists data to disk. Suitable for:
    - Single-process deployments that need persistence
    - Development with restart preservation
    - Low-traffic applications

    Not suitable for:
    - Multi-process deployments (no locking across processes)
    - High-traffic applications (file I/O overhead)
    """

    def __init__(self, storage_dir: str | Path, use_json: bool = False):
        """
        Initialize file storage.

        Args:
            storage_dir: Directory to store collection files
            use_json: Use JSON instead of pickle (slower but human-readable)
        """
        self.storage_dir = Path(storage_dir)
        self.use_json = use_json
        self._lock = RLock()  # Reentrant lock for safety

        # Create storage directory if it doesn't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_path(self, collection_name: str, key: str) -> Path:
        """Get file path for a collection."""
        # Use safe filename encoding
        safe_key = key.replace("/", "_").replace("\\", "_")[:200]
        return self.storage_dir / collection_name / f"{safe_key}.dat"

    def get(self, collection_name: str, key: str) -> dict[str, Any] | None:
        """Retrieve a collection from file."""
        file_path = self._get_file_path(collection_name, key)

        with self._lock:
            if not file_path.exists():
                return None

            try:
                if self.use_json:
                    with open(file_path) as f:
                        stored = json.load(f)
                else:
                    with open(file_path, "rb") as f:
                        stored = pickle.load(f)

                # Check expiration
                if "expiry" in stored and stored["expiry"] > 0:
                    if time.time() >= stored["expiry"]:
                        # Expired, delete file
                        file_path.unlink()
                        return None

                return stored.get("data")

            except Exception:
                # Corrupted file, delete it
                if file_path.exists():
                    file_path.unlink()
                return None

    def set(
        self, collection_name: str, key: str, data: dict[str, Any], ttl: int = 0
    ) -> None:
        """Store a collection to file."""
        file_path = self._get_file_path(collection_name, key)

        with self._lock:
            # Create collection directory if needed
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Prepare storage data
            stored = {
                "data": data,
                "expiry": time.time() + ttl if ttl > 0 else 0,
                "created": time.time(),
            }

            try:
                if self.use_json:
                    with open(file_path, "w") as f:
                        json.dump(stored, f)
                else:
                    with open(file_path, "wb") as f:
                        pickle.dump(stored, f)
            except Exception:
                # Failed to write, ignore
                pass

    def delete(self, collection_name: str, key: str) -> None:
        """Delete a collection file."""
        file_path = self._get_file_path(collection_name, key)

        with self._lock:
            if file_path.exists():
                try:
                    file_path.unlink()
                except Exception:
                    pass

    def clear_expired(self) -> int:
        """Remove expired collection files."""
        with self._lock:
            removed_count = 0
            current_time = time.time()

            # Iterate through all collection directories
            for collection_dir in self.storage_dir.iterdir():
                if not collection_dir.is_dir():
                    continue

                # Check each collection file
                for file_path in collection_dir.glob("*.dat"):
                    try:
                        if self.use_json:
                            with open(file_path) as f:
                                stored = json.load(f)
                        else:
                            with open(file_path, "rb") as f:
                                stored = pickle.load(f)

                        # Check expiration
                        if "expiry" in stored and stored["expiry"] > 0:
                            if current_time >= stored["expiry"]:
                                file_path.unlink()
                                removed_count += 1

                    except Exception:
                        # Corrupted file, delete it
                        file_path.unlink()
                        removed_count += 1

            return removed_count


class RedisStorage(StorageBackend):
    """
    Redis-based storage backend.

    Suitable for:
    - Multi-process deployments
    - Distributed WAF deployments
    - High-traffic applications
    - Shared state across multiple servers

    Requires redis-py package.
    """

    def __init__(
        self, host: str = "localhost", port: int = 6379, db: int = 0, **kwargs
    ):
        """
        Initialize Redis storage.

        Args:
            host: Redis server host
            port: Redis server port
            db: Redis database number
            **kwargs: Additional redis.Redis arguments
        """
        try:
            import redis
        except ImportError as e:
            msg = "Redis storage requires redis-py: pip install redis"
            raise ImportError(msg) from e

        self.redis = redis.Redis(host=host, port=port, db=db, **kwargs)
        self.key_prefix = "lewaf:collection:"

    def _get_redis_key(self, collection_name: str, key: str) -> str:
        """Get Redis key for a collection."""
        return f"{self.key_prefix}{collection_name}:{key}"

    def get(self, collection_name: str, key: str) -> dict[str, Any] | None:
        """Retrieve a collection from Redis."""
        redis_key = self._get_redis_key(collection_name, key)

        try:
            data = self.redis.get(redis_key)
            if data is None:
                return None

            return pickle.loads(data)  # type: ignore
        except Exception:
            return None

    def set(
        self, collection_name: str, key: str, data: dict[str, Any], ttl: int = 0
    ) -> None:
        """Store a collection in Redis."""
        redis_key = self._get_redis_key(collection_name, key)

        try:
            serialized = pickle.dumps(data)

            if ttl > 0:
                self.redis.setex(redis_key, ttl, serialized)
            else:
                self.redis.set(redis_key, serialized)
        except Exception:
            # Failed to store, ignore
            pass

    def delete(self, collection_name: str, key: str) -> None:
        """Delete a collection from Redis."""
        redis_key = self._get_redis_key(collection_name, key)

        try:
            self.redis.delete(redis_key)
        except Exception:
            pass

    def clear_expired(self) -> int:
        """
        Remove expired collections from Redis.

        Note: Redis handles expiration automatically, so this is a no-op.
        """
        return 0  # Redis handles expiration automatically


# Global storage backend instance
_storage_backend: StorageBackend | None = None


def get_storage_backend() -> StorageBackend:
    """Get the global storage backend instance."""
    global _storage_backend

    if _storage_backend is None:
        # Default to memory storage
        _storage_backend = MemoryStorage()

    return _storage_backend


def set_storage_backend(backend: StorageBackend) -> None:
    """Set the global storage backend instance."""
    global _storage_backend
    _storage_backend = backend
