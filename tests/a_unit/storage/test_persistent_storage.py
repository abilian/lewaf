"""
Tests for persistent storage backends and collections.
"""

import tempfile
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from lewaf.primitives.collections import MapCollection, TransactionVariables
from lewaf.storage.backends import FileStorage, MemoryStorage
from lewaf.storage.collections import PersistentCollectionManager


class TestMemoryStorage:
    """Test MemoryStorage backend."""

    @pytest.fixture
    def storage(self):
        """Create MemoryStorage instance."""
        return MemoryStorage()

    def test_set_and_get(self, storage):
        """Test basic set and get operations."""
        data = {"score": ["5"], "count": ["10"]}
        storage.set("ip", "192.168.1.1", data)

        retrieved = storage.get("ip", "192.168.1.1")
        assert retrieved == data

    def test_get_nonexistent(self, storage):
        """Test getting non-existent collection returns None."""
        result = storage.get("ip", "192.168.1.1")
        assert result is None

    def test_delete(self, storage):
        """Test deleting a collection."""
        data = {"score": ["5"]}
        storage.set("ip", "192.168.1.1", data)

        storage.delete("ip", "192.168.1.1")

        retrieved = storage.get("ip", "192.168.1.1")
        assert retrieved is None

    def test_multiple_collections(self, storage):
        """Test storing multiple collection types."""
        ip_data = {"score": ["5"]}
        session_data = {"user": ["alice"]}

        storage.set("ip", "192.168.1.1", ip_data)
        storage.set("session", "abc123", session_data)

        assert storage.get("ip", "192.168.1.1") == ip_data
        assert storage.get("session", "abc123") == session_data

    def test_ttl_expiration(self, storage):
        """Test TTL expiration."""
        data = {"score": ["5"]}
        storage.set("ip", "192.168.1.1", data, ttl=1)  # 1 second TTL

        # Should exist immediately
        assert storage.get("ip", "192.168.1.1") == data

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert storage.get("ip", "192.168.1.1") is None

    def test_clear_expired(self, storage):
        """Test clearing expired collections."""
        # Create one with TTL and one without
        storage.set("ip", "192.168.1.1", {"score": ["5"]}, ttl=1)
        storage.set("ip", "192.168.1.2", {"score": ["10"]})  # No TTL

        time.sleep(1.1)

        removed = storage.clear_expired()
        assert removed == 1

        # Non-expired should still exist
        assert storage.get("ip", "192.168.1.2") is not None

    def test_update_ttl(self, storage):
        """Test updating collection with different TTL."""
        data = {"score": ["5"]}

        # Set with TTL
        storage.set("ip", "192.168.1.1", data, ttl=60)

        # Update with no TTL (should remove expiration)
        storage.set("ip", "192.168.1.1", data, ttl=0)

        # Check stats show no expiration
        stats = storage.get_stats()
        assert stats["total_with_expiration"] == 0

    def test_get_stats(self, storage):
        """Test getting storage statistics."""
        storage.set("ip", "192.168.1.1", {"score": ["5"]})
        storage.set("session", "abc123", {"user": ["alice"]})

        stats = storage.get_stats()
        assert stats["backend"] == "memory"
        assert stats["total_collections"] == 2
        assert "ip" in stats["collection_types"]
        assert "session" in stats["collection_types"]


class TestFileStorage:
    """Test FileStorage backend."""

    @pytest.fixture
    def storage_dir(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def storage(self, storage_dir):
        """Create FileStorage instance."""
        return FileStorage(storage_dir)

    def test_set_and_get(self, storage):
        """Test basic set and get with file storage."""
        data = {"score": ["5"], "count": ["10"]}
        storage.set("ip", "192.168.1.1", data)

        retrieved = storage.get("ip", "192.168.1.1")
        assert retrieved == data

    def test_persistence_across_instances(self, storage_dir):
        """Test data persists across storage instances."""
        # Create first instance and store data
        storage1 = FileStorage(storage_dir)
        data = {"score": ["5"]}
        storage1.set("ip", "192.168.1.1", data)

        # Create second instance and retrieve data
        storage2 = FileStorage(storage_dir)
        retrieved = storage2.get("ip", "192.168.1.1")
        assert retrieved == data

    def test_json_format(self, storage_dir):
        """Test using JSON format instead of pickle."""
        storage = FileStorage(storage_dir, use_json=True)
        data = {"score": ["5"], "count": ["10"]}
        storage.set("ip", "192.168.1.1", data)

        retrieved = storage.get("ip", "192.168.1.1")
        assert retrieved == data

    def test_ttl_expiration(self, storage):
        """Test TTL expiration with file storage."""
        data = {"score": ["5"]}
        storage.set("ip", "192.168.1.1", data, ttl=1)

        # Should exist immediately
        assert storage.get("ip", "192.168.1.1") == data

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired and file deleted
        assert storage.get("ip", "192.168.1.1") is None

    def test_clear_expired(self, storage):
        """Test clearing expired files."""
        storage.set("ip", "192.168.1.1", {"score": ["5"]}, ttl=1)
        storage.set("ip", "192.168.1.2", {"score": ["10"]})

        time.sleep(1.1)

        removed = storage.clear_expired()
        assert removed == 1

        # Non-expired should still exist
        assert storage.get("ip", "192.168.1.2") is not None

    def test_safe_filename_handling(self, storage):
        """Test that unsafe characters in keys are handled safely."""
        # Keys with slashes should be sanitized
        data = {"score": ["5"]}
        storage.set("ip", "192.168.1.1/24", data)

        # Should still be retrievable
        retrieved = storage.get("ip", "192.168.1.1/24")
        assert retrieved == data


class TestPersistentCollectionManager:
    """Test PersistentCollectionManager."""

    @pytest.fixture
    def storage(self):
        """Create storage backend."""
        return MemoryStorage()

    @pytest.fixture
    def manager(self, storage):
        """Create collection manager."""
        return PersistentCollectionManager(storage)

    @pytest.fixture
    def collection(self):
        """Create MapCollection."""
        return MapCollection("IP")

    def test_init_new_collection(self, manager, collection):
        """Test initializing a new collection."""
        manager.init_collection("ip", "192.168.1.1", collection)

        # Collection should be empty (no existing data)
        assert len(collection.find_all()) == 0

        # Should be tracked as loaded
        loaded = manager.get_loaded_collection("ip", "192.168.1.1")
        assert loaded is not None
        assert loaded.collection_name == "ip"
        assert loaded.key == "192.168.1.1"

    def test_init_existing_collection(self, manager, collection, storage):
        """Test initializing collection with existing data."""
        # Pre-populate storage
        existing_data = {
            "score": ["10"],
            "count": ["5"],
        }
        storage.set("ip", "192.168.1.1", existing_data)

        # Initialize collection
        manager.init_collection("ip", "192.168.1.1", collection)

        # Collection should be populated with stored data
        assert collection.get("score") == ["10"]
        assert collection.get("count") == ["5"]

    def test_persist_collections(self, manager, collection, storage):
        """Test persisting collections to storage."""
        # Initialize and modify collection
        manager.init_collection("ip", "192.168.1.1", collection, ttl=60)

        collection.add("score", "15")
        collection.add("count", "3")

        # Persist
        manager.persist_collections()

        # Verify data was saved to storage
        stored = storage.get("ip", "192.168.1.1")
        assert stored == {
            "score": ["15"],
            "count": ["3"],
        }

    def test_multiple_collections(self, manager, storage):
        """Test managing multiple persistent collections."""
        ip_collection = MapCollection("IP")
        session_collection = MapCollection("SESSION")

        manager.init_collection("ip", "192.168.1.1", ip_collection)
        manager.init_collection("session", "abc123", session_collection)

        ip_collection.add("score", "10")
        session_collection.add("user", "alice")

        manager.persist_collections()

        # Verify both were saved
        assert storage.get("ip", "192.168.1.1") == {"score": ["10"]}
        assert storage.get("session", "abc123") == {"user": ["alice"]}

    def test_ttl_passed_to_storage(self, manager, collection, storage):
        """Test that TTL is correctly passed to storage."""
        manager.init_collection("ip", "192.168.1.1", collection, ttl=300)

        collection.add("score", "10")
        manager.persist_collections()

        # Check that TTL was used (data exists)
        assert storage.get("ip", "192.168.1.1") is not None

        # Note: Exact TTL verification would require checking storage internals


class TestInitColAction:
    """Test initcol action integration."""

    @pytest.fixture
    def transaction(self):
        """Create mock transaction."""
        tx = Mock()
        tx.variables = TransactionVariables()
        tx.variables.remote_addr.set("192.168.1.100")
        tx.variables.tx.add("sessionid", "abc123")
        return tx

    def test_initcol_ip(self, transaction):
        """Test initcol for IP-based collection."""
        from lewaf.primitives.actions import InitColAction

        # Create action
        action = InitColAction()
        action.init({}, "ip=%{REMOTE_ADDR}")

        # Execute
        rule = Mock()
        rule.id = 1
        action.evaluate(rule, transaction)

        # Should create IP collection
        assert hasattr(transaction.variables, "ip")
        assert isinstance(transaction.variables.ip, MapCollection)

        # Should have collection manager
        assert hasattr(transaction, "collection_manager")

    def test_initcol_session(self, transaction):
        """Test initcol for session-based collection."""
        from lewaf.primitives.actions import InitColAction

        action = InitColAction()
        action.init({}, "session=%{TX.sessionid}")

        rule = Mock()
        rule.id = 1
        action.evaluate(rule, transaction)

        # Should create session collection
        assert hasattr(transaction.variables, "session")

    def test_initcol_with_ttl(self, transaction):
        """Test initcol with custom TTL."""
        from lewaf.primitives.actions import InitColAction

        action = InitColAction()
        action.init({}, "ip=%{REMOTE_ADDR},ttl=1800")

        assert action.ttl == 1800

    def test_initcol_persistence(self, transaction):
        """Test that initcol persists data across 'requests'."""
        from lewaf.primitives.actions import InitColAction
        from lewaf.storage import MemoryStorage, set_storage_backend

        # Use clean storage
        storage = MemoryStorage()
        set_storage_backend(storage)

        # First 'request'
        action = InitColAction()
        action.init({}, "ip=%{REMOTE_ADDR}")

        rule = Mock()
        rule.id = 1
        action.evaluate(rule, transaction)

        # Modify collection
        transaction.variables.ip.add("request_count", "1")

        # Persist
        transaction.collection_manager.persist_collections()

        # Second 'request' - new transaction
        transaction2 = Mock()
        transaction2.variables = TransactionVariables()
        transaction2.variables.remote_addr.set("192.168.1.100")  # Same IP

        action2 = InitColAction()
        action2.init({}, "ip=%{REMOTE_ADDR}")
        action2.evaluate(rule, transaction2)

        # Should have loaded previous data
        assert transaction2.variables.ip.get("request_count") == ["1"]


class TestSetSidAction:
    """Test setsid action."""

    @pytest.fixture
    def transaction(self):
        """Create mock transaction."""
        tx = Mock()
        tx.variables = TransactionVariables()
        tx.variables.request_cookies.add("phpsessid", "session123")
        return tx

    def test_setsid_from_cookie(self, transaction):
        """Test setting session ID from cookie."""
        from lewaf.primitives.actions import SetSidAction

        action = SetSidAction()
        action.init({}, "%{REQUEST_COOKIES.phpsessid}")

        rule = Mock()
        rule.id = 1
        action.evaluate(rule, transaction)

        # Should set TX.sessionid
        assert transaction.variables.tx.get("sessionid") == ["session123"]

    def test_setsid_then_initcol(self, transaction):
        """Test setsid followed by initcol."""
        from lewaf.primitives.actions import InitColAction, SetSidAction

        # Set session ID
        setsid_action = SetSidAction()
        setsid_action.init({}, "%{REQUEST_COOKIES.phpsessid}")

        rule = Mock()
        rule.id = 1
        setsid_action.evaluate(rule, transaction)

        # Initialize session collection
        initcol_action = InitColAction()
        initcol_action.init({}, "session=%{TX.sessionid}")
        initcol_action.evaluate(rule, transaction)

        # Should create session collection with correct key
        assert hasattr(transaction.variables, "session")


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_rate_limiting_per_ip(self):
        """Test rate limiting using persistent IP collection."""
        from lewaf.primitives.actions import InitColAction, SetVarAction
        from lewaf.storage import MemoryStorage, set_storage_backend

        # Setup
        storage = MemoryStorage()
        set_storage_backend(storage)

        # Simulate multiple requests from same IP
        for request_num in range(1, 6):
            # Create transaction
            tx = Mock()
            tx.variables = TransactionVariables()
            tx.variables.remote_addr.set("192.168.1.100")

            # Initialize IP collection
            initcol = InitColAction()
            initcol.init({}, "ip=%{REMOTE_ADDR}")

            rule = Mock()
            rule.id = 1
            initcol.evaluate(rule, tx)

            # Increment request count
            setvar = SetVarAction()
            setvar.init({}, "ip.request_count=+1")
            setvar.evaluate(rule, tx)

            # Persist
            tx.collection_manager.persist_collections()

            # Check count
            count_values = tx.variables.ip.get("request_count")
            current_count = int(count_values[0]) if count_values else 0

            assert current_count == request_num

    def test_session_anomaly_score(self):
        """Test tracking anomaly score per session."""
        from lewaf.primitives.actions import InitColAction, SetSidAction, SetVarAction
        from lewaf.storage import MemoryStorage, set_storage_backend

        storage = MemoryStorage()
        set_storage_backend(storage)

        # First request in session
        tx1 = Mock()
        tx1.variables = TransactionVariables()
        tx1.variables.request_cookies.add("sessionid", "abc123")

        rule = Mock()
        rule.id = 1

        # Set session ID
        setsid = SetSidAction()
        setsid.init({}, "%{REQUEST_COOKIES.sessionid}")
        setsid.evaluate(rule, tx1)

        # Initialize session collection
        initcol = InitColAction()
        initcol.init({}, "session=%{TX.sessionid}")
        initcol.evaluate(rule, tx1)

        # Set initial anomaly score
        setvar = SetVarAction()
        setvar.init({}, "session.anomaly_score=5")
        setvar.evaluate(rule, tx1)

        tx1.collection_manager.persist_collections()

        # Second request in same session
        tx2 = Mock()
        tx2.variables = TransactionVariables()
        tx2.variables.request_cookies.add("sessionid", "abc123")

        setsid.evaluate(rule, tx2)
        initcol.evaluate(rule, tx2)

        # Increment anomaly score
        setvar2 = SetVarAction()
        setvar2.init({}, "session.anomaly_score=+3")
        setvar2.evaluate(rule, tx2)

        # Should have cumulative score
        score = tx2.variables.session.get("anomaly_score")
        assert score == ["8"]  # 5 + 3
