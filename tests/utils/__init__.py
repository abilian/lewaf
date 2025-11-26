"""Utility modules for production testing."""

from __future__ import annotations

from typing import Any


class MockOperatorTransaction:
    """Minimal mock transaction for operator testing.

    Satisfies the TransactionProtocol for operators which only needs
    capturing and capture_field methods.
    """

    def __init__(self):
        self.captured_fields: dict[int, str] = {}
        self._capturing = False

    def capturing(self) -> bool:
        """Return whether the transaction is capturing matches."""
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        """Capture a field value at the given index."""
        self.captured_fields[index] = value


class MockTransactionVariables:
    """Mock transaction variables for testing."""

    def __init__(self):
        self._vars: dict[str, str] = {}
        self.tx = MockTxCollection()
        self.ip = MockCollection()
        self.session = MockCollection()
        self.user = MockCollection()
        self.global_ = MockCollection()
        self.resource = MockCollection()

    def get(self, name: str) -> str:
        return self._vars.get(name, "")

    def set(self, name: str, value: str) -> None:
        self._vars[name] = value


class MockCollection:
    """Mock collection for testing."""

    def __init__(self):
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str:
        return self._data.get(key, "")

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)


class MockTxCollection(MockCollection):
    """Mock TX collection for testing."""


class MockRule:
    """Mock rule for testing that satisfies RuleProtocol."""

    def __init__(self, rule_id: int = 1):
        self.id = rule_id
        self.msg = "Test rule message"
        self.phase = 2
        self.severity = 2
        self.log_data = ""
        self.tags: list[str] = []


class MockTransaction:
    """Mock transaction for testing that satisfies TransactionProtocol."""

    def __init__(self):
        # State attributes
        self.chain_state: dict[str, Any] = {}
        self.skip_state: dict[str, Any] = {}
        self.multimatch_state: dict[str, Any] = {}
        self.deprecated_vars: set[str] = set()
        self.var_expiration: dict[str, float] = {}
        self.ctl_directives: dict[str, Any] = {}
        self.collection_manager: Any = None

        # Engine control attributes
        self.rule_engine_enabled: bool = True
        self.rule_engine_mode: str = "On"
        self.body_processor: str = ""
        self.body_limit: int = 131072

        # Variables
        self.variables = MockTransactionVariables()

        # Additional state for testing
        self._interrupted = False
        self._interrupt_rule: MockRule | None = None

    def interrupt(self, rule: MockRule) -> None:
        """Interrupt the transaction with the given rule."""
        self._interrupted = True
        self._interrupt_rule = rule


# Singleton instance for simple tests that don't need state
_STUB_OP_TX = MockOperatorTransaction()


def stub_tx() -> MockOperatorTransaction:
    """Get a stub transaction for simple operator tests.

    Returns a singleton for tests that don't need state tracking.
    For tests that need to check captured fields, create a new instance.
    """
    return _STUB_OP_TX
