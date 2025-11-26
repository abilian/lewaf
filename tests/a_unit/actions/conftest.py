"""Shared fixtures for action tests."""

from __future__ import annotations

import pytest

from tests.utils import StubRule, StubTransaction


@pytest.fixture
def mock_rule():
    """Create a mock rule for testing."""
    return StubRule()


@pytest.fixture
def mock_transaction():
    """Create a mock transaction for testing."""
    return StubTransaction()
