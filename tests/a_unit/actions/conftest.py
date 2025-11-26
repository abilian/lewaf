"""Shared fixtures for action tests."""

from __future__ import annotations

import pytest

from tests.utils import MockRule, MockTransaction


@pytest.fixture
def mock_rule():
    """Create a mock rule for testing."""
    return MockRule()


@pytest.fixture
def mock_transaction():
    """Create a mock transaction for testing."""
    return MockTransaction()
