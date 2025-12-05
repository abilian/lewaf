"""Common fixtures and utilities for example tests."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

# Get examples directory
EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


def import_module_from_file(module_name: str, file_path: Path):
    """Import a module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec and spec.loader:
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    msg = f"Could not load module from {file_path}"
    raise ImportError(msg)


@pytest.fixture
def examples_dir():
    """Fixture providing the examples directory path."""
    return EXAMPLES_DIR
