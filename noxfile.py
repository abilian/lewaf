from __future__ import annotations

import nox

PYTHONS = ["3.10", "3.11", "3.12", "3.13", "3.14"]


@nox.session(python=PYTHONS)
def tests(session):
    # Note: we use 'uv' instead of 'pip' to make setup quicker
    # '--active' and 'external=True' are needed for proper setup
    session.run("uv", "sync", "--active", external=True)
    session.run("uv", "run", "--active", "pytest", external=True)


@nox.session(python=PYTHONS)
def examples(session):
    """Test all integration examples with their dependencies."""
    # Sync dev dependencies and examples dependency group
    session.run("uv", "sync", "--active", "--group", "examples", external=True)
    # Run only the examples tests
    session.run("uv", "run", "--active", "pytest", "tests/e_examples/", external=True)
