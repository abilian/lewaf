"""Base classes and protocols for operators."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

    from lewaf.primitives.collections import TransactionVariables


class TransactionProtocol(Protocol):
    """Protocol defining the transaction interface needed by operators."""

    variables: TransactionVariables

    def capturing(self) -> bool:
        """Return whether the transaction is capturing matches."""
        ...

    def capture_field(self, index: int, value: str) -> None:
        """Capture a field value at the given index."""
        ...


# Global operator registry
OPERATORS: dict[str, Any] = {}

# Simple dataset registry for SecDataset support
DATASETS: dict[str, list[str]] = {}


class OperatorOptions:
    """Options for creating operators, matching Go's OperatorOptions."""

    def __init__(
        self,
        arguments: str,
        path: list[str] | None = None,
        datasets: dict[str, list[str]] | None = None,
    ):
        self.arguments = arguments
        self.path = path or []
        self.datasets = datasets or {}


class Operator:
    """Base class for rule operators."""

    def __init__(self, argument: str):
        self._argument = argument

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Evaluate the operator against a value in the context of a transaction."""
        raise NotImplementedError


def register_operator(name: str) -> Callable:
    """Register an operator class by name."""

    def decorator(cls: type[Operator]) -> type[Operator]:
        OPERATORS[name.lower()] = cls
        return cls

    return decorator


def get_operator(name: str, options: OperatorOptions) -> Operator:
    """Get an operator instance by name."""
    if name.lower() not in OPERATORS:
        msg = f"Unknown operator: {name}"
        raise ValueError(msg)
    operator_cls = OPERATORS[name.lower()]
    return operator_cls(options.arguments)


def register_dataset(name: str, data: list[str]) -> None:
    """Register a dataset for use with dataset operators."""
    DATASETS[name] = data


def get_dataset(name: str) -> list[str]:
    """Get a dataset by name."""
    return DATASETS.get(name, [])
