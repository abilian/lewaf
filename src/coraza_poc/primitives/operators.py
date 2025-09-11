from typing import TYPE_CHECKING
from coraza_poc.core import compile_regex

if TYPE_CHECKING:
    from coraza_poc.transaction import Transaction

OPERATORS = {}


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

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Evaluate the operator against a value in the context of a transaction."""
        raise NotImplementedError


class OperatorFactory:
    """Factory function type for creating operators."""

    @staticmethod
    def create(options: OperatorOptions) -> Operator:
        raise NotImplementedError


def register_operator(name: str):
    """Register an operator factory by name."""

    def decorator(factory_cls):
        OPERATORS[name.lower()] = factory_cls
        return factory_cls

    return decorator


def get_operator(name: str, options: OperatorOptions) -> Operator:
    """Get an operator instance by name."""
    if name.lower() not in OPERATORS:
        raise ValueError(f"Unknown operator: {name}")
    factory = OPERATORS[name.lower()]
    return factory.create(options)


@register_operator("rx")
class RxOperatorFactory(OperatorFactory):
    """Factory for regex operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "RxOperator":
        return RxOperator(options.arguments)


class RxOperator(Operator):
    """Regular expression operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._regex = compile_regex(argument)

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Evaluate regex against the value."""
        if hasattr(tx, "capturing") and tx.capturing():
            # Handle capture groups if transaction supports it
            match = self._regex.search(value)
            if match:
                for i, group in enumerate(
                    match.groups()[:9]
                ):  # Max 9 capture groups like Go
                    if hasattr(tx, "capture_field"):
                        tx.capture_field(i + 1, group if group is not None else "")
                return True
            return False
        else:
            return self._regex.search(value) is not None


@register_operator("eq")
class EqOperatorFactory(OperatorFactory):
    """Factory for equality operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "EqOperator":
        return EqOperator(options.arguments)


class EqOperator(Operator):
    """Equality operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value equals the argument."""
        return value == self._argument


@register_operator("contains")
class ContainsOperatorFactory(OperatorFactory):
    """Factory for contains operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "ContainsOperator":
        return ContainsOperator(options.arguments)


class ContainsOperator(Operator):
    """Contains substring operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value contains the argument substring."""
        return self._argument in value


@register_operator("beginswith")
class BeginsWithOperatorFactory(OperatorFactory):
    """Factory for begins with operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "BeginsWithOperator":
        return BeginsWithOperator(options.arguments)


class BeginsWithOperator(Operator):
    """Begins with operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value begins with the argument."""
        return value.startswith(self._argument)


@register_operator("endswith")
class EndsWithOperatorFactory(OperatorFactory):
    """Factory for ends with operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "EndsWithOperator":
        return EndsWithOperator(options.arguments)


class EndsWithOperator(Operator):
    """Ends with operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value ends with the argument."""
        return value.endswith(self._argument)
