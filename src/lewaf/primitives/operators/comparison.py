"""String and numeric comparison operators."""

from __future__ import annotations

from ._base import (
    Operator,
    TransactionProtocol,
    register_operator,
)


@register_operator("eq")
class EqOperator(Operator):
    """Equality operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value equals the argument."""
        return value == self._argument


@register_operator("contains")
class ContainsOperator(Operator):
    """Contains substring operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value contains the argument substring."""
        return self._argument in value


@register_operator("beginswith")
class BeginsWithOperator(Operator):
    """Begins with operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value begins with the argument."""
        return value.startswith(self._argument)


@register_operator("endswith")
class EndsWithOperator(Operator):
    """Ends with operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value ends with the argument."""
        return value.endswith(self._argument)


@register_operator("gt")
class GtOperator(Operator):
    """Greater than operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is greater than the argument."""
        try:
            return float(value) > float(self._argument)
        except ValueError:
            return False


@register_operator("ge")
class GeOperator(Operator):
    """Greater than or equal operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is greater than or equal to the argument."""
        try:
            return float(value) >= float(self._argument)
        except ValueError:
            return False


@register_operator("lt")
class LtOperator(Operator):
    """Less than operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is less than the argument."""
        try:
            return float(value) < float(self._argument)
        except ValueError:
            return False


@register_operator("le")
class LeOperator(Operator):
    """Less than or equal operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is less than or equal to the argument."""
        try:
            return float(value) <= float(self._argument)
        except ValueError:
            return False


@register_operator("streq")
class StrEqOperator(Operator):
    """String equality operator (case sensitive)."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value exactly equals the argument."""
        return value == self._argument
