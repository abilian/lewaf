"""String and numeric comparison operators."""

from __future__ import annotations

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    register_operator,
)


@register_operator("eq")
class EqOperatorFactory(OperatorFactory):
    """Factory for equality operators."""

    @staticmethod
    def create(options: OperatorOptions) -> EqOperator:
        return EqOperator(options.arguments)


class EqOperator(Operator):
    """Equality operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value equals the argument."""
        return value == self._argument


@register_operator("contains")
class ContainsOperatorFactory(OperatorFactory):
    """Factory for contains operators."""

    @staticmethod
    def create(options: OperatorOptions) -> ContainsOperator:
        return ContainsOperator(options.arguments)


class ContainsOperator(Operator):
    """Contains substring operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value contains the argument substring."""
        return self._argument in value


@register_operator("beginswith")
class BeginsWithOperatorFactory(OperatorFactory):
    """Factory for begins with operators."""

    @staticmethod
    def create(options: OperatorOptions) -> BeginsWithOperator:
        return BeginsWithOperator(options.arguments)


class BeginsWithOperator(Operator):
    """Begins with operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value begins with the argument."""
        return value.startswith(self._argument)


@register_operator("endswith")
class EndsWithOperatorFactory(OperatorFactory):
    """Factory for ends with operators."""

    @staticmethod
    def create(options: OperatorOptions) -> EndsWithOperator:
        return EndsWithOperator(options.arguments)


class EndsWithOperator(Operator):
    """Ends with operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value ends with the argument."""
        return value.endswith(self._argument)


@register_operator("gt")
class GtOperatorFactory(OperatorFactory):
    """Factory for greater than operators."""

    @staticmethod
    def create(options: OperatorOptions) -> GtOperator:
        return GtOperator(options.arguments)


class GtOperator(Operator):
    """Greater than operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is greater than the argument."""
        try:
            return float(value) > float(self._argument)
        except ValueError:
            return False


@register_operator("ge")
class GeOperatorFactory(OperatorFactory):
    """Factory for greater than or equal operators."""

    @staticmethod
    def create(options: OperatorOptions) -> GeOperator:
        return GeOperator(options.arguments)


class GeOperator(Operator):
    """Greater than or equal operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is greater than or equal to the argument."""
        try:
            return float(value) >= float(self._argument)
        except ValueError:
            return False


@register_operator("lt")
class LtOperatorFactory(OperatorFactory):
    """Factory for less than operators."""

    @staticmethod
    def create(options: OperatorOptions) -> LtOperator:
        return LtOperator(options.arguments)


class LtOperator(Operator):
    """Less than operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is less than the argument."""
        try:
            return float(value) < float(self._argument)
        except ValueError:
            return False


@register_operator("le")
class LeOperatorFactory(OperatorFactory):
    """Factory for less than or equal operators."""

    @staticmethod
    def create(options: OperatorOptions) -> LeOperator:
        return LeOperator(options.arguments)


class LeOperator(Operator):
    """Less than or equal operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is less than or equal to the argument."""
        try:
            return float(value) <= float(self._argument)
        except ValueError:
            return False


@register_operator("streq")
class StrEqOperatorFactory(OperatorFactory):
    """Factory for string equality operators."""

    @staticmethod
    def create(options: OperatorOptions) -> StrEqOperator:
        return StrEqOperator(options.arguments)


class StrEqOperator(Operator):
    """String equality operator (case sensitive)."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value exactly equals the argument."""
        return value == self._argument
