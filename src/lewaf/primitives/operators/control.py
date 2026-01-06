"""Control flow operators (unconditional, nomatch)."""

from __future__ import annotations

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    register_operator,
)


@register_operator("unconditional")
@register_operator("unconditionalmatch")  # Alias for Go compatibility
class UnconditionalOperatorFactory(OperatorFactory):
    """Factory for unconditional operators."""

    @staticmethod
    def create(options: OperatorOptions) -> UnconditionalOperator:
        return UnconditionalOperator(options.arguments)


class UnconditionalOperator(Operator):
    """Unconditional operator that always matches."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Always returns True."""
        return True


@register_operator("nomatch")
class NoMatchOperatorFactory(OperatorFactory):
    """Factory for NoMatch operators."""

    @staticmethod
    def create(options: OperatorOptions) -> NoMatchOperator:
        return NoMatchOperator(options.arguments)


class NoMatchOperator(Operator):
    """NoMatch operator that always returns false."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Always returns False."""
        return False
