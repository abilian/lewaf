"""Threat detection operators (SQL injection, XSS)."""

from __future__ import annotations

from urllib.parse import unquote

from lewaf.core import compile_regex

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    register_operator,
)


@register_operator("detectsqli")
class DetectSQLiOperatorFactory(OperatorFactory):
    """Factory for SQL injection detection operators."""

    @staticmethod
    def create(options: OperatorOptions) -> DetectSQLiOperator:
        return DetectSQLiOperator(options.arguments)


class DetectSQLiOperator(Operator):
    """SQL injection detection operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Common SQL injection patterns
        self._patterns = [
            compile_regex(r"(?i)(union\s+select|select\s+.*\s+from)"),
            compile_regex(r"(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)"),
            compile_regex(r"(?i)(drop\s+table|delete\s+from|insert\s+into)"),
            compile_regex(r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)"),
            compile_regex(r"(?i)['\"][\s]*(\s*or\s+|--|\s*union\s+)"),
            compile_regex(r"(?i)(having\s+|group\s+by\s+|order\s+by\s+)"),
        ]

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Detect SQL injection patterns."""
        decoded_value = unquote(value)  # URL decode first
        for pattern in self._patterns:
            if pattern.search(decoded_value):
                return True
        return False


@register_operator("detectxss")
class DetectXSSOperatorFactory(OperatorFactory):
    """Factory for XSS detection operators."""

    @staticmethod
    def create(options: OperatorOptions) -> DetectXSSOperator:
        return DetectXSSOperator(options.arguments)


class DetectXSSOperator(Operator):
    """XSS detection operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Common XSS patterns
        self._patterns = [
            compile_regex(r"(?i)<script[^>]*>"),
            compile_regex(r"(?i)javascript:"),
            compile_regex(r"(?i)on\w+\s*="),  # event handlers
            compile_regex(r"(?i)<iframe[^>]*>"),
            compile_regex(r"(?i)document\.cookie"),
            compile_regex(r"(?i)alert\s*\("),
            compile_regex(r"(?i)eval\s*\("),
            compile_regex(r"(?i)<object[^>]*>"),
            compile_regex(r"(?i)<embed[^>]*>"),
        ]

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Detect XSS patterns."""
        decoded_value = unquote(value)  # URL decode first
        for pattern in self._patterns:
            if pattern.search(decoded_value):
                return True
        return False
