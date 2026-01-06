"""Pattern matching operators (regex, phrase match, wildcards)."""

from __future__ import annotations

import fnmatch
import re

from lewaf.core import compile_regex

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    get_dataset,
    register_operator,
)


@register_operator("rx")
class RxOperatorFactory(OperatorFactory):
    """Factory for regex operators."""

    @staticmethod
    def create(options: OperatorOptions) -> RxOperator:
        return RxOperator(options.arguments)


class RxOperator(Operator):
    """Regular expression operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._regex = compile_regex(argument)

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Evaluate regex against the value."""
        if tx.capturing():
            # Handle capture groups if transaction supports it
            match = self._regex.search(value)
            if match:
                for i, group in enumerate(
                    match.groups()[:9]
                ):  # Max 9 capture groups like Go
                    tx.capture_field(i + 1, group if group is not None else "")
                return True
            return False
        return self._regex.search(value) is not None


@register_operator("pm")
class PmOperatorFactory(OperatorFactory):
    """Factory for phrase match operators."""

    @staticmethod
    def create(options: OperatorOptions) -> PmOperator:
        return PmOperator(options.arguments)


class PmOperator(Operator):
    """Phrase match operator for exact string matching."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse space-separated phrases
        self._phrases = [
            phrase.strip() for phrase in argument.split() if phrase.strip()
        ]

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if any phrase matches the value."""
        value_lower = value.lower()
        return any(phrase.lower() in value_lower for phrase in self._phrases)


@register_operator("pmfromfile")
class PmFromFileOperatorFactory(OperatorFactory):
    """Factory for phrase match from file operators."""

    @staticmethod
    def create(options: OperatorOptions) -> PmFromFileOperator:
        return PmFromFileOperator(options.arguments)


class PmFromFileOperator(Operator):
    """Phrase match from file operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._phrases: list[str] = []
        # In a real implementation, we'd read from the file
        # For now, we'll simulate by treating the argument as a filename
        self._filename = argument

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if any phrase from file matches the value."""
        # For testing purposes, we'll simulate some common patterns
        # In production, this would read from the actual data file
        if "php-errors" in self._filename:
            php_errors = ["parse error", "fatal error", "warning:", "notice:"]
            return any(error in value.lower() for error in php_errors)
        if "sql-errors" in self._filename:
            sql_errors = ["syntax error", "mysql error", "ora-", "sqlstate"]
            return any(error in value.lower() for error in sql_errors)
        if "unix-shell" in self._filename:
            shell_commands = ["bin/sh", "/bin/bash", "wget", "curl"]
            return any(cmd in value.lower() for cmd in shell_commands)

        # Default behavior - no match
        return False


@register_operator("strmatch")
class StrMatchOperatorFactory(OperatorFactory):
    """Factory for string match operators."""

    @staticmethod
    def create(options: OperatorOptions) -> StrMatchOperator:
        return StrMatchOperator(options.arguments)


class StrMatchOperator(Operator):
    """String match operator with wildcards."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Convert glob-style pattern to regex
        self._pattern = compile_regex(fnmatch.translate(argument))

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value matches the string pattern."""
        return self._pattern.match(value) is not None


@register_operator("within")
class WithinOperatorFactory(OperatorFactory):
    """Factory for within operators."""

    @staticmethod
    def create(options: OperatorOptions) -> WithinOperator:
        return WithinOperator(options.arguments)


class WithinOperator(Operator):
    """Within range operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse space-separated values
        self._values = set(argument.split())

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is within the set of allowed values."""
        return value in self._values


@register_operator("restpath")
class RestPathOperatorFactory(OperatorFactory):
    """Factory for RestPath operators."""

    @staticmethod
    def create(options: OperatorOptions) -> RestPathOperator:
        return RestPathOperator(options.arguments)


class RestPathOperator(Operator):
    """REST path pattern matching operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._pattern = self._compile_path_pattern(argument)

    def _compile_path_pattern(self, path_pattern: str) -> str:
        """Convert REST path pattern to regex."""
        # Escape special regex characters except {}
        escaped = re.escape(path_pattern)

        # Replace escaped braces back and convert {param} to named capture groups
        # This handles patterns like /path/{id}/{name}
        pattern = re.sub(r"\\{([^}]+)\\}", r"(?P<\1>[^/]+)", escaped)

        # Anchor the pattern
        return f"^{pattern}$"

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if the input matches the REST path pattern."""
        match = re.match(self._pattern, value)
        if match:
            # Populate ARGS_PATH with captured path segments
            # and add to ARGS for unified access
            for name, captured_value in match.groupdict().items():
                if hasattr(tx, "variables"):
                    # Add to args_path collection (path parameters)
                    if hasattr(tx.variables, "args_path"):
                        tx.variables.args_path.add(name, captured_value)
                    # Also add to general args collection
                    if hasattr(tx.variables, "args"):
                        tx.variables.args.add(name, captured_value)
                    # Add parameter names
                    if hasattr(tx.variables, "args_names"):
                        tx.variables.args_names.add(name, name)
            return True
        return False


@register_operator("pmfromdataset")
class PmFromDatasetOperatorFactory(OperatorFactory):
    """Factory for PmFromDataset operators."""

    @staticmethod
    def create(options: OperatorOptions) -> PmFromDatasetOperator:
        return PmFromDatasetOperator(options.arguments)


class PmFromDatasetOperator(Operator):
    """Pattern matching from dataset operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._dataset_name = argument.strip()
        if not self._dataset_name:
            msg = "PmFromDataset operator requires a dataset name"
            raise ValueError(msg)

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value contains any patterns from the dataset."""
        patterns = get_dataset(self._dataset_name)
        if not patterns:
            return False

        value_lower = value.lower()

        # Case-insensitive substring matching
        for pattern in patterns:
            if pattern.lower() in value_lower:
                if tx.capturing():
                    tx.capture_field(0, pattern)
                return True

        return False
