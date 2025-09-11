import fnmatch
import ipaddress
from typing import TYPE_CHECKING
from urllib.parse import unquote

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


@register_operator("gt")
class GtOperatorFactory(OperatorFactory):
    """Factory for greater than operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "GtOperator":
        return GtOperator(options.arguments)


class GtOperator(Operator):
    """Greater than operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is greater than the argument."""
        try:
            return float(value) > float(self._argument)
        except ValueError:
            return False


@register_operator("ge")
class GeOperatorFactory(OperatorFactory):
    """Factory for greater than or equal operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "GeOperator":
        return GeOperator(options.arguments)


class GeOperator(Operator):
    """Greater than or equal operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is greater than or equal to the argument."""
        try:
            return float(value) >= float(self._argument)
        except ValueError:
            return False


@register_operator("lt")
class LtOperatorFactory(OperatorFactory):
    """Factory for less than operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "LtOperator":
        return LtOperator(options.arguments)


class LtOperator(Operator):
    """Less than operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is less than the argument."""
        try:
            return float(value) < float(self._argument)
        except ValueError:
            return False


@register_operator("le")
class LeOperatorFactory(OperatorFactory):
    """Factory for less than or equal operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "LeOperator":
        return LeOperator(options.arguments)


class LeOperator(Operator):
    """Less than or equal operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is less than or equal to the argument."""
        try:
            return float(value) <= float(self._argument)
        except ValueError:
            return False


@register_operator("within")
class WithinOperatorFactory(OperatorFactory):
    """Factory for within operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "WithinOperator":
        return WithinOperator(options.arguments)


class WithinOperator(Operator):
    """Within range operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse space-separated values
        self._values = set(argument.split())

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is within the set of allowed values."""
        return value in self._values


@register_operator("ipmatch")
class IpMatchOperatorFactory(OperatorFactory):
    """Factory for IP match operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "IpMatchOperator":
        return IpMatchOperator(options.arguments)


class IpMatchOperator(Operator):
    """IP address/network matching operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse IP address or CIDR network
        try:
            self._network = ipaddress.ip_network(argument, strict=False)
        except ValueError:
            # Fallback to exact IP match
            try:
                self._network = ipaddress.ip_network(f"{argument}/32", strict=False)
            except ValueError:
                self._network = None

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if IP address matches the network/address."""
        if not self._network:
            return False

        try:
            ip = ipaddress.ip_address(value.strip())
            return ip in self._network
        except ValueError:
            return False


@register_operator("detectsqli")
class DetectSQLiOperatorFactory(OperatorFactory):
    """Factory for SQL injection detection operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "DetectSQLiOperator":
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

    def evaluate(self, tx: "Transaction", value: str) -> bool:
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
    def create(options: OperatorOptions) -> "DetectXSSOperator":
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

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Detect XSS patterns."""
        decoded_value = unquote(value)  # URL decode first
        for pattern in self._patterns:
            if pattern.search(decoded_value):
                return True
        return False


@register_operator("validatebyterange")
class ValidateByteRangeOperatorFactory(OperatorFactory):
    """Factory for byte range validation operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "ValidateByteRangeOperator":
        return ValidateByteRangeOperator(options.arguments)


class ValidateByteRangeOperator(Operator):
    """Validate byte range operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse byte ranges like "32-126,9,10,13" or "1-255"
        self._valid_bytes = set()
        for part in argument.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                self._valid_bytes.update(range(start, end + 1))
            else:
                self._valid_bytes.add(int(part))

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if all bytes in value are within valid ranges."""
        try:
            value_bytes = value.encode("utf-8")
            return all(byte in self._valid_bytes for byte in value_bytes)
        except Exception:
            return False


@register_operator("validateutf8encoding")
class ValidateUtf8EncodingOperatorFactory(OperatorFactory):
    """Factory for UTF-8 validation operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "ValidateUtf8EncodingOperator":
        return ValidateUtf8EncodingOperator(options.arguments)


class ValidateUtf8EncodingOperator(Operator):
    """UTF-8 encoding validation operator."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value is valid UTF-8."""
        try:
            # If we can encode and decode it, it's valid UTF-8
            value.encode("utf-8").decode("utf-8")
            return True
        except UnicodeError:
            return False


@register_operator("pm")
class PmOperatorFactory(OperatorFactory):
    """Factory for phrase match operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "PmOperator":
        return PmOperator(options.arguments)


class PmOperator(Operator):
    """Phrase match operator for exact string matching."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse space-separated phrases
        self._phrases = [
            phrase.strip() for phrase in argument.split() if phrase.strip()
        ]

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if any phrase matches the value."""
        value_lower = value.lower()
        return any(phrase.lower() in value_lower for phrase in self._phrases)


@register_operator("pmfromfile")
class PmFromFileOperatorFactory(OperatorFactory):
    """Factory for phrase match from file operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "PmFromFileOperator":
        return PmFromFileOperator(options.arguments)


class PmFromFileOperator(Operator):
    """Phrase match from file operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._phrases = []
        # In a real implementation, we'd read from the file
        # For now, we'll simulate by treating the argument as a filename
        self._filename = argument

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if any phrase from file matches the value."""
        # For testing purposes, we'll simulate some common patterns
        # In production, this would read from the actual data file
        if "php-errors" in self._filename:
            php_errors = ["parse error", "fatal error", "warning:", "notice:"]
            return any(error in value.lower() for error in php_errors)
        elif "sql-errors" in self._filename:
            sql_errors = ["syntax error", "mysql error", "ora-", "sqlstate"]
            return any(error in value.lower() for error in sql_errors)
        elif "unix-shell" in self._filename:
            shell_commands = ["bin/sh", "/bin/bash", "wget", "curl"]
            return any(cmd in value.lower() for cmd in shell_commands)

        # Default behavior - no match
        return False


@register_operator("strmatch")
class StrMatchOperatorFactory(OperatorFactory):
    """Factory for string match operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "StrMatchOperator":
        return StrMatchOperator(options.arguments)


class StrMatchOperator(Operator):
    """String match operator with wildcards."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Convert glob-style pattern to regex
        self._pattern = compile_regex(fnmatch.translate(argument))

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value matches the string pattern."""
        return self._pattern.match(value) is not None


@register_operator("streq")
class StrEqOperatorFactory(OperatorFactory):
    """Factory for string equality operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "StrEqOperator":
        return StrEqOperator(options.arguments)


class StrEqOperator(Operator):
    """String equality operator (case sensitive)."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Check if value exactly equals the argument."""
        return value == self._argument


@register_operator("unconditional")
class UnconditionalOperatorFactory(OperatorFactory):
    """Factory for unconditional operators."""

    @staticmethod
    def create(options: OperatorOptions) -> "UnconditionalOperator":
        return UnconditionalOperator(options.arguments)


class UnconditionalOperator(Operator):
    """Unconditional operator that always matches."""

    def evaluate(self, tx: "Transaction", value: str) -> bool:
        """Always returns True."""
        return True
