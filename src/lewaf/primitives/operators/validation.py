"""Validation operators (byte range, UTF-8, URL encoding, schema, NID)."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from lewaf.core import compile_regex

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    register_operator,
)


@register_operator("validatebyterange")
class ValidateByteRangeOperatorFactory(OperatorFactory):
    """Factory for byte range validation operators."""

    @staticmethod
    def create(options: OperatorOptions) -> ValidateByteRangeOperator:
        return ValidateByteRangeOperator(options.arguments)


class ValidateByteRangeOperator(Operator):
    """Validate byte range operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse byte ranges like "32-126,9,10,13" or "1-255"
        self._valid_bytes: set[int] = set()
        for part in argument.split(","):
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                self._valid_bytes.update(range(start, end + 1))
            else:
                self._valid_bytes.add(int(part))

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
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
    def create(options: OperatorOptions) -> ValidateUtf8EncodingOperator:
        return ValidateUtf8EncodingOperator(options.arguments)


class ValidateUtf8EncodingOperator(Operator):
    """UTF-8 encoding validation operator."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if value is valid UTF-8."""
        try:
            # If we can encode and decode it, it's valid UTF-8
            value.encode("utf-8").decode("utf-8")
            return True
        except UnicodeError:
            return False


@register_operator("validateurlencoding")
class ValidateUrlEncodingOperatorFactory(OperatorFactory):
    """Factory for ValidateUrlEncoding operators."""

    @staticmethod
    def create(options: OperatorOptions) -> ValidateUrlEncodingOperator:
        return ValidateUrlEncodingOperator(options.arguments)


class ValidateUrlEncodingOperator(Operator):
    """Validates URL-encoded characters in input."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if the input contains valid URL encoding."""
        # Find all percent-encoded sequences
        encoded_chars = re.findall(r"%[0-9A-Fa-f]{2}", value)

        for encoded_char in encoded_chars:
            try:
                # Try to decode the percent-encoded character
                hex_value = encoded_char[1:]  # Remove the %
                int(hex_value, 16)  # Validate it's a valid hex number
            except ValueError:
                # Invalid hex encoding found
                return True

        # Check for incomplete percent encodings (% followed by less than 2 hex chars)
        incomplete_pattern = r"%(?:[0-9A-Fa-f]?(?![0-9A-Fa-f])|(?![0-9A-Fa-f]))"
        return bool(re.search(incomplete_pattern, value))


@register_operator("validateschema")
class ValidateSchemaOperatorFactory(OperatorFactory):
    """Factory for ValidateSchema operators."""

    @staticmethod
    def create(options: OperatorOptions) -> ValidateSchemaOperator:
        return ValidateSchemaOperator(options.arguments)


class ValidateSchemaOperator(Operator):
    """Validates JSON/XML schema."""

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if the input is valid JSON or XML."""
        # Try JSON validation first
        try:
            json.loads(value)
            return False  # Valid JSON, no error
        except json.JSONDecodeError:
            pass

        # Try XML validation
        try:
            ET.fromstring(value)
            return False  # Valid XML, no error
        except ET.ParseError:
            pass

        # If neither JSON nor XML is valid, return True (validation failed)
        return True


@register_operator("validatenid")
class ValidateNidOperatorFactory(OperatorFactory):
    """Factory for ValidateNid operators."""

    @staticmethod
    def create(options: OperatorOptions) -> ValidateNidOperator:
        return ValidateNidOperator(options.arguments)


class ValidateNidOperator(Operator):
    """Validates National ID numbers for different countries.

    Syntax: @validateNid <country_code> <regex>
    Supported countries:
    - cl: Chilean RUT (Rol Único Tributario)
    - us: US Social Security Number
    """

    def __init__(self, argument: str):
        super().__init__(argument)
        # Parse argument: "country_code regex_pattern"
        parts = argument.split(None, 1)
        if len(parts) < 2:
            msg = "validateNid requires format: <country_code> <regex>"
            raise ValueError(msg)

        self._country_code = parts[0].lower()
        self._regex_pattern = parts[1]
        self._regex = compile_regex(self._regex_pattern)

        # Select validation function based on country code
        if self._country_code == "cl":
            self._validator = self._validate_cl
        elif self._country_code == "us":
            self._validator = self._validate_us
        else:
            msg = (
                f"Unsupported country code '{self._country_code}'. "
                "Supported: cl (Chile), us (USA)"
            )
            raise ValueError(msg)

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Find and validate National IDs in the input value."""
        matches = self._regex.findall(value)

        result = False
        for i, match in enumerate(matches[:10]):  # Max 10 matches
            if self._validator(match):
                result = True
                # Capture the valid NID
                tx.capture_field(i, match)

        return result

    def _validate_cl(self, nid: str) -> bool:
        """Validate Chilean RUT (Rol Único Tributario).

        Format: 12.345.678-9 or 12345678-9 or 123456789
        Uses modulo 11 checksum algorithm.
        """
        if len(nid) < 8:
            return False

        # Normalize: remove non-digits except 'k' or 'K'
        nid = nid.lower()
        nid = re.sub(r"[^\dk]", "", nid)

        if len(nid) < 2:
            return False

        # Split into number and verification digit
        rut_number = nid[:-1]
        dv = nid[-1]

        try:
            rut = int(rut_number)
        except ValueError:
            return False

        # Calculate verification digit using modulo 11
        total = 0
        factor = 2
        while rut > 0:
            total += (rut % 10) * factor
            rut //= 10
            if factor == 7:
                factor = 2
            else:
                factor += 1

        remainder = total % 11
        if remainder == 0:
            expected_dv = "0"
        elif remainder == 1:
            expected_dv = "k"
        else:
            expected_dv = str(11 - remainder)

        return dv == expected_dv

    def _validate_us(self, nid: str) -> bool:
        """Validate US Social Security Number.

        Format: 123-45-6789
        Rules:
        - Area (first 3 digits): 001-665, 667-899 (not 666)
        - Group (middle 2 digits): 01-99
        - Serial (last 4 digits): 0001-9999
        - No repeating digits (e.g., 111-11-1111)
        - No sequential digits (e.g., 123-45-6789 if truly sequential)
        """
        # Remove non-digits
        nid = re.sub(r"[^\d]", "", nid)

        if len(nid) < 9:
            return False

        try:
            area = int(nid[0:3])
            group = int(nid[3:5])
            serial = int(nid[5:9])
        except ValueError:
            return False

        # Validate area, group, serial ranges
        if area == 0 or group == 0 or serial == 0:
            return False
        if area >= 740 or area == 666:
            return False

        # Check for all same digits
        if len(set(nid[:9])) == 1:
            return False

        # Check for sequential digits
        is_sequential = True
        prev_digit = int(nid[0])
        for i in range(1, 9):
            curr_digit = int(nid[i])
            if curr_digit != prev_digit + 1:
                is_sequential = False
                break
            prev_digit = curr_digit

        return not is_sequential
