"""Data masking utilities for compliance."""

import re
from typing import Any


class DataMasker:
    """Mask sensitive data for compliance (PCI-DSS, GDPR)."""

    # Regex patterns for sensitive data
    CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    EMAIL_PATTERN = re.compile(r"\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")
    IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    AUTH_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")

    def __init__(self, config: dict[str, bool] | None = None):
        """Initialize data masker.

        Args:
            config: Masking configuration
        """
        self.config = config or {
            "credit_card": True,
            "ssn": True,
            "email": False,
            "password": True,
            "auth_token": True,
            "ip_address": False,
        }

    def mask_credit_card(self, text: str) -> str:
        """Mask credit card numbers.

        Args:
            text: Text to mask

        Returns:
            Masked text (shows only last 4 digits)
        """
        def replace_card(match: re.Match) -> str:
            card = match.group(0).replace("-", "").replace(" ", "")
            return f"****-****-****-{card[-4:]}"

        return self.CREDIT_CARD_PATTERN.sub(replace_card, text)

    def mask_ssn(self, text: str) -> str:
        """Mask Social Security Numbers.

        Args:
            text: Text to mask

        Returns:
            Masked text (shows only last 4 digits)
        """
        def replace_ssn(match: re.Match) -> str:
            ssn = match.group(0)
            return f"***-**-{ssn[-4:]}"

        return self.SSN_PATTERN.sub(replace_ssn, text)

    def mask_email(self, text: str) -> str:
        """Mask email addresses.

        Args:
            text: Text to mask

        Returns:
            Masked text (shows first and last char of username)
        """
        def replace_email(match: re.Match) -> str:
            username = match.group(1)
            domain = match.group(2)
            if len(username) <= 2:
                masked_user = "*" * len(username)
            else:
                masked_user = username[0] + "*" * (len(username) - 2) + username[-1]
            return f"{masked_user}@{domain}"

        return self.EMAIL_PATTERN.sub(replace_email, text)

    def mask_ip_address(self, text: str) -> str:
        """Mask IP addresses (GDPR anonymization).

        Args:
            text: Text to mask

        Returns:
            Masked text (shows only network portion)
        """
        def replace_ip(match: re.Match) -> str:
            ip = match.group(0)
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        return self.IP_PATTERN.sub(replace_ip, text)

    def mask_auth_token(self, text: str) -> str:
        """Mask authentication tokens.

        Args:
            text: Text to mask

        Returns:
            Masked text (shows only first 8 chars)
        """
        def replace_token(match: re.Match) -> str:
            token = match.group(0)
            if len(token) > 8:
                return token[:8] + "...[REDACTED]"
            return "[REDACTED]"

        return self.AUTH_TOKEN_PATTERN.sub(replace_token, text)

    def mask_password(self, text: str) -> str:
        """Mask password fields.

        Args:
            text: Text to mask

        Returns:
            Masked text
        """
        # Always redact password values
        return "[REDACTED]"

    def mask(self, data: Any) -> Any:
        """Mask sensitive data in various formats.

        Args:
            data: Data to mask (str, dict, list)

        Returns:
            Masked data
        """
        if isinstance(data, str):
            return self._mask_string(data)
        elif isinstance(data, dict):
            return self._mask_dict(data)
        elif isinstance(data, list):
            return [self.mask(item) for item in data]
        else:
            return data

    def _mask_string(self, text: str) -> str:
        """Mask sensitive data in string.

        Args:
            text: String to mask

        Returns:
            Masked string
        """
        if self.config.get("credit_card"):
            text = self.mask_credit_card(text)

        if self.config.get("ssn"):
            text = self.mask_ssn(text)

        if self.config.get("email"):
            text = self.mask_email(text)

        if self.config.get("ip_address"):
            text = self.mask_ip_address(text)

        if self.config.get("auth_token"):
            text = self.mask_auth_token(text)

        return text

    def _mask_dict(self, data: dict) -> dict:
        """Mask sensitive data in dictionary.

        Args:
            data: Dictionary to mask

        Returns:
            Masked dictionary
        """
        masked = {}
        for key, value in data.items():
            # Mask password fields
            if "password" in key.lower() or "passwd" in key.lower():
                if self.config.get("password"):
                    masked[key] = "[REDACTED]"
                else:
                    masked[key] = value
            # Mask authorization headers
            elif "authorization" in key.lower() or "auth" in key.lower():
                if self.config.get("auth_token"):
                    masked[key] = self.mask_auth_token(str(value))
                else:
                    masked[key] = value
            # Recursively mask nested data
            else:
                masked[key] = self.mask(value)

        return masked


# Singleton instance
_default_masker: DataMasker | None = None


def get_default_masker() -> DataMasker:
    """Get default data masker instance.

    Returns:
        Default DataMasker instance
    """
    global _default_masker
    if _default_masker is None:
        _default_masker = DataMasker()
    return _default_masker


def set_masking_config(config: dict[str, bool]) -> None:
    """Configure default masker.

    Args:
        config: Masking configuration
    """
    global _default_masker
    _default_masker = DataMasker(config)


def mask_sensitive_data(data: Any) -> Any:
    """Mask sensitive data using default masker.

    Args:
        data: Data to mask

    Returns:
        Masked data
    """
    return get_default_masker().mask(data)
