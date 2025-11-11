"""Audit logging and compliance features for lewaf."""

from __future__ import annotations

from lewaf.logging.audit import (
    AuditLogger,
    configure_audit_logging,
    get_audit_logger,
)
from lewaf.logging.formatters import CompactJSONFormatter, JSONFormatter
from lewaf.logging.masking import (
    DataMasker,
    get_default_masker,
    mask_sensitive_data,
    set_masking_config,
)

__all__ = [
    "AuditLogger",
    "configure_audit_logging",
    "get_audit_logger",
    "JSONFormatter",
    "CompactJSONFormatter",
    "DataMasker",
    "get_default_masker",
    "mask_sensitive_data",
    "set_masking_config",
]
