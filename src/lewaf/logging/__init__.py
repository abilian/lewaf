"""Audit logging and compliance features for LeWAF.

Public API:
    AuditLogger - Main audit logging class
    configure_audit_logging - Convenience setup function

Internal API (implementation details):
    Formatters, masking utilities, error loggers
"""

from __future__ import annotations

# Public API
# Internal API - exposed for advanced use cases
from lewaf.logging.audit import (
    AuditLogger,
    configure_audit_logging,
    get_audit_logger,
)
from lewaf.logging.error_logger import (
    log_body_processing_error,
    log_error,
    log_operator_error,
    log_storage_error,
    log_transformation_error,
)
from lewaf.logging.formatters import CompactJSONFormatter, JSONFormatter
from lewaf.logging.masking import (
    DataMasker,
    get_default_masker,
    mask_sensitive_data,
    set_masking_config,
)

# Only export the minimal public API
__all__ = [
    # Public API (stable for 1.0)
    "AuditLogger",
    # Internal API (may change between versions)
    "CompactJSONFormatter",
    "DataMasker",
    "JSONFormatter",
    "configure_audit_logging",
    "get_audit_logger",
    "get_default_masker",
    "log_body_processing_error",
    "log_error",
    "log_operator_error",
    "log_storage_error",
    "log_transformation_error",
    "mask_sensitive_data",
    "set_masking_config",
]
