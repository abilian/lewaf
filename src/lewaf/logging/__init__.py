"""Audit logging and compliance features for lewaf."""

from __future__ import annotations

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

__all__ = [
    "AuditLogger",
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
