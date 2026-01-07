"""Operators package for WAF rule evaluation.

This package provides all operator implementations for the WAF engine.
Operators are organized by category:
- comparison: String and numeric comparisons (eq, gt, lt, contains, etc.)
- matching: Pattern matching (rx, pm, strmatch, restpath, etc.)
- network: IP/network operations (ipmatch, geolookup, rbl, etc.)
- validation: Input validation (validatebyterange, validateutf8encoding, etc.)
- detection: Threat detection (detectsqli, detectxss)
- control: Flow control (unconditional, nomatch)
- inspection: File inspection (inspectfile)

All operators are registered automatically on import and accessible via get_operator().
"""

from __future__ import annotations

from ._base import (
    DATASETS,
    OPERATORS,
    Operator,
    OperatorOptions,
    TransactionProtocol,
    get_dataset,
    get_operator,
    register_dataset,
    register_operator,
)

# Import operator implementations (registration happens on import)
from .comparison import (
    BeginsWithOperator,
    ContainsOperator,
    EndsWithOperator,
    EqOperator,
    GeOperator,
    GtOperator,
    LeOperator,
    LtOperator,
    StrEqOperator,
)
from .control import (
    NoMatchOperator,
    UnconditionalOperator,
)
from .detection import (
    DetectSQLiOperator,
    DetectXSSOperator,
)
from .inspection import (
    InspectFileOperator,
)
from .matching import (
    PmFromDatasetOperator,
    PmFromFileOperator,
    PmOperator,
    RestPathOperator,
    RxOperator,
    StrMatchOperator,
    WithinOperator,
)
from .network import (
    GeoLookupOperator,
    IpMatchFromDatasetOperator,
    IpMatchFromFileOperator,
    IpMatchOperator,
    RblOperator,
)
from .validation import (
    ValidateByteRangeOperator,
    ValidateNidOperator,
    ValidateSchemaOperator,
    ValidateUrlEncodingOperator,
    ValidateUtf8EncodingOperator,
)

__all__ = [
    # Base classes and utilities
    "DATASETS",
    "OPERATORS",
    "Operator",
    "OperatorOptions",
    "TransactionProtocol",
    "get_dataset",
    "get_operator",
    "register_dataset",
    "register_operator",
    # Comparison operators
    "BeginsWithOperator",
    "ContainsOperator",
    "EndsWithOperator",
    "EqOperator",
    "GeOperator",
    "GtOperator",
    "LeOperator",
    "LtOperator",
    "StrEqOperator",
    # Control operators
    "NoMatchOperator",
    "UnconditionalOperator",
    # Detection operators
    "DetectSQLiOperator",
    "DetectXSSOperator",
    # Inspection operators
    "InspectFileOperator",
    # Matching operators
    "PmFromDatasetOperator",
    "PmFromFileOperator",
    "PmOperator",
    "RestPathOperator",
    "RxOperator",
    "StrMatchOperator",
    "WithinOperator",
    # Network operators
    "GeoLookupOperator",
    "IpMatchFromDatasetOperator",
    "IpMatchFromFileOperator",
    "IpMatchOperator",
    "RblOperator",
    # Validation operators
    "ValidateByteRangeOperator",
    "ValidateNidOperator",
    "ValidateSchemaOperator",
    "ValidateUrlEncodingOperator",
    "ValidateUtf8EncodingOperator",
]
