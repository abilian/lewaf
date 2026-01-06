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

# Import base classes and registry first
from __future__ import annotations

from ._base import (
    DATASETS,
    OPERATORS,
    Operator,
    OperatorFactory,
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
    BeginsWithOperatorFactory,
    ContainsOperator,
    ContainsOperatorFactory,
    EndsWithOperator,
    EndsWithOperatorFactory,
    EqOperator,
    EqOperatorFactory,
    GeOperator,
    GeOperatorFactory,
    GtOperator,
    GtOperatorFactory,
    LeOperator,
    LeOperatorFactory,
    LtOperator,
    LtOperatorFactory,
    StrEqOperator,
    StrEqOperatorFactory,
)
from .control import (
    NoMatchOperator,
    NoMatchOperatorFactory,
    UnconditionalOperator,
    UnconditionalOperatorFactory,
)
from .detection import (
    DetectSQLiOperator,
    DetectSQLiOperatorFactory,
    DetectXSSOperator,
    DetectXSSOperatorFactory,
)
from .inspection import (
    InspectFileOperator,
    InspectFileOperatorFactory,
)
from .matching import (
    PmFromDatasetOperator,
    PmFromDatasetOperatorFactory,
    PmFromFileOperator,
    PmFromFileOperatorFactory,
    PmOperator,
    PmOperatorFactory,
    RestPathOperator,
    RestPathOperatorFactory,
    RxOperator,
    RxOperatorFactory,
    StrMatchOperator,
    StrMatchOperatorFactory,
    WithinOperator,
    WithinOperatorFactory,
)
from .network import (
    GeoLookupOperator,
    GeoLookupOperatorFactory,
    IpMatchFromDatasetOperator,
    IpMatchFromDatasetOperatorFactory,
    IpMatchFromFileOperator,
    IpMatchFromFileOperatorFactory,
    IpMatchOperator,
    IpMatchOperatorFactory,
    RblOperator,
    RblOperatorFactory,
)
from .validation import (
    ValidateByteRangeOperator,
    ValidateByteRangeOperatorFactory,
    ValidateNidOperator,
    ValidateNidOperatorFactory,
    ValidateSchemaOperator,
    ValidateSchemaOperatorFactory,
    ValidateUrlEncodingOperator,
    ValidateUrlEncodingOperatorFactory,
    ValidateUtf8EncodingOperator,
    ValidateUtf8EncodingOperatorFactory,
)

__all__ = [
    # Base classes and utilities
    "DATASETS",
    "OPERATORS",
    "Operator",
    "OperatorFactory",
    "OperatorOptions",
    "TransactionProtocol",
    "get_dataset",
    "get_operator",
    "register_dataset",
    "register_operator",
    # Comparison operators
    "BeginsWithOperator",
    "BeginsWithOperatorFactory",
    "ContainsOperator",
    "ContainsOperatorFactory",
    "EndsWithOperator",
    "EndsWithOperatorFactory",
    "EqOperator",
    "EqOperatorFactory",
    "GeOperator",
    "GeOperatorFactory",
    "GtOperator",
    "GtOperatorFactory",
    "LeOperator",
    "LeOperatorFactory",
    "LtOperator",
    "LtOperatorFactory",
    "StrEqOperator",
    "StrEqOperatorFactory",
    # Control operators
    "NoMatchOperator",
    "NoMatchOperatorFactory",
    "UnconditionalOperator",
    "UnconditionalOperatorFactory",
    # Detection operators
    "DetectSQLiOperator",
    "DetectSQLiOperatorFactory",
    "DetectXSSOperator",
    "DetectXSSOperatorFactory",
    # Inspection operators
    "InspectFileOperator",
    "InspectFileOperatorFactory",
    # Matching operators
    "PmFromDatasetOperator",
    "PmFromDatasetOperatorFactory",
    "PmFromFileOperator",
    "PmFromFileOperatorFactory",
    "PmOperator",
    "PmOperatorFactory",
    "RestPathOperator",
    "RestPathOperatorFactory",
    "RxOperator",
    "RxOperatorFactory",
    "StrMatchOperator",
    "StrMatchOperatorFactory",
    "WithinOperator",
    "WithinOperatorFactory",
    # Network operators
    "GeoLookupOperator",
    "GeoLookupOperatorFactory",
    "IpMatchFromDatasetOperator",
    "IpMatchFromDatasetOperatorFactory",
    "IpMatchFromFileOperator",
    "IpMatchFromFileOperatorFactory",
    "IpMatchOperator",
    "IpMatchOperatorFactory",
    "RblOperator",
    "RblOperatorFactory",
    # Validation operators
    "ValidateByteRangeOperator",
    "ValidateByteRangeOperatorFactory",
    "ValidateNidOperator",
    "ValidateNidOperatorFactory",
    "ValidateSchemaOperator",
    "ValidateSchemaOperatorFactory",
    "ValidateUrlEncodingOperator",
    "ValidateUrlEncodingOperatorFactory",
    "ValidateUtf8EncodingOperator",
    "ValidateUtf8EncodingOperatorFactory",
]
