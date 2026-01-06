"""Actions package for WAF rule evaluation.

This package provides all action implementations for the WAF engine.
Actions are organized by category:
- metadata: Rule metadata (id, phase, msg, severity, tag, etc.)
- blocking: Disruptive actions (deny, allow, block, redirect, drop, exec)
- logging_actions: Logging and capture (log, pass, nolog, capture, etc.)
- flow_control: Rule flow control (chain, skip, skipafter, conditional, ctl)
- variables: Variable management (setenv, setvar, deprecatevar, expirevar)
- collections: Persistent collections (initcol, setsid)
- transformation: Transformation pipeline (t:)

All actions are registered automatically on import and accessible via ACTIONS dict.
"""

# Import base classes and registry first
from __future__ import annotations

from ._base import (
    ACTIONS,
    Action,
    ActionType,
    MacroExpander,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)

# Import action implementations (registration happens on import)
from .blocking import (
    AllowAction,
    BlockAction,
    DenyAction,
    DropAction,
    ExecAction,
    RedirectAction,
)
from .collections import (
    InitColAction,
    SetSidAction,
)
from .flow_control import (
    ChainAction,
    ConditionalAction,
    CtlAction,
    SkipAction,
    SkipAfterAction,
    SkipNextAction,
)
from .logging_actions import (
    AuditLogAction,
    CaptureAction,
    LogAction,
    MultiMatchAction,
    NoAuditLogAction,
    NoLogAction,
    PassAction,
)
from .metadata import (
    AccuracyAction,
    IdAction,
    LogDataAction,
    MaturityAction,
    MsgAction,
    PhaseAction,
    RevAction,
    SeverityAction,
    StatusAction,
    TagAction,
    VerAction,
)
from .transformation import (
    TransformationAction,
)
from .variables import (
    DeprecateVarAction,
    ExpireVarAction,
    SetEnvAction,
    SetVarAction,
)

__all__ = [
    # Base classes and utilities
    "ACTIONS",
    "Action",
    "ActionType",
    "MacroExpander",
    "RuleProtocol",
    "TransactionProtocol",
    "register_action",
    # Metadata actions
    "AccuracyAction",
    "IdAction",
    "LogDataAction",
    "MaturityAction",
    "MsgAction",
    "PhaseAction",
    "RevAction",
    "SeverityAction",
    "StatusAction",
    "TagAction",
    "VerAction",
    # Blocking actions
    "AllowAction",
    "BlockAction",
    "DenyAction",
    "DropAction",
    "ExecAction",
    "RedirectAction",
    # Logging actions
    "AuditLogAction",
    "CaptureAction",
    "LogAction",
    "MultiMatchAction",
    "NoAuditLogAction",
    "NoLogAction",
    "PassAction",
    # Flow control actions
    "ChainAction",
    "ConditionalAction",
    "CtlAction",
    "SkipAction",
    "SkipAfterAction",
    "SkipNextAction",
    # Variable actions
    "DeprecateVarAction",
    "ExpireVarAction",
    "SetEnvAction",
    "SetVarAction",
    # Collection actions
    "InitColAction",
    "SetSidAction",
    # Transformation action
    "TransformationAction",
]
