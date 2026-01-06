"""Logging actions (log, pass, nolog, auditlog, noauditlog, capture, multimatch)."""

from __future__ import annotations

import logging

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("log")
class LogAction(Action):
    """Log action for rule matches."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.info(f"Rule {rule.id} matched and logged.")


@register_action("pass")
class PassAction(Action):
    """Pass action allows the request to continue."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.debug(f"Rule {rule.id} matched but allowed to pass")
        # Pass action does nothing - just allows the request to continue


@register_action("nolog")
class NoLogAction(Action):
    """No log action prevents logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # This action prevents logging, handled at framework level
        pass


@register_action("auditlog")
class AuditLogAction(Action):
    """Audit log action marks transaction for logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.info(f"Rule {rule.id} marked transaction for audit logging")
        transaction.force_audit_log = True


@register_action("noauditlog")
class NoAuditLogAction(Action):
    """No audit log action prevents audit logging."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.debug(f"Rule {rule.id} disabled audit logging for transaction")
        transaction.audit_log_enabled = False


@register_action("capture")
class CaptureAction(Action):
    """Capture action for capturing matched groups."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Capture functionality handled by operators
        pass


@register_action("multimatch")
class MultiMatchAction(Action):
    """Multi-match action for multiple pattern matching."""

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        # Multi-match logic handled by operators
        if not hasattr(transaction, "multimatch_state"):
            transaction.multimatch_state = {}
        transaction.multimatch_state["enabled"] = True
