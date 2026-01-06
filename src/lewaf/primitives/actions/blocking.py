"""Disruptive blocking actions (deny, allow, block, redirect, drop, exec)."""

from __future__ import annotations

import logging

from ._base import (
    Action,
    ActionType,
    RuleProtocol,
    TransactionProtocol,
    register_action,
)


@register_action("deny")
class DenyAction(Action):
    """Deny action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.warning(f"Executing DENY action from rule {rule.id}")
        transaction.interrupt(rule)


@register_action("allow")
class AllowAction(Action):
    """Allow action that permits the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.info(f"Rule {rule.id} allowing request")
        # Allow doesn't interrupt, it just permits


@register_action("block")
class BlockAction(Action):
    """Block action that blocks the request."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.warning(f"Blocking request due to rule {rule.id}")
        transaction.interrupt(rule)


@register_action("redirect")
class RedirectAction(Action):
    """Redirect action issues external redirection."""

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Redirect action requires a URL."""
        if not data:
            msg = "Redirect action requires a URL"
            raise ValueError(msg)
        self.redirect_url = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.warning(f"Rule {rule.id} redirecting to {self.redirect_url}")
        transaction.interrupt(rule, action="redirect", redirect_url=self.redirect_url)


@register_action("drop")
class DropAction(Action):
    """Drop action terminates connection.

    LIMITATION: True TCP connection termination requires low-level socket access
    that is not available in Python WSGI/ASGI middleware. This action behaves
    identically to 'deny' - it interrupts the transaction and returns an error
    response. The actual TCP connection may remain open depending on the server.

    For true connection dropping, you need:
    - Native server integration (nginx, Apache modules)
    - Low-level socket access not available in middleware

    In practice, 'deny' achieves the same security outcome in most cases.
    """

    def action_type(self) -> ActionType:
        return ActionType.DISRUPTIVE

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.warning(f"Rule {rule.id} dropping connection (via deny)")
        transaction.interrupt(rule, action="drop")


@register_action("exec")
class ExecAction(Action):
    """Exec action executes external command.

    SECURITY: This action is INTENTIONALLY DISABLED. Executing arbitrary shell
    commands from WAF rules is a significant security risk that can lead to:
    - Remote code execution vulnerabilities
    - Privilege escalation
    - System compromise

    This action is rarely needed in production. If you require external command
    execution, implement it through a secure, audited hook mechanism outside
    the WAF rule engine.

    The action is recognized for CRS compatibility but will only log a warning.
    """

    def action_type(self) -> ActionType:
        return ActionType.NONDISRUPTIVE

    def init(self, rule_metadata: dict, data: str) -> None:
        """Exec action requires a command."""
        if not data:
            msg = "Exec action requires a command"
            raise ValueError(msg)
        self.command = data

    def evaluate(self, rule: RuleProtocol, transaction: TransactionProtocol) -> None:
        logging.warning(f"Rule {rule.id} exec action disabled: {self.command}")
        logging.warning("SECURITY: exec action is intentionally disabled in LeWAF")
