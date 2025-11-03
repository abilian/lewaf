from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Union
from urllib.parse import parse_qs

from lewaf.primitives.collections import TransactionVariables

if TYPE_CHECKING:
    from lewaf.integration import WAF
    from lewaf.rules import Rule


class Transaction:
    def __init__(self, waf: WAF, id: str):
        self.id = id
        self.waf = waf
        self.variables = TransactionVariables()
        self.interruption: dict[str, str | int] | None = None
        self.current_phase = 0

        # State attributes for advanced actions (Phase 6)
        self.chain_state: dict[str, Any] = {}
        self.skip_state: dict[str, Any] = {}
        self.multimatch_state: dict[str, Any] = {}
        self.deprecated_vars: set[str] = set()
        self.var_expiration: dict[str, float] = {}
        self.ctl_directives: dict[str, Any] = {}

        # Engine control attributes
        self.rule_engine_enabled: bool = True
        self.rule_engine_mode: str = "on"
        self.body_processor: str = "URLENCODED"
        self.body_limit: int = 131072

    def process_uri(self, uri: str, method: str):
        self.variables.request_uri.set(uri)
        self.variables.request_method.set(method)
        # Set default HTTP protocol version
        self.variables.request_protocol.set("HTTP/1.1")
        if "?" in uri:
            qs = uri.split("?", 1)[1]
            for key, values in parse_qs(qs).items():
                for value in values:
                    self.variables.args.add(key, value)

    def process_request_headers(self) -> Optional[Dict[str, Union[str, int]]]:
        self.current_phase = 1
        self.waf.rule_group.evaluate(1, self)
        return self.interruption

    def process_request_body(self) -> Optional[Dict[str, Union[str, int]]]:
        self.current_phase = 2
        self.waf.rule_group.evaluate(2, self)
        return self.interruption

    def interrupt(self, rule: Rule):
        self.interruption = {"rule_id": rule.id, "action": "deny"}

    def capturing(self) -> bool:
        """Return whether the transaction is capturing matches."""
        # For now, always return False. This can be extended later.
        return False

    def capture_field(self, index: int, value: str) -> None:
        """Capture a field value at the given index."""
        # Placeholder implementation - can be extended to store captures
        pass
