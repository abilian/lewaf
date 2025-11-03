from __future__ import annotations

from urllib.parse import parse_qs

from lewaf.primitives.collections import TransactionVariables
from typing import Dict, Optional, Union, TYPE_CHECKING

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
