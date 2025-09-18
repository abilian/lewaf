from __future__ import annotations

from urllib.parse import parse_qs

from coraza_poc.primitives.collections import TransactionVariables


class Transaction:
    def __init__(self, waf, id):
        self.id = id
        self.waf = waf
        self.variables = TransactionVariables()
        self.interruption: dict[str, str | int] | None = None
        self.current_phase = 0

    def process_uri(self, uri, method):
        self.variables.request_uri.set(uri)
        self.variables.request_method.set(method)
        if "?" in uri:
            qs = uri.split("?", 1)[1]
            for key, values in parse_qs(qs).items():
                for value in values:
                    self.variables.args.add(key, value)

    def process_request_headers(self):
        self.current_phase = 1
        self.waf.rule_group.evaluate(1, self)
        return self.interruption

    def process_request_body(self):
        self.current_phase = 2
        self.waf.rule_group.evaluate(2, self)
        return self.interruption

    def interrupt(self, rule):
        self.interruption = {"rule_id": rule.id, "action": "deny"}
