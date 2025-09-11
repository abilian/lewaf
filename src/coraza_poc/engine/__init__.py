import logging


class RuleGroup:
    def __init__(self):
        self.rules_by_phase = {1: [], 2: [], 3: [], 4: [], 5: []}

    def add(self, rule):
        self.rules_by_phase[rule.phase].append(rule)
        logging.debug("Added rule %s to phase %s", rule.id, rule.phase)

    def evaluate(self, phase, transaction):
        logging.info("--- Executing Phase %s ---", phase)
        for rule in self.rules_by_phase[phase]:
            rule.evaluate(transaction)
            if transaction.interruption:
                logging.warning(
                    "Transaction interrupted by rule %s. Halting phase.",
                    transaction.interruption["rule_id"],
                )
                return
