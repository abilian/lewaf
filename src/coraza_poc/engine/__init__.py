import logging

class RuleGroup:
    def __init__(self):
        self.rules_by_phase = {1: [], 2: [], 3: [], 4: [], 5: []}

    def add(self, rule):
        self.rules_by_phase[rule.phase].append(rule)
        logging.debug(f"Added rule {rule.id} to phase {rule.phase}")

    def evaluate(self, phase, transaction):
        logging.info(f"--- Executing Phase {phase} ---")
        for rule in self.rules_by_phase[phase]:
            rule.evaluate(transaction)
            if transaction.interruption:
                logging.warning(
                    f"Transaction interrupted by rule {transaction.interruption['rule_id']}. Halting phase."
                )
                return
