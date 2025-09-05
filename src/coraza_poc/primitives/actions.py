ACTIONS = {}

class Action:
    def __init__(self, argument=None):
        self.argument = argument

    def evaluate(self, rule, transaction):
        raise NotImplementedError

def register_action(name):
    def decorator(cls):
        ACTIONS[name.lower()] = cls
        return cls
    return decorator

@register_action("log")
class LogAction(Action):
    def evaluate(self, rule, transaction):
        import logging
        logging.info(f"Rule {rule.id} matched and logged.")

@register_action("deny")
class DenyAction(Action):
    def evaluate(self, rule, transaction):
        import logging
        logging.warning(f"Executing DENY action from rule {rule.id}")
        transaction.interrupt(rule)

@register_action("id")
class IdAction(Action):
    def evaluate(self, rule, transaction):
        pass

@register_action("phase")
class PhaseAction(Action):
    def evaluate(self, rule, transaction):
        pass
