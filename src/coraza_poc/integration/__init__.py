from coraza_poc.primitives.operators import get_operator, OperatorOptions
from coraza_poc.primitives.actions import ACTIONS
from coraza_poc.engine import RuleGroup
from coraza_poc.rules import Rule
from coraza_poc.transaction import Transaction


class SecLangParser:
    def __init__(self, rule_group):
        self.rule_group = rule_group

    def from_string(self, rule_str):
        parts = rule_str.split('"')
        if len(parts) < 5 or not parts[0].strip().startswith("SecRule"):
            raise ValueError(f"Invalid rule format: {rule_str}")

        variables_str = parts[0].replace("SecRule", "").strip()
        operator_str = parts[1]
        actions_str = parts[3]

        parsed_vars = []
        for var in variables_str.split("|"):
            if ":" in var:
                var_name, key = var.split(":", 1)
                parsed_vars.append((var_name.upper(), key))
            else:
                parsed_vars.append((var.upper(), None))

        if operator_str.startswith("@"):
            parts = operator_str[1:].split(" ", 1)
            op_name = parts[0]
            op_arg = parts[1] if len(parts) > 1 else ""
        else:
            op_name, op_arg = "rx", operator_str

        try:
            options = OperatorOptions(op_arg)
            op_instance = get_operator(op_name, options)
            parsed_operator = type(
                "ParsedOperator",
                (),
                {"name": op_name, "argument": op_arg, "op": op_instance},
            )
        except ValueError as e:
            raise ValueError(f"Failed to create operator {op_name}: {e}") from e

        parsed_actions = {}
        parsed_transformations = []
        parsed_metadata = {}
        for action in actions_str.split(","):
            action = action.strip()
            key, _, value = action.partition(":")
            key = key.lower()

            if key == "t":
                parsed_transformations.append(value)
            else:
                action_class = ACTIONS.get(key)
                if not action_class:
                    raise ValueError(f"Unknown action: {key}")
                parsed_actions[key] = action_class(value)
                if key in ["id", "phase"]:
                    parsed_metadata[key] = int(value)

        rule = Rule(
            parsed_vars,
            parsed_operator,
            parsed_transformations,
            parsed_actions,
            parsed_metadata,
        )
        self.rule_group.add(rule)


class WAF:
    def __init__(self, config):
        self.rule_group = RuleGroup()
        self.parser = SecLangParser(self.rule_group)
        for rule_str in config["rules"]:
            self.parser.from_string(rule_str)
        self._tx_counter = 0

    def new_transaction(self):
        self._tx_counter += 1
        return Transaction(self, f"tx-{self._tx_counter}")
