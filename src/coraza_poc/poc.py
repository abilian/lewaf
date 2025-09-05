import re
import logging
from functools import lru_cache
from urllib.parse import parse_qs

# --- Layer 6: Supporting Services ---
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


@lru_cache(maxsize=128)
def compile_regex(pattern):
    logging.debug(f"Compiling regex: {pattern}")
    return re.compile(pattern)


# --- Layer 5: Data & Logic Primitives ---


# -- Collections --
class Collection:
    def __init__(self, name):
        self._name = name

    def name(self):
        return self._name

    def find_all(self):
        raise NotImplementedError


class MapCollection(Collection):
    def __init__(self, name, case_insensitive=True):
        super().__init__(name)
        self._data = {}
        self._case_insensitive = case_insensitive

    def add(self, key, value):
        if self._case_insensitive:
            key = key.lower()
        if key not in self._data:
            self._data[key] = []
        self._data[key].append(value)

    def get(self, key):
        if self._case_insensitive:
            key = key.lower()
        return self._data.get(key, [])

    def find_all(self):
        matches = []
        for key, values in self._data.items():
            for value in values:
                matches.append(MatchData(self._name, key, value))
        return matches

    def __str__(self):
        return f"{self._name}: {self._data}"


# CORRECTION: Added a SingleValueCollection for non-keyed variables like REQUEST_URI
class SingleValueCollection(Collection):
    def __init__(self, name):
        super().__init__(name)
        self._value = ""

    def set(self, value):
        self._value = value

    def get(self):
        return self._value

    def find_all(self):
        return [MatchData(self._name, "", self._value)]

    def __str__(self):
        return f"{self._name}: {self._value}"


class TransactionVariables:
    def __init__(self):
        self.args = MapCollection("ARGS")
        self.request_headers = MapCollection("REQUEST_HEADERS")
        self.tx = MapCollection("TX", case_insensitive=False)
        self.request_uri = SingleValueCollection(
            "REQUEST_URI"
        )  # CORRECTION: Use SingleValueCollection


# -- Transformations --
TRANSFORMATIONS = {}


def register_transformation(name):
    def decorator(fn):
        TRANSFORMATIONS[name.lower()] = fn
        return fn

    return decorator


@register_transformation("lowercase")
def lowercase(value):
    lower_val = value.lower()
    return lower_val, lower_val != value


# -- Operators --
OPERATORS = {}


class Operator:
    def __init__(self, argument):
        self._argument = argument

    def evaluate(self, tx, value):
        raise NotImplementedError


def register_operator(name):
    def decorator(cls):
        OPERATORS[name.lower()] = cls
        return cls

    return decorator


@register_operator("rx")
class RxOperator(Operator):
    def __init__(self, argument):
        super().__init__(argument)
        self._regex = compile_regex(argument)

    def evaluate(self, tx, value):
        return self._regex.search(value) is not None


# -- Actions --
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
        logging.info(f"Rule {rule.id} matched and logged.")


@register_action("deny")
class DenyAction(Action):
    def evaluate(self, rule, transaction):
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


# --- Layer 4: Rule Execution Layer ---


class MatchData:
    def __init__(self, variable, key, value):
        self.variable = variable
        self.key = key
        self.value = value

    def __repr__(self):
        return f"MatchData(variable='{self.variable}', key='{self.key}', value='{self.value}')"


class Rule:
    def __init__(self, variables, operator, transformations, actions, metadata):
        self.variables = variables
        self.operator = operator
        self.transformations = transformations
        self.actions = actions
        self.metadata = metadata
        self.id = metadata.get("id", 0)
        self.phase = metadata.get("phase", 1)

    def evaluate(self, transaction):
        logging.debug(
            f"Evaluating rule {self.id} in phase {transaction.current_phase}..."
        )

        values_to_test = []
        for var_name, key in self.variables:
            # CORRECTION: Handle both map and single value collections
            collection = getattr(transaction.variables, var_name.lower())
            if isinstance(collection, MapCollection):
                if key:
                    for value in collection.get(key):
                        values_to_test.append(value)
                else:
                    for match in collection.find_all():
                        values_to_test.append(match.value)
            elif isinstance(collection, SingleValueCollection):
                values_to_test.append(collection.get())

        for value in values_to_test:
            transformed_value = value
            for t_name in self.transformations:
                transformed_value, _ = TRANSFORMATIONS[t_name](transformed_value)

            logging.debug(
                f"  Testing operator '{self.operator.name}' with arg '{self.operator.argument}' against transformed value '{transformed_value}'"
            )
            if self.operator.op.evaluate(transaction, transformed_value):
                logging.info(
                    f"  MATCH! Rule {self.id} matched on value '{transformed_value}'"
                )
                for action in self.actions.values():
                    action.evaluate(self, transaction)
                return True
        return False


# --- Layer 3: Rule Processing Engine ---


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


# --- Layer 2: Transaction Management Layer ---


class Transaction:
    def __init__(self, waf, id):
        self.id = id
        self.waf = waf
        self.variables = TransactionVariables()
        self.interruption = None
        self.current_phase = 0

    def process_uri(self, uri, method):
        # CORRECTION: This method now correctly populates REQUEST_URI
        self.variables.request_uri.set(uri)
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


# --- Layer 1: Integration Layer ---


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
            op_name, op_arg = operator_str[1:].split(" ", 1)
        else:
            op_name, op_arg = "rx", operator_str

        operator_class = OPERATORS.get(op_name.lower())
        if not operator_class:
            raise ValueError(f"Unknown operator: {op_name}")
        op_instance = operator_class(op_arg)
        parsed_operator = type(
            "ParsedOperator",
            (),
            {"name": op_name, "argument": op_arg, "op": op_instance},
        )

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
