from coraza_poc.primitives.collections import MatchData

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
        import logging
        logging.debug(
            f"Evaluating rule {self.id} in phase {transaction.current_phase}..."
        )

        values_to_test = []
        for var_name, key in self.variables:
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
