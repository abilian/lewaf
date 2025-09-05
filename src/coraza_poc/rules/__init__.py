from coraza_poc.primitives.collections import MatchData, MapCollection, SingleValueCollection
from coraza_poc.primitives.transformations import TRANSFORMATIONS

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
        logging.debug("Evaluating rule %s in phase %s...", self.id, transaction.current_phase)

        values_to_test = []
        for var_name, key in self.variables:
            collection = getattr(transaction.variables, var_name.lower())
            if isinstance(collection, MapCollection):
                if key:
                    values_to_test.extend(collection.get(key))
                else:
                    values_to_test.extend(match.value for match in collection.find_all())
            elif isinstance(collection, SingleValueCollection):
                values_to_test.append(collection.get())

        for value in values_to_test:
            transformed_value = value
            for t_name in self.transformations:
                transformed_value, _ = TRANSFORMATIONS[t_name](transformed_value)

            logging.debug("Testing operator '%s' with arg '%s' against value '%s'", 
                         self.operator.name, self.operator.argument, transformed_value)
            
            if self.operator.op.evaluate(transaction, transformed_value):
                logging.info("MATCH! Rule %s matched on value '%s'", self.id, transformed_value)
                for action in self.actions.values():
                    action.evaluate(self, transaction)
                return True
        return False
