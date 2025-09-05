from coraza_poc.core import compile_regex

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
