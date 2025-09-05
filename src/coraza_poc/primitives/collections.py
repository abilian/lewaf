class MatchData:
    def __init__(self, variable, key, value):
        self.variable = variable
        self.key = key
        self.value = value

    def __repr__(self):
        return f"MatchData(variable='{self.variable}', key='{self.key}', value='{self.value}')"

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
        self.request_uri = SingleValueCollection("REQUEST_URI")
