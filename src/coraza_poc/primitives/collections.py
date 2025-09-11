import re
from typing import List


class MatchData:
    """Represents a match from a collection with variable name, key, and value."""

    def __init__(self, variable: str, key: str, value: str):
        self.variable = variable
        self.key = key
        self.value = value

    def __repr__(self):
        return f"MatchData(variable='{self.variable}', key='{self.key}', value='{self.value}')"


class Collection:
    """Base class for WAF collections."""

    def __init__(self, name: str):
        self._name = name

    def name(self) -> str:
        """Return the name of this collection."""
        return self._name

    def find_all(self) -> List[MatchData]:
        """Return all matches in this collection."""
        raise NotImplementedError


class MapCollection(Collection):
    """Collection for key-value pairs like request headers or arguments."""

    def __init__(self, name: str, case_insensitive: bool = True):
        super().__init__(name)
        self._data: dict[str, List[str]] = {}
        self._case_insensitive = case_insensitive

    def add(self, key: str, value: str) -> None:
        """Add a value to the given key."""
        if self._case_insensitive:
            key = key.lower()
        if key not in self._data:
            self._data[key] = []
        self._data[key].append(value)

    def get(self, key: str) -> List[str]:
        """Get all values for the given key."""
        if self._case_insensitive:
            key = key.lower()
        return self._data.get(key, [])

    def set(self, key: str, values: List[str]) -> None:
        """Replace the key's values with the provided list."""
        if self._case_insensitive:
            key = key.lower()
        self._data[key] = values.copy()

    def remove(self, key: str) -> None:
        """Remove the key from the collection."""
        if self._case_insensitive:
            key = key.lower()
        self._data.pop(key, None)

    def find_regex(self, pattern: re.Pattern[str]) -> List[MatchData]:
        """Find all matches where the key matches the regex pattern."""
        matches = []
        for key, values in self._data.items():
            if pattern.search(key):
                for value in values:
                    matches.append(MatchData(self._name, key, value))
        return matches

    def find_string(self, search_key: str) -> List[MatchData]:
        """Find all matches for the exact key string."""
        if self._case_insensitive:
            search_key = search_key.lower()
        matches = []
        if search_key in self._data:
            for value in self._data[search_key]:
                matches.append(MatchData(self._name, search_key, value))
        return matches

    def find_all(self) -> List[MatchData]:
        """Return all key-value pairs as MatchData objects."""
        matches = []
        for key, values in self._data.items():
            for value in values:
                matches.append(MatchData(self._name, key, value))
        return matches

    def __str__(self):
        return f"{self._name}: {self._data}"


class SingleValueCollection(Collection):
    """Collection for single values like REQUEST_URI."""

    def __init__(self, name: str):
        super().__init__(name)
        self._value = ""

    def set(self, value: str) -> None:
        """Set the single value for this collection."""
        self._value = value

    def get(self) -> str:
        """Get the single value of this collection."""
        return self._value

    def find_all(self) -> List[MatchData]:
        """Return the single value as a MatchData object."""
        return [MatchData(self._name, "", self._value)]

    def __str__(self):
        return f"{self._name}: {self._value}"


class TransactionVariables:
    """Container for all transaction variables used in WAF rules."""

    def __init__(self):
        self.args = MapCollection("ARGS")
        self.request_headers = MapCollection("REQUEST_HEADERS")
        self.tx = MapCollection("TX", case_insensitive=False)
        self.request_uri = SingleValueCollection("REQUEST_URI")
