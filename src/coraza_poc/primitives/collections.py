from __future__ import annotations

import re


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

    def find_all(self) -> list[MatchData]:
        """Return all matches in this collection."""
        raise NotImplementedError


class MapCollection(Collection):
    """Collection for key-value pairs like request headers or arguments."""

    def __init__(self, name: str, case_insensitive: bool = True):
        super().__init__(name)
        self._data: dict[str, list[str]] = {}
        self._case_insensitive = case_insensitive

    def add(self, key: str, value: str) -> None:
        """Add a value to the given key."""
        if self._case_insensitive:
            key = key.lower()
        if key not in self._data:
            self._data[key] = []
        self._data[key].append(value)

    def get(self, key: str) -> list[str]:
        """Get all values for the given key."""
        if self._case_insensitive:
            key = key.lower()
        return self._data.get(key, [])

    def set(self, key: str, values: list[str]) -> None:
        """Replace the key's values with the provided list."""
        if self._case_insensitive:
            key = key.lower()
        self._data[key] = values.copy()

    def remove(self, key: str) -> None:
        """Remove the key from the collection."""
        if self._case_insensitive:
            key = key.lower()
        self._data.pop(key, None)

    def find_regex(self, pattern: re.Pattern[str]) -> list[MatchData]:
        """Find all matches where the key matches the regex pattern."""
        matches = []
        for key, values in self._data.items():
            if pattern.search(key):
                for value in values:
                    matches.append(MatchData(self._name, key, value))
        return matches

    def find_string(self, search_key: str) -> list[MatchData]:
        """Find all matches for the exact key string."""
        if self._case_insensitive:
            search_key = search_key.lower()
        matches = []
        if search_key in self._data:
            for value in self._data[search_key]:
                matches.append(MatchData(self._name, search_key, value))
        return matches

    def find_all(self) -> list[MatchData]:
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

    def find_all(self) -> list[MatchData]:
        """Return the single value as a MatchData object."""
        return [MatchData(self._name, "", self._value)]

    def __str__(self):
        return f"{self._name}: {self._value}"


class FileData:
    """Represents uploaded file data."""

    def __init__(
        self, name: str, filename: str, content: bytes, content_type: str = ""
    ):
        self.name = name
        self.filename = filename
        self.content = content
        self.content_type = content_type
        self.size = len(content)


class FilesCollection(Collection):
    """Collection for uploaded files."""

    def __init__(self, name: str = "FILES"):
        super().__init__(name)
        self._files: dict[str, list[FileData]] = {}

    def add_file(
        self, name: str, filename: str, content: bytes, content_type: str = ""
    ) -> None:
        """Add an uploaded file."""
        file_data = FileData(name, filename, content, content_type)
        if name not in self._files:
            self._files[name] = []
        self._files[name].append(file_data)

    def get_files(self, name: str) -> list[FileData]:
        """Get all files for a given form field name."""
        return self._files.get(name, [])

    def find_all(self) -> list[MatchData]:
        """Return all file names and filenames as MatchData objects."""
        matches = []
        for name, files in self._files.items():
            for file_data in files:
                matches.append(MatchData(self._name, name, file_data.filename))
        return matches

    def find_regex(self, pattern: re.Pattern[str]) -> list[MatchData]:
        """Find files where the field name matches the regex pattern."""
        matches = []
        for name, files in self._files.items():
            if pattern.search(name):
                for file_data in files:
                    matches.append(MatchData(self._name, name, file_data.filename))
        return matches

    def find_string(self, search_name: str) -> list[MatchData]:
        """Find files for the exact field name."""
        matches = []
        if search_name in self._files:
            for file_data in self._files[search_name]:
                matches.append(MatchData(self._name, search_name, file_data.filename))
        return matches


class BodyCollection(SingleValueCollection):
    """Collection for request/response body content."""

    def __init__(self, name: str):
        super().__init__(name)
        self._raw_content = b""
        self._content_type = ""

    def set_content(self, content: bytes, content_type: str = "") -> None:
        """Set the raw body content."""
        self._raw_content = content
        self._content_type = content_type.lower()
        # Convert to string for text content
        try:
            self._value = content.decode("utf-8", errors="ignore")
        except Exception:
            self._value = str(content)

    def get_raw(self) -> bytes:
        """Get the raw body content as bytes."""
        return self._raw_content

    def get_content_type(self) -> str:
        """Get the content type."""
        return self._content_type

    def is_json(self) -> bool:
        """Check if content is JSON."""
        return "json" in self._content_type

    def is_xml(self) -> bool:
        """Check if content is XML."""
        return "xml" in self._content_type or self._content_type.endswith("/xml")


class TransactionVariables:
    """Container for all transaction variables used in WAF rules."""

    def __init__(self):
        # Core collections from original implementation
        self.args = MapCollection("ARGS")
        self.request_headers = MapCollection("REQUEST_HEADERS")
        self.tx = MapCollection("TX", case_insensitive=False)
        self.request_uri = SingleValueCollection("REQUEST_URI")

        # Additional collections for full Go compatibility
        self.request_body = BodyCollection("REQUEST_BODY")
        self.response_body = BodyCollection("RESPONSE_BODY")
        self.response_headers = MapCollection("RESPONSE_HEADERS")
        self.request_cookies = MapCollection("REQUEST_COOKIES")
        self.response_cookies = MapCollection("RESPONSE_COOKIES")
        self.files = FilesCollection("FILES")
        self.multipart_name = MapCollection("MULTIPART_NAME")

        # Additional single value collections
        self.request_method = SingleValueCollection("REQUEST_METHOD")
        self.request_protocol = SingleValueCollection("REQUEST_PROTOCOL")
        self.request_line = SingleValueCollection("REQUEST_LINE")
        self.response_status = SingleValueCollection("RESPONSE_STATUS")
        self.server_name = SingleValueCollection("SERVER_NAME")
        self.server_addr = SingleValueCollection("SERVER_ADDR")
        self.server_port = SingleValueCollection("SERVER_PORT")
        self.remote_addr = SingleValueCollection("REMOTE_ADDR")
        self.remote_host = SingleValueCollection("REMOTE_HOST")
        self.remote_port = SingleValueCollection("REMOTE_PORT")
        self.query_string = SingleValueCollection("QUERY_STRING")

        # Content analysis collections
        self.xml = MapCollection("XML")
        self.json = MapCollection("JSON")

        # Geo and IP collections (placeholders - would need actual implementation)
        self.geo = MapCollection("GEO")
        self.matched_var = SingleValueCollection("MATCHED_VAR")
        self.matched_var_name = SingleValueCollection("MATCHED_VAR_NAME")

        # Environment and server variables
        self.env = MapCollection("ENV")
        self.server_addr = SingleValueCollection("SERVER_ADDR")
        self.server_port = SingleValueCollection("SERVER_PORT")
