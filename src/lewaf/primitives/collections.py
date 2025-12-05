from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
        self.args_get = MapCollection("ARGS_GET")
        self.args_post = MapCollection("ARGS_POST")
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
        self.multipart_part_headers = MapCollection("MULTIPART_PART_HEADERS")

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

        # Geographic location collection populated by geoLookup operator
        self.geo = MapCollection("GEO", case_insensitive=False)

        # Match tracking variables - populated during rule evaluation
        self.matched_var = SingleValueCollection("MATCHED_VAR")
        self.matched_var_name = SingleValueCollection("MATCHED_VAR_NAME")
        self.matched_vars = MapCollection("MATCHED_VARS", case_insensitive=False)
        self.matched_vars_names = MapCollection(
            "MATCHED_VARS_NAMES", case_insensitive=False
        )

        # Environment and server variables
        self.env = MapCollection("ENV")

        # File upload variables
        self.files_combined_size = SingleValueCollection("FILES_COMBINED_SIZE")
        self.files_names = MapCollection("FILES_NAMES")
        self.files_sizes = MapCollection("FILES_SIZES")
        self.files_tmp_content = MapCollection("FILES_TMP_CONTENT")
        self.files_tmp_names = MapCollection("FILES_TMPNAMES")

        # Error handling variables
        self.reqbody_error = SingleValueCollection("REQBODY_ERROR")
        self.reqbody_error_msg = SingleValueCollection("REQBODY_ERROR_MSG")
        self.reqbody_processor = SingleValueCollection("REQBODY_PROCESSOR")
        self.reqbody_processor_error = SingleValueCollection("REQBODY_PROCESSOR_ERROR")
        self.reqbody_processor_error_msg = SingleValueCollection(
            "REQBODY_PROCESSOR_ERROR_MSG"
        )
        self.inbound_data_error = SingleValueCollection("INBOUND_DATA_ERROR")
        self.outbound_data_error = SingleValueCollection("OUTBOUND_DATA_ERROR")

        # Additional request/response variables
        self.request_body_length = SingleValueCollection("REQUEST_BODY_LENGTH")
        self.response_content_length = SingleValueCollection("RESPONSE_CONTENT_LENGTH")
        self.response_content_type = SingleValueCollection("RESPONSE_CONTENT_TYPE")
        self.request_headers_names = MapCollection("REQUEST_HEADERS_NAMES")
        self.response_headers_names = MapCollection("RESPONSE_HEADERS_NAMES")
        self.request_cookies_names = MapCollection("REQUEST_COOKIES_NAMES")
        self.args_names = MapCollection("ARGS_NAMES")
        self.args_get_names = MapCollection("ARGS_GET_NAMES")
        self.args_post_names = MapCollection("ARGS_POST_NAMES")
        self.args_combined_size = SingleValueCollection("ARGS_COMBINED_SIZE")

        # Performance and monitoring variables
        self.duration = SingleValueCollection("DURATION")
        self.highest_severity = SingleValueCollection("HIGHEST_SEVERITY")
        self.unique_id = SingleValueCollection("UNIQUE_ID")

        # Additional path variables
        self.request_basename = SingleValueCollection("REQUEST_BASENAME")
        self.request_filename = SingleValueCollection("REQUEST_FILENAME")
        self.request_uri_raw = SingleValueCollection("REQUEST_URI_RAW")

        # Status and protocol variables
        self.status_line = SingleValueCollection("STATUS_LINE")
        self.response_protocol = SingleValueCollection("RESPONSE_PROTOCOL")
        self.server_addr = SingleValueCollection("SERVER_ADDR")
        self.server_port = SingleValueCollection("SERVER_PORT")

    def set_geo_data(self, geo_data: dict[str, str]) -> None:
        """Set geographic location data from geoLookup operator.

        Args:
            geo_data: Dictionary containing geographic information with keys:
                - COUNTRY_CODE: ISO 3166-1 alpha-2 country code (e.g., 'US', 'GB')
                - COUNTRY_NAME: Full country name (e.g., 'United States', 'United Kingdom')
                - REGION: Region/state code (e.g., 'CA', 'NY')
                - REGION_NAME: Full region/state name (e.g., 'California', 'New York')
                - CITY: City name (e.g., 'San Francisco', 'New York')
                - POSTAL_CODE: Postal/ZIP code (e.g., '94102', '10001')
                - LATITUDE: Latitude coordinate as string (e.g., '37.7749')
                - LONGITUDE: Longitude coordinate as string (e.g., '-122.4194')
                - CONTINENT: Continent code (e.g., 'NA', 'EU')
                - TIME_ZONE: Time zone identifier (e.g., 'America/Los_Angeles')
        """
        # Clear existing geo data
        self.geo._data.clear()

        # Set all provided geographic data
        for key, value in geo_data.items():
            if value:  # Only add non-empty values
                self.geo.add(key, value)

    def set_performance_metrics(
        self,
        duration_ms: float | None = None,
        severity: int | None = None,
        transaction_id: str | None = None,
    ) -> None:
        """Set performance monitoring variables.

        Args:
            duration_ms: Transaction processing duration in milliseconds
            severity: Highest severity level encountered (0-5, where 5 is most severe)
            transaction_id: Unique identifier for this transaction
        """
        if duration_ms is not None:
            self.duration.set(str(duration_ms))

        if severity is not None:
            # Ensure severity is within valid range (0-5)
            severity = max(0, min(5, severity))
            self.highest_severity.set(str(severity))

        if transaction_id is not None:
            self.unique_id.set(transaction_id)

    def update_highest_severity(self, severity: int) -> None:
        """Update highest severity if the new severity is higher.

        Args:
            severity: New severity level to compare (0-5)
        """
        current_severity = self.highest_severity.get()
        if current_severity:
            try:
                current_severity_int = int(current_severity)
                if severity > current_severity_int:
                    self.highest_severity.set(str(severity))
            except ValueError:
                # If current severity is invalid, set the new one
                self.highest_severity.set(str(max(0, min(5, severity))))
        else:
            # No current severity set
            self.highest_severity.set(str(max(0, min(5, severity))))

    def set_network_variables(
        self,
        remote_addr: str | None = None,
        remote_host: str | None = None,
        remote_port: int | None = None,
        server_addr: str | None = None,
        server_port: int | None = None,
    ) -> None:
        """Set network connection variables.

        Args:
            remote_addr: Client IP address
            remote_host: Client hostname (if available)
            remote_port: Client port number
            server_addr: Server IP address
            server_port: Server port number
        """
        if remote_addr is not None:
            self.remote_addr.set(remote_addr)

        if remote_host is not None:
            self.remote_host.set(remote_host)

        if remote_port is not None:
            self.remote_port.set(str(remote_port))

        if server_addr is not None:
            self.server_addr.set(server_addr)

        if server_port is not None:
            self.server_port.set(str(server_port))

    def set_request_variables(
        self,
        uri: str | None = None,
        method: str | None = None,
        protocol: str | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
    ) -> None:
        """Set core request variables and compute derived values.

        Args:
            uri: Request URI path
            method: HTTP method (GET, POST, etc.)
            protocol: HTTP protocol version (HTTP/1.1, HTTP/2, etc.)
            body: Request body content
            content_type: Content-Type header value
        """
        if uri is not None:
            self.request_uri.set(uri)
            self.request_uri_raw.set(uri)  # In production, this would be URL-encoded

            # Extract basename and filename from URI
            import os  # noqa: PLC0415 - Avoids circular import

            if uri:
                # Remove query string for path extraction
                path = uri.split("?")[0]
                self.request_basename.set(os.path.basename(path))

                # Extract filename (basename if it has an extension, empty otherwise)
                basename = os.path.basename(path)
                if "." in basename and not basename.startswith("."):
                    self.request_filename.set(basename)
                else:
                    self.request_filename.set("")

        if method is not None:
            self.request_method.set(method.upper())

        if protocol is not None:
            self.request_protocol.set(protocol)

        if body is not None:
            self.request_body.set_content(body, content_type or "")
            self.request_body_length.set(str(len(body)))

    def set_response_variables(
        self,
        status: int | None = None,
        protocol: str | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        content_length: int | None = None,
    ) -> None:
        """Set response variables.

        Args:
            status: HTTP status code (200, 404, etc.)
            protocol: HTTP protocol version
            body: Response body content
            content_type: Response Content-Type header
            content_length: Response Content-Length value
        """
        if status is not None:
            self.response_status.set(str(status))

        if protocol is not None:
            self.response_protocol.set(protocol)

        # Set status line after protocol is potentially set
        if status is not None:
            # Use provided protocol or current response_protocol or default
            protocol_val = protocol or self.response_protocol.get() or "HTTP/1.1"

            # HTTP status phrases (subset of common ones)
            status_phrases = {
                200: "OK",
                201: "Created",
                204: "No Content",
                301: "Moved Permanently",
                302: "Found",
                304: "Not Modified",
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                405: "Method Not Allowed",
                409: "Conflict",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
            }
            phrase = status_phrases.get(status, "Unknown")
            self.status_line.set(f"{protocol_val} {status} {phrase}")

        if content_type is not None:
            self.response_content_type.set(content_type)

        if content_length is not None:
            self.response_content_length.set(str(content_length))

        if body is not None:
            self.response_body.set_content(body, content_type or "")
            if content_length is None:  # Auto-set if not provided
                self.response_content_length.set(str(len(body)))

    def populate_header_names(self) -> None:
        """Populate header name collections from existing headers."""
        # Populate REQUEST_HEADERS_NAMES from REQUEST_HEADERS
        self.request_headers_names._data.clear()
        for header_name in self.request_headers._data:
            self.request_headers_names.add(header_name, header_name)

        # Populate RESPONSE_HEADERS_NAMES from RESPONSE_HEADERS
        self.response_headers_names._data.clear()
        for header_name in self.response_headers._data:
            self.response_headers_names.add(header_name, header_name)

    def populate_args_metadata(self) -> None:
        """Populate argument metadata collections."""
        # Populate ARGS_NAMES from ARGS
        self.args_names._data.clear()
        for arg_name in self.args._data:
            self.args_names.add(arg_name, arg_name)

        # Calculate ARGS_COMBINED_SIZE
        total_size = 0
        for arg_name, arg_values in self.args._data.items():
            total_size += len(arg_name)  # Key size
            for value in arg_values:
                total_size += len(value)  # Value size
        self.args_combined_size.set(str(total_size))

    def populate_cookie_names(self) -> None:
        """Populate cookie name collections from existing cookies."""
        # Populate REQUEST_COOKIES_NAMES from REQUEST_COOKIES
        self.request_cookies_names._data.clear()
        for cookie_name in self.request_cookies._data:
            self.request_cookies_names.add(cookie_name, cookie_name)
