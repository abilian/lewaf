from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs

from lewaf.bodyprocessors import BodyProcessorError, get_body_processor
from lewaf.primitives.collections import TransactionVariables

if TYPE_CHECKING:
    from lewaf.integration import WAF
    from lewaf.rules import Rule

# Default configuration constants
DEFAULT_BODY_LIMIT = 131072  # 128 KB - Maximum request body size
DEFAULT_HTTP_PROTOCOL = "HTTP/1.1"


class Transaction:
    """Transaction representing a single HTTP request/response cycle.

    Public API (stable for 1.0):
        id: str - Unique transaction identifier
        interruption: dict | None - Interruption info if request was blocked

        process_uri(uri, method) - Set request URI and method
        add_request_body(body, content_type) - Add request body
        process_request_headers() -> dict | None - Evaluate Phase 1 rules
        process_request_body() -> dict | None - Evaluate Phase 2 rules
        add_response_headers(headers) - Add response headers
        add_response_status(status, protocol) - Add response status
        process_response_headers() -> dict | None - Evaluate Phase 3 rules
        add_response_body(body, content_type) - Add response body
        process_response_body() -> dict | None - Evaluate Phase 4 rules

    Internal API (may change between versions):
        waf, variables, chain_state, skip_state, multimatch_state,
        deprecated_vars, var_expiration, ctl_directives, collection_manager,
        rule_engine_enabled, rule_engine_mode, body_processor, body_limit,
        audit_log_enabled, force_audit_log, skip_rules_count, current_phase
    """

    def __init__(self, waf: WAF, id: str):
        self.id = id
        self.waf = waf
        self.variables = TransactionVariables()
        self.interruption: dict[str, str | int] | None = None
        self.current_phase = 0

        # State attributes for advanced actions (Phase 6)
        self.chain_state: dict[str, Any] = {}
        self.skip_state: dict[str, Any] = {}
        self.multimatch_state: dict[str, Any] = {}
        self.deprecated_vars: set[str] = set()
        self.var_expiration: dict[str, float] = {}
        self.ctl_directives: dict[str, Any] = {}
        self.collection_manager: Any = None  # PersistentCollectionManager, set by WAF

        # Engine control attributes
        self.rule_engine_enabled: bool = True
        self.rule_engine_mode: str = "on"
        self.body_processor: str = "URLENCODED"
        self.body_limit: int = DEFAULT_BODY_LIMIT

        # Audit logging control
        self.audit_log_enabled: bool = True
        self.force_audit_log: bool = False

        # Skip rules counter (for skip action)
        self.skip_rules_count: int = 0

        # Capture state for regex match groups (TX:0 through TX:9)
        self._capturing: bool = False

    def add_request_body(self, body: bytes, content_type: str = "") -> None:
        """Add request body content to transaction.

        Args:
            body: Request body bytes
            content_type: Content-Type header value
        """
        # Set body content
        self.variables.set_request_variables(body=body, content_type=content_type)

        # Set Content-Type header if provided
        if content_type:
            self.variables.request_headers.add("content-type", content_type)

    def _select_body_processor(self, content_type: str) -> str | None:
        """Select body processor based on Content-Type.

        Args:
            content_type: Content-Type header value

        Returns:
            Processor name, or None if no processor needed
        """
        if not content_type:
            return None

        content_type = content_type.lower().split(";")[0].strip()

        if "application/x-www-form-urlencoded" in content_type:
            return "URLENCODED"
        if "application/json" in content_type:
            return "JSON"
        if "xml" in content_type:
            return "XML"
        if "multipart/form-data" in content_type:
            return "MULTIPART"

        return None

    def _parse_request_body(self) -> None:
        """Parse request body using appropriate processor."""
        # Get body content
        body = self.variables.request_body.get_raw()
        if not body:
            return

        # Get Content-Type
        content_type_values = self.variables.request_headers.get("content-type")
        content_type = content_type_values[0] if content_type_values else ""

        # Select processor
        processor_name = self._select_body_processor(content_type)
        if not processor_name:
            # No processor needed (e.g., GET request or unknown content type)
            return

        # Set processor name
        self.variables.reqbody_processor.set(processor_name)

        try:
            # Get processor instance
            processor = get_body_processor(processor_name)

            # Parse body
            processor.read(body, content_type)

            # Merge collections
            self._merge_processor_collections(processor)

        except BodyProcessorError as e:
            # Set error variables
            self.variables.reqbody_error.set("1")
            self.variables.reqbody_error_msg.set(str(e))
            self.variables.reqbody_processor_error.set("1")
            self.variables.reqbody_processor_error_msg.set(str(e))

        except Exception as e:
            # Unexpected error
            self.variables.reqbody_error.set("1")
            self.variables.reqbody_error_msg.set(f"Unexpected error: {e}")

    def _merge_processor_collections(self, processor: Any) -> None:
        """Merge body processor collections into transaction variables.

        Args:
            processor: Body processor instance
        """
        collections = processor.get_collections()

        # ARGS_POST - form field arguments
        if "args_post" in collections:
            args_post = collections["args_post"]
            for key, value in args_post.items():
                self.variables.args_post.add(key, value)
                # Also add to ARGS (union of query params and POST params)
                self.variables.args.add(key, value)

            # Populate ARGS_POST_NAMES
            for key in args_post:
                self.variables.args_post_names.add(key, key)

        # FILES - uploaded files
        if "files" in collections:
            files = collections["files"]
            multipart_filename = collections.get("multipart_filename", {})

            for name, content in files.items():
                filename = multipart_filename.get(name, "unknown")
                # Get content type from processor if available
                content_type = ""
                if hasattr(processor, "parts"):
                    for part in processor.parts:
                        if part.name == name:
                            content_type = part.content_type
                            break

                self.variables.files.add_file(name, filename, content, content_type)

        # FILES_NAMES
        if "files_names" in collections:
            for name, value in collections["files_names"].items():
                self.variables.files_names.add(name, value)

        # FILES_SIZES
        if "files_sizes" in collections:
            total_size = 0
            for name, size in collections["files_sizes"].items():
                self.variables.files_sizes.add(name, str(size))
                total_size += size
            self.variables.files_combined_size.set(str(total_size))

        # MULTIPART_NAME
        if "multipart_name" in collections:
            for name, value in collections["multipart_name"].items():
                self.variables.multipart_name.add(name, value)

        # MULTIPART_PART_HEADERS - headers from each multipart part
        if "multipart_part_headers" in collections:
            for key, value in collections["multipart_part_headers"].items():
                self.variables.multipart_part_headers.add(key, value)

        # XML - structured XML data
        if "xml" in collections:
            xml_data = collections["xml"]
            if isinstance(xml_data, dict) and "_root" in xml_data:
                # Store XML root element reference
                self.variables.xml.add("_root", str(xml_data["_root"]))

        # REQUEST_BODY is already set via set_request_variables

    def process_uri(self, uri: str, method: str):
        self.variables.request_uri.set(uri)
        self.variables.request_method.set(method)
        # Set default HTTP protocol version
        self.variables.request_protocol.set(DEFAULT_HTTP_PROTOCOL)
        if "?" in uri:
            qs = uri.split("?", 1)[1]
            for key, values in parse_qs(qs).items():
                for value in values:
                    self.variables.args.add(key, value)
                    # Also populate ARGS_GET for query string parameters
                    self.variables.args_get.add(key, value)
                # Populate ARGS_GET_NAMES and ARGS_NAMES
                self.variables.args_get_names.add(key, key)
                self.variables.args_names.add(key, key)

    def process_request_headers(self) -> dict[str, str | int] | None:
        """Process request headers and evaluate Phase 1 rules.

        Returns:
            Interruption dict if rules triggered, None otherwise
        """
        self.current_phase = 1
        self.waf.rule_group.evaluate(1, self)
        return self.interruption

    def process_request_body(self) -> dict[str, str | int] | None:
        """Process request body and evaluate Phase 2 rules.

        Returns:
            Interruption dict if rules triggered, None otherwise
        """
        # Parse body before evaluating rules
        self._parse_request_body()

        # Evaluate Phase 2 rules
        self.current_phase = 2
        self.waf.rule_group.evaluate(2, self)
        return self.interruption

    def add_response_headers(self, headers: dict[str, str]) -> None:
        """Add response headers to transaction.

        Args:
            headers: Response headers as dict (name -> value)
        """
        for name, value in headers.items():
            self.variables.response_headers.add(name.lower(), value)

        # Populate derived variables
        self.variables.populate_header_names()

        # Extract Content-Type if present
        content_type_values = self.variables.response_headers.get("content-type")
        if content_type_values:
            self.variables.response_content_type.set(content_type_values[0])

        # Extract Content-Length if present
        content_length_values = self.variables.response_headers.get("content-length")
        if content_length_values:
            try:
                length = int(content_length_values[0])
                self.variables.response_content_length.set(str(length))
            except ValueError:
                pass

    def add_response_status(
        self, status: int, protocol: str = DEFAULT_HTTP_PROTOCOL
    ) -> None:
        """Add response status to transaction.

        Args:
            status: HTTP status code
            protocol: HTTP protocol version
        """
        self.variables.set_response_variables(status=status, protocol=protocol)

    def process_response_headers(self) -> dict[str, str | int] | None:
        """Process response headers and evaluate Phase 3 rules.

        Returns:
            Interruption dict if rules triggered, None otherwise
        """
        self.current_phase = 3
        self.waf.rule_group.evaluate(3, self)
        return self.interruption

    def add_response_body(self, body: bytes, content_type: str = "") -> None:
        """Add response body content to transaction.

        Args:
            body: Response body bytes
            content_type: Content-Type header value
        """
        # Set body content
        self.variables.set_response_variables(
            body=body, content_type=content_type, content_length=len(body)
        )

    def _parse_response_body(self) -> None:
        """Parse response body using appropriate processor."""
        # Get body content
        body = self.variables.response_body.get_raw()
        if not body:
            return

        # Get Content-Type
        content_type = self.variables.response_content_type.get()
        if not content_type:
            # Try from response headers
            content_type_values = self.variables.response_headers.get("content-type")
            content_type = content_type_values[0] if content_type_values else ""

        # Select processor (reuse request processor logic)
        processor_name = self._select_body_processor(content_type)
        if not processor_name:
            return

        # Store processor name in TX collection (response-specific)
        self.variables.tx.add("response_body_processor", processor_name)

        try:
            processor = get_body_processor(processor_name)
            processor.read(body, content_type)

            # Merge collections (same as request body)
            # Note: This populates ARGS_POST with response data
            # Real implementation might use different collection names
            self._merge_processor_collections(processor)

        except BodyProcessorError as e:
            # Set error variables for response body
            self.variables.tx.add("response_body_error", "1")
            self.variables.tx.add("response_body_error_msg", str(e))
        except Exception as e:
            self.variables.tx.add("response_body_error", "1")
            self.variables.tx.add("response_body_error_msg", f"Unexpected error: {e}")

    def process_response_body(self) -> dict[str, str | int] | None:
        """Process response body and evaluate Phase 4 rules.

        Returns:
            Interruption dict if rules triggered, None otherwise
        """
        # Parse body before evaluating rules
        self._parse_response_body()

        # Evaluate Phase 4 rules
        self.current_phase = 4
        self.waf.rule_group.evaluate(4, self)
        return self.interruption

    def interrupt(
        self, rule: Rule, action: str = "deny", redirect_url: str | None = None
    ) -> None:
        """Interrupt the transaction with the given action.

        Args:
            rule: The rule that triggered the interruption
            action: The action type (deny, redirect, drop)
            redirect_url: Optional redirect URL for redirect action
        """
        self.interruption = {"rule_id": rule.id, "action": action}
        if redirect_url:
            self.interruption["redirect_url"] = redirect_url

    def set_capturing(self, enabled: bool) -> None:
        """Enable or disable capture mode for the current rule evaluation.

        Args:
            enabled: Whether to capture regex match groups
        """
        self._capturing = enabled

    def capturing(self) -> bool:
        """Return whether the transaction is capturing matches.

        Returns:
            True if the current rule has the 'capture' action enabled
        """
        return self._capturing

    def capture_field(self, index: int, value: str) -> None:
        """Capture a field value at the given index.

        Stores captured regex groups in TX:0 through TX:9, following
        ModSecurity convention. TX:0 contains the full match, TX:1-TX:9
        contain capture groups.

        Args:
            index: Capture group index (0-9)
            value: Captured value
        """
        if 0 <= index <= 9:
            self.variables.tx.add(str(index), value)
