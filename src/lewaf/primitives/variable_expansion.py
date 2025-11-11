"""
Advanced variable expansion and macro system for SecLang rules.

This module implements full variable expansion support including:
- Simple variables: %{VAR}
- Collection members: %{ARGS.id}, %{TX.score}
- Collection operators: &ARGS (count), &TX (count)
- Special variables: %{MATCHED_VAR}, %{TIME}, %{UNIQUE_ID}
- Environment variables: %{ENV.PATH}
- Nested expansion: %{TX.%{ARGS.var_name}}
"""

from __future__ import annotations

import os
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lewaf.primitives.collections import Collection, TransactionVariables


class VariableExpander:
    """Advanced variable and macro expansion for SecLang expressions."""

    # Regex pattern for variable references: %{VAR_NAME}
    VAR_PATTERN = re.compile(r"%\{([^}]+)\}")

    # Regex pattern for collection operators: &ARGS, &TX
    COLLECTION_OP_PATTERN = re.compile(r"&([A-Z_]+)")

    @staticmethod
    def expand(expression: str, variables: TransactionVariables) -> str:
        """
        Expand all macros and variables in an expression.

        Args:
            expression: Expression containing variables like %{TX.score}
            variables: TransactionVariables object

        Returns:
            Expanded expression with variables resolved

        Examples:
            >>> expand("%{TX.score}", tx_vars)
            "5"
            >>> expand("User %{ARGS.name} from %{REMOTE_ADDR}", tx_vars)
            "User alice from 192.168.1.1"
        """
        if not expression:
            return expression

        # Expand variable references (%{VAR})
        # Support nested expansion by expanding multiple times
        max_iterations = 10
        for _ in range(max_iterations):
            prev = expression
            expression = VariableExpander.VAR_PATTERN.sub(
                lambda m: VariableExpander._resolve_variable(m.group(1), variables),
                expression,
            )
            if expression == prev:
                break  # No more expansions

        return expression

    @staticmethod
    def expand_collection_operator(spec: str, variables: TransactionVariables) -> int:
        """
        Resolve collection operators like &ARGS, &TX.

        Collection operators return the count of items in the collection.

        Args:
            spec: Collection operator specification (e.g., "&ARGS", "&TX")
            variables: TransactionVariables object

        Returns:
            Count of items in the collection

        Examples:
            >>> expand_collection_operator("&ARGS", tx_vars)
            3  # 3 arguments present
            >>> expand_collection_operator("&TX", tx_vars)
            5  # 5 transaction variables set
        """
        if not spec.startswith("&"):
            return 0

        collection_name = spec[1:].upper()
        collection = VariableExpander._get_collection(collection_name, variables)

        if collection:
            return len(collection.find_all())

        return 0

    @staticmethod
    def _resolve_variable(var_spec: str, variables: TransactionVariables) -> str:
        """Resolve a single variable specification."""
        var_spec = var_spec.strip()
        var_spec_upper = var_spec.upper()

        # Handle collection member access (e.g., TX.score, REQUEST_HEADERS.host)
        if "." in var_spec:
            parts = var_spec.split(".", 1)
            collection_name = parts[0].upper()
            member_key = parts[1]  # Keep original case for member key initially

            return VariableExpander._resolve_collection_member(
                collection_name, member_key, variables
            )

        # Handle special single-value variables
        return VariableExpander._resolve_single_variable(var_spec_upper, variables)

    @staticmethod
    def _resolve_single_variable(var_name: str, variables: TransactionVariables) -> str:
        """Resolve single-value variables."""
        # Special computed variables
        if var_name == "TIME":
            return str(int(time.time() * 1000))  # Milliseconds
        if var_name == "TIME_SEC":
            return str(int(time.time()))  # Seconds
        if var_name == "TIME_YEAR":
            return time.strftime("%Y")
        if var_name == "TIME_MON":
            return time.strftime("%m")
        if var_name == "TIME_DAY":
            return time.strftime("%d")
        if var_name == "TIME_HOUR":
            return time.strftime("%H")
        if var_name == "TIME_MIN":
            return time.strftime("%M")
        if var_name == "TIME_SEC":
            return time.strftime("%S")
        if var_name == "TIME_WDAY":
            return time.strftime("%w")  # Day of week (0-6)

        # Request variables
        if var_name == "REQUEST_URI":
            return variables.request_uri.get()
        if var_name == "REQUEST_URI_RAW":
            return variables.request_uri_raw.get()
        if var_name == "REQUEST_METHOD":
            return variables.request_method.get()
        if var_name == "REQUEST_PROTOCOL":
            return variables.request_protocol.get()
        if var_name == "REQUEST_LINE":
            return variables.request_line.get()
        if var_name == "REQUEST_BASENAME":
            return variables.request_basename.get()
        if var_name == "REQUEST_FILENAME":
            return variables.request_filename.get()
        if var_name == "REQUEST_BODY":
            return variables.request_body.get()
        if var_name == "REQUEST_BODY_LENGTH":
            return variables.request_body_length.get()
        if var_name == "QUERY_STRING":
            return variables.query_string.get()

        # Response variables
        if var_name == "RESPONSE_STATUS":
            return variables.response_status.get()
        if var_name == "RESPONSE_PROTOCOL":
            return variables.response_protocol.get()
        if var_name == "RESPONSE_BODY":
            return variables.response_body.get()
        if var_name == "RESPONSE_CONTENT_LENGTH":
            return variables.response_content_length.get()
        if var_name == "RESPONSE_CONTENT_TYPE":
            return variables.response_content_type.get()
        if var_name == "STATUS_LINE":
            return variables.status_line.get()

        # Network variables
        if var_name == "REMOTE_ADDR":
            return variables.remote_addr.get()
        if var_name == "REMOTE_HOST":
            return variables.remote_host.get()
        if var_name == "REMOTE_PORT":
            return variables.remote_port.get()
        if var_name == "SERVER_ADDR":
            return variables.server_addr.get()
        if var_name == "SERVER_PORT":
            return variables.server_port.get()
        if var_name == "SERVER_NAME":
            return variables.server_name.get()

        # Match variables
        if var_name == "MATCHED_VAR":
            return variables.matched_var.get()
        if var_name == "MATCHED_VAR_NAME":
            return variables.matched_var_name.get()

        # Performance variables
        if var_name == "DURATION":
            return variables.duration.get()
        if var_name == "HIGHEST_SEVERITY":
            return variables.highest_severity.get()
        if var_name == "UNIQUE_ID":
            return variables.unique_id.get()

        # Size variables
        if var_name == "FILES_COMBINED_SIZE":
            return variables.files_combined_size.get()
        if var_name == "ARGS_COMBINED_SIZE":
            return variables.args_combined_size.get()

        # Error variables
        if var_name == "REQBODY_ERROR":
            return variables.reqbody_error.get()
        if var_name == "REQBODY_ERROR_MSG":
            return variables.reqbody_error_msg.get()
        if var_name == "REQBODY_PROCESSOR":
            return variables.reqbody_processor.get()
        if var_name == "REQBODY_PROCESSOR_ERROR":
            return variables.reqbody_processor_error.get()
        if var_name == "REQBODY_PROCESSOR_ERROR_MSG":
            return variables.reqbody_processor_error_msg.get()
        if var_name == "INBOUND_DATA_ERROR":
            return variables.inbound_data_error.get()
        if var_name == "OUTBOUND_DATA_ERROR":
            return variables.outbound_data_error.get()

        # Unknown variable
        return ""

    @staticmethod
    def _resolve_collection_member(
        collection_name: str, member_key: str, variables: TransactionVariables
    ) -> str:
        """Resolve collection member access like TX.score, ARGS.id."""
        collection_name = collection_name.upper()

        # Handle TX collection (case-insensitive keys)
        if collection_name == "TX":
            values = variables.tx.get(member_key.lower())
            return values[0] if values else ""

        # Handle ARGS collection
        if collection_name == "ARGS":
            values = variables.args.get(member_key)
            return values[0] if values else ""

        # Handle REQUEST_HEADERS collection
        if collection_name == "REQUEST_HEADERS":
            values = variables.request_headers.get(member_key.lower())
            return values[0] if values else ""

        # Handle RESPONSE_HEADERS collection
        if collection_name == "RESPONSE_HEADERS":
            values = variables.response_headers.get(member_key.lower())
            return values[0] if values else ""

        # Handle REQUEST_COOKIES collection
        if collection_name == "REQUEST_COOKIES":
            values = variables.request_cookies.get(member_key)
            return values[0] if values else ""

        # Handle RESPONSE_COOKIES collection
        if collection_name == "RESPONSE_COOKIES":
            values = variables.response_cookies.get(member_key)
            return values[0] if values else ""

        # Handle GEO collection
        if collection_name == "GEO":
            values = variables.geo.get(member_key.upper())
            return values[0] if values else ""

        # Handle ENV collection (environment variables)
        if collection_name == "ENV":
            return os.environ.get(member_key.upper(), "")

        # Handle FILES collections
        if collection_name == "FILES_NAMES":
            values = variables.files_names.get(member_key)
            return values[0] if values else ""
        if collection_name == "FILES_SIZES":
            values = variables.files_sizes.get(member_key)
            return values[0] if values else ""

        # Handle XML collection
        if collection_name == "XML":
            values = variables.xml.get(member_key)
            return values[0] if values else ""

        # Handle JSON collection
        if collection_name == "JSON":
            values = variables.json.get(member_key)
            return values[0] if values else ""

        return ""

    @staticmethod
    def _get_collection(
        collection_name: str, variables: TransactionVariables
    ) -> Collection | None:
        """Get a collection by name."""
        collection_name = collection_name.upper()

        collection_map = {
            "ARGS": variables.args,
            "ARGS_NAMES": variables.args_names,
            "REQUEST_HEADERS": variables.request_headers,
            "REQUEST_HEADERS_NAMES": variables.request_headers_names,
            "RESPONSE_HEADERS": variables.response_headers,
            "RESPONSE_HEADERS_NAMES": variables.response_headers_names,
            "REQUEST_COOKIES": variables.request_cookies,
            "REQUEST_COOKIES_NAMES": variables.request_cookies_names,
            "RESPONSE_COOKIES": variables.response_cookies,
            "TX": variables.tx,
            "GEO": variables.geo,
            "ENV": variables.env,
            "FILES": variables.files,
            "FILES_NAMES": variables.files_names,
            "FILES_SIZES": variables.files_sizes,
            "XML": variables.xml,
            "JSON": variables.json,
            "MULTIPART_NAME": variables.multipart_name,
        }

        return collection_map.get(collection_name)


# Compatibility alias for existing code
class MacroExpander:
    """Legacy compatibility wrapper for VariableExpander."""

    @staticmethod
    def expand(expression: str, transaction) -> str:
        """
        Expand macros and variables (legacy interface).

        Args:
            expression: Expression to expand
            transaction: Transaction object with 'variables' attribute

        Returns:
            Expanded expression
        """
        if not hasattr(transaction, "variables"):
            return expression

        return VariableExpander.expand(expression, transaction.variables)

    @staticmethod
    def _resolve_variable(var_spec: str, transaction) -> str:
        """Legacy method for resolving variables."""
        if not hasattr(transaction, "variables"):
            return ""

        return VariableExpander._resolve_variable(var_spec, transaction.variables)

    @staticmethod
    def _resolve_collection_member(
        collection_name: str, member_key: str, transaction
    ) -> str:
        """Legacy method for resolving collection members."""
        if not hasattr(transaction, "variables"):
            return ""

        return VariableExpander._resolve_collection_member(
            collection_name, member_key, transaction.variables
        )
