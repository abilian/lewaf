"""Unit tests for TransactionVariables functionality."""

from coraza_poc.primitives.collections import TransactionVariables


def test_transaction_variables_creation():
    """Test basic TransactionVariables creation."""
    variables = TransactionVariables()

    # Check that basic collections exist
    assert hasattr(variables, "args")
    assert hasattr(variables, "request_headers")
    assert hasattr(variables, "request_uri")
    assert hasattr(variables, "tx")

    # Check collection names
    assert variables.args.name() == "ARGS"
    assert variables.request_headers.name() == "REQUEST_HEADERS"
    assert variables.request_uri.name() == "REQUEST_URI"


def test_transaction_variables_basic_usage():
    """Test basic usage of transaction variables."""
    variables = TransactionVariables()

    # Add some data
    variables.args.add("param1", "value1")
    variables.request_headers.add("User-Agent", "test-agent")
    variables.request_uri.set("/test/path")

    # Verify data
    args_matches = variables.args.find_string("param1")
    assert len(args_matches) == 1
    assert args_matches[0].value == "value1"
    assert args_matches[0].key == "param1"

    header_matches = variables.request_headers.find_string(
        "user-agent"
    )  # Case insensitive
    assert len(header_matches) == 1
    assert header_matches[0].value == "test-agent"

    uri_matches = variables.request_uri.find_all()
    assert len(uri_matches) == 1
    assert uri_matches[0].value == "/test/path"


def test_transaction_variables_phase1_variables():
    """Test Phase 1 specific variables."""
    variables = TransactionVariables()

    # Test server variables
    assert hasattr(variables, "server_addr")
    assert hasattr(variables, "server_name")
    assert hasattr(variables, "server_port")

    # Test request variables
    assert hasattr(variables, "request_line")
    assert hasattr(variables, "request_protocol")
    assert hasattr(variables, "query_string")

    # Verify names
    assert variables.server_addr.name() == "SERVER_ADDR"
    assert variables.server_name.name() == "SERVER_NAME"
    assert variables.server_port.name() == "SERVER_PORT"


def test_transaction_variables_phase2_variables():
    """Test Phase 2 specific variables."""
    variables = TransactionVariables()

    # Test file upload variables
    assert hasattr(variables, "files_combined_size")
    assert hasattr(variables, "files_names")
    assert hasattr(variables, "files_tmp_names")

    # Test error handling variables
    assert hasattr(variables, "reqbody_error")
    assert hasattr(variables, "inbound_data_error")
    assert hasattr(variables, "outbound_data_error")

    # Verify names
    assert variables.files_combined_size.name() == "FILES_COMBINED_SIZE"
    assert variables.reqbody_error.name() == "REQBODY_ERROR"


def test_transaction_variables_performance_variables():
    """Test performance and monitoring variables."""
    variables = TransactionVariables()

    # Test performance variables
    assert hasattr(variables, "duration")
    assert hasattr(variables, "highest_severity")
    assert hasattr(variables, "unique_id")

    # Verify names
    assert variables.duration.name() == "DURATION"
    assert variables.highest_severity.name() == "HIGHEST_SEVERITY"
    assert variables.unique_id.name() == "UNIQUE_ID"


def test_transaction_variables_matched_var():
    """Test MATCHED_VAR and MATCHED_VAR_NAME variables."""
    variables = TransactionVariables()

    assert hasattr(variables, "matched_var")
    assert hasattr(variables, "matched_var_name")

    assert variables.matched_var.name() == "MATCHED_VAR"
    assert variables.matched_var_name.name() == "MATCHED_VAR_NAME"


def test_transaction_variables_tx_collection():
    """Test TX collection for custom variables."""
    variables = TransactionVariables()

    # TX collection should allow custom variables
    variables.tx.add("custom_var", "custom_value")
    variables.tx.add("session_id", "abc123")

    # Verify custom variables
    custom_matches = variables.tx.find_string("custom_var")
    assert len(custom_matches) == 1
    assert custom_matches[0].value == "custom_value"
    assert custom_matches[0].key == "custom_var"

    session_matches = variables.tx.find_string("session_id")
    assert len(session_matches) == 1
    assert session_matches[0].value == "abc123"
    assert session_matches[0].key == "session_id"


def test_transaction_variables_remote_variables():
    """Test remote connection variables."""
    variables = TransactionVariables()

    # Test that remote variables exist (added in later phases)
    assert hasattr(variables, "remote_addr")
    assert hasattr(variables, "remote_host")
    assert hasattr(variables, "remote_port")

    # Verify names
    assert variables.remote_addr.name() == "REMOTE_ADDR"
    assert variables.remote_host.name() == "REMOTE_HOST"
    assert variables.remote_port.name() == "REMOTE_PORT"
