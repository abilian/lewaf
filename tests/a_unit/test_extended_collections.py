"""Tests for extended collections matching Go Coraza functionality."""

from coraza_poc.primitives.collections import (
    BodyCollection,
    FileData,
    FilesCollection,
    TransactionVariables,
)


def test_file_data():
    """Test FileData class."""
    content = b"file content"
    file_data = FileData("upload", "test.txt", content, "text/plain")

    assert file_data.name == "upload"
    assert file_data.filename == "test.txt"
    assert file_data.content == content
    assert file_data.content_type == "text/plain"
    assert file_data.size == len(content)


def test_files_collection():
    """Test FilesCollection functionality."""
    files = FilesCollection()

    # Add files
    files.add_file("upload1", "file1.txt", b"content1", "text/plain")
    files.add_file("upload1", "file2.txt", b"content2", "text/plain")
    files.add_file("upload2", "image.jpg", b"image_data", "image/jpeg")

    # Test get_files
    upload1_files = files.get_files("upload1")
    assert len(upload1_files) == 2
    assert upload1_files[0].filename == "file1.txt"
    assert upload1_files[1].filename == "file2.txt"

    upload2_files = files.get_files("upload2")
    assert len(upload2_files) == 1
    assert upload2_files[0].filename == "image.jpg"

    # Test find_all
    all_matches = files.find_all()
    assert len(all_matches) == 3
    assert all_matches[0].key == "upload1"
    assert all_matches[0].value == "file1.txt"

    # Test find_string
    string_matches = files.find_string("upload1")
    assert len(string_matches) == 2
    assert string_matches[0].value == "file1.txt"
    assert string_matches[1].value == "file2.txt"

    # Test find_regex
    import re

    regex_matches = files.find_regex(re.compile(r"upload\d+"))
    assert len(regex_matches) == 3


def test_body_collection():
    """Test BodyCollection functionality."""
    body = BodyCollection("REQUEST_BODY")

    # Test text content
    text_content = b"Hello World"
    body.set_content(text_content, "text/plain")

    assert body.get() == "Hello World"
    assert body.get_raw() == text_content
    assert body.get_content_type() == "text/plain"
    assert not body.is_json()
    assert not body.is_xml()

    # Test JSON content
    json_content = b'{"key": "value"}'
    body.set_content(json_content, "application/json")

    assert body.get() == '{"key": "value"}'
    assert body.get_raw() == json_content
    assert body.get_content_type() == "application/json"
    assert body.is_json()
    assert not body.is_xml()

    # Test XML content
    xml_content = b"<root><item>test</item></root>"
    body.set_content(xml_content, "application/xml")

    assert body.get() == "<root><item>test</item></root>"
    assert body.is_xml()
    assert not body.is_json()

    # Test text/xml content type
    body.set_content(xml_content, "text/xml")
    assert body.is_xml()

    # Test find_all
    matches = body.find_all()
    assert len(matches) == 1
    assert matches[0].variable == "REQUEST_BODY"
    assert matches[0].value == "<root><item>test</item></root>"


def test_body_collection_encoding_handling():
    """Test BodyCollection handles different encodings."""
    body = BodyCollection("REQUEST_BODY")

    # Test UTF-8 content
    utf8_content = "Hello 世界".encode("utf-8")
    body.set_content(utf8_content, "text/plain; charset=utf-8")

    assert body.get() == "Hello 世界"

    # Test binary content (non-UTF-8)
    binary_content = b"\x80\x81\x82"
    body.set_content(binary_content, "application/octet-stream")

    # Should handle gracefully with errors='ignore'
    assert body.get() is not None  # Will be some representation of the binary data


def test_transaction_variables_extended():
    """Test extended TransactionVariables functionality."""
    tv = TransactionVariables()

    # Test all core collections exist
    assert hasattr(tv, "args")
    assert hasattr(tv, "request_headers")
    assert hasattr(tv, "tx")
    assert hasattr(tv, "request_uri")

    # Test extended collections exist
    assert hasattr(tv, "request_body")
    assert hasattr(tv, "response_body")
    assert hasattr(tv, "response_headers")
    assert hasattr(tv, "request_cookies")
    assert hasattr(tv, "response_cookies")
    assert hasattr(tv, "files")
    assert hasattr(tv, "multipart_name")

    # Test single value collections
    assert hasattr(tv, "request_method")
    assert hasattr(tv, "request_protocol")
    assert hasattr(tv, "request_line")
    assert hasattr(tv, "response_status")
    assert hasattr(tv, "server_name")
    assert hasattr(tv, "remote_addr")
    assert hasattr(tv, "remote_host")
    assert hasattr(tv, "remote_port")

    # Test content analysis collections
    assert hasattr(tv, "xml")
    assert hasattr(tv, "json")

    # Test geo and matching collections
    assert hasattr(tv, "geo")
    assert hasattr(tv, "matched_var")
    assert hasattr(tv, "matched_var_name")

    # Test environment collections
    assert hasattr(tv, "env")
    assert hasattr(tv, "server_addr")
    assert hasattr(tv, "server_port")


def test_transaction_variables_functionality():
    """Test that extended collections work correctly."""
    tv = TransactionVariables()

    # Test request body
    tv.request_body.set_content(b'{"test": "data"}', "application/json")
    assert tv.request_body.get() == '{"test": "data"}'
    assert tv.request_body.is_json()

    # Test response headers
    tv.response_headers.add("Content-Type", "text/html")
    tv.response_headers.add("Set-Cookie", "session=abc123")

    response_matches = tv.response_headers.find_all()
    assert len(response_matches) == 2

    # Test files
    tv.files.add_file("upload", "test.pdf", b"pdf_content", "application/pdf")
    file_matches = tv.files.find_all()
    assert len(file_matches) == 1
    assert file_matches[0].value == "test.pdf"

    # Test single value collections
    tv.request_method.set("POST")
    tv.response_status.set("200")
    tv.remote_addr.set("192.168.1.100")

    assert tv.request_method.get() == "POST"
    assert tv.response_status.get() == "200"
    assert tv.remote_addr.get() == "192.168.1.100"

    # Test collection names
    assert tv.request_method.name() == "REQUEST_METHOD"
    assert tv.response_headers.name() == "RESPONSE_HEADERS"
    assert tv.files.name() == "FILES"


def test_collection_types():
    """Test that collections have the correct types."""
    tv = TransactionVariables()

    # Map collections
    from coraza_poc.primitives.collections import MapCollection

    assert isinstance(tv.args, MapCollection)
    assert isinstance(tv.request_headers, MapCollection)
    assert isinstance(tv.response_headers, MapCollection)
    assert isinstance(tv.tx, MapCollection)

    # Single value collections
    from coraza_poc.primitives.collections import SingleValueCollection

    assert isinstance(tv.request_uri, SingleValueCollection)
    assert isinstance(tv.request_method, SingleValueCollection)
    assert isinstance(tv.response_status, SingleValueCollection)

    # Body collections
    assert isinstance(tv.request_body, BodyCollection)
    assert isinstance(tv.response_body, BodyCollection)

    # Files collection
    assert isinstance(tv.files, FilesCollection)


def test_collection_case_sensitivity():
    """Test case sensitivity settings for different collections."""
    tv = TransactionVariables()

    # TX collection should be case sensitive
    tv.tx.add("TestKey", "value1")
    tv.tx.add("testkey", "value2")

    # Should have both keys (case sensitive)
    all_tx = tv.tx.find_all()
    keys = [match.key for match in all_tx]
    assert "TestKey" in keys
    assert "testkey" in keys
    assert len(all_tx) == 2

    # Other collections should be case insensitive by default
    tv.request_headers.add("Content-Type", "text/html")
    tv.request_headers.add("content-type", "application/json")

    # Should only have one key (case insensitive)
    content_type_matches = tv.request_headers.find_string("content-type")
    assert len(content_type_matches) == 2  # Two values for same key
    assert content_type_matches[0].key == "content-type"  # Normalized to lowercase


def test_body_collection_empty_content():
    """Test BodyCollection with empty or None content."""
    body = BodyCollection("REQUEST_BODY")

    # Empty content
    body.set_content(b"", "text/plain")
    assert body.get() == ""
    assert body.get_raw() == b""

    # Test find_all with empty content
    matches = body.find_all()
    assert len(matches) == 1
    assert matches[0].value == ""


def test_files_collection_empty():
    """Test FilesCollection when empty."""
    files = FilesCollection()

    # Empty collection
    assert files.find_all() == []
    assert files.get_files("nonexistent") == []
    assert files.find_string("nonexistent") == []

    import re

    assert files.find_regex(re.compile(r".*")) == []
