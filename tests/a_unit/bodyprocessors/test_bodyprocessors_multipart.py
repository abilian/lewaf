"""Tests for Multipart body processor."""

import pytest

from lewaf.bodyprocessors import BodyProcessorError, get_body_processor
from lewaf.bodyprocessors.multipart import MultipartProcessor


def test_multipart_processor_basic():
    """Test basic multipart parsing with simple fields."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="password"\r\n'
        b"\r\n"
        b"secret123\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    collections = processor.get_collections()
    assert "args_post" in collections
    assert "files" in collections

    args_post = collections["args_post"]
    assert args_post["username"] == "admin"
    assert args_post["password"] == "secret123"
    assert processor.body_parsed


def test_multipart_processor_file_upload():
    """Test file upload parsing."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    file_content = b"This is the file content\nWith multiple lines\n"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="upload.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n" + file_content + b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    collections = processor.get_collections()
    files = collections["files"]
    files_names = collections["files_names"]
    files_sizes = collections["files_sizes"]
    multipart_filename = collections["multipart_filename"]

    assert "file" in files
    assert files["file"] == file_content
    assert files_names["file"] == "file"
    assert files_sizes["file"] == len(file_content)
    assert multipart_filename["file"] == "upload.txt"


def test_multipart_processor_mixed_fields():
    """Test multipart with both form fields and files."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="data.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"file data\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="action"\r\n'
        b"\r\n"
        b"upload\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    collections = processor.get_collections()
    args_post = collections["args_post"]
    files = collections["files"]

    assert args_post["username"] == "admin"
    assert args_post["action"] == "upload"
    assert "file" in files
    assert files["file"] == b"file data"


def test_multipart_processor_multiple_files():
    """Test multiple file uploads."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file1"; filename="file1.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"content1\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file2"; filename="file2.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"content2\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    collections = processor.get_collections()
    files = collections["files"]
    multipart_filename = collections["multipart_filename"]

    assert len(files) == 2
    assert files["file1"] == b"content1"
    assert files["file2"] == b"content2"
    assert multipart_filename["file1"] == "file1.txt"
    assert multipart_filename["file2"] == "file2.txt"


def test_multipart_processor_empty_field():
    """Test multipart with empty field."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="empty"\r\n'
        b"\r\n"
        b"\r\n"
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="nonempty"\r\n'
        b"\r\n"
        b"value\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    args_post = processor.get_collections()["args_post"]
    assert args_post["empty"] == ""
    assert args_post["nonempty"] == "value"


def test_multipart_processor_quoted_boundary():
    """Test boundary with quotes in Content-Type."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="field"\r\n'
        b"\r\n"
        b"value\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    # Boundary in quotes
    processor.read(body, f'multipart/form-data; boundary="{boundary}"')

    args_post = processor.get_collections()["args_post"]
    assert args_post["field"] == "value"


def test_multipart_processor_missing_boundary():
    """Test error when boundary is missing."""
    processor = MultipartProcessor()
    body = b"some data"

    with pytest.raises(BodyProcessorError, match="Missing boundary"):
        processor.read(body, "multipart/form-data")


def test_multipart_processor_too_large():
    """Test size limit protection."""
    processor = MultipartProcessor()
    # Create body larger than max_size (10MB)
    boundary = "----WebKitFormBoundary"
    large_data = b"x" * (11 * 1024 * 1024)
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="large"\r\n'
        b"\r\n" + large_data + b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    with pytest.raises(BodyProcessorError, match="too large"):
        processor.read(body, f"multipart/form-data; boundary={boundary}")


def test_multipart_processor_binary_file():
    """Test binary file upload."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    # Binary data (not valid UTF-8)
    binary_data = bytes(range(256))
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="binary"; filename="data.bin"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n" + binary_data + b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    files = processor.get_collections()["files"]
    assert files["binary"] == binary_data


def test_multipart_processor_special_chars_filename():
    """Test filename with special characters."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="test file (1).txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"content\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    multipart_filename = processor.get_collections()["multipart_filename"]
    assert multipart_filename["file"] == "test file (1).txt"


def test_multipart_processor_find_field():
    """Test find() for form fields."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="username"\r\n'
        b"\r\n"
        b"admin\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    assert processor.find("username") == ["admin"]
    assert processor.find("nonexistent") == []


def test_multipart_processor_find_filename():
    """Test find() for filenames."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="test.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"data\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    assert processor.find("filename:upload") == ["test.txt"]


def test_multipart_processor_find_file_content():
    """Test find() for file content."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    file_data = b"test data"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="upload"; filename="test.txt"\r\n'
        b"Content-Type: text/plain\r\n"
        b"\r\n" + file_data + b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    result = processor.find("file:upload")
    assert len(result) == 1
    # Result is hex encoded
    assert bytes.fromhex(result[0]) == file_data


def test_multipart_processor_no_parts():
    """Test multipart with no parts."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = b"------WebKitFormBoundary--\r\n"

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    collections = processor.get_collections()
    assert len(collections["args_post"]) == 0
    assert len(collections["files"]) == 0


def test_multipart_processor_registry():
    """Test multipart processor via registry."""
    processor = get_body_processor("MULTIPART")
    assert isinstance(processor, MultipartProcessor)

    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="test"\r\n'
        b"\r\n"
        b"value\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")
    assert processor.get_collections()["args_post"]["test"] == "value"


def test_multipart_processor_content_type_detection():
    """Test Content-Type is preserved for files."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="image"; filename="photo.jpg"\r\n'
        b"Content-Type: image/jpeg\r\n"
        b"\r\n"
        b"\xff\xd8\xff\xe0\x00\x10JFIF\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    # Verify file was parsed
    files = processor.get_collections()["files"]
    assert "image" in files
    # Verify the part has correct content type
    assert len(processor.parts) == 1
    assert processor.parts[0].content_type == "image/jpeg"


def test_multipart_processor_part_size_limit():
    """Test individual part size limit."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    # Create part larger than max_part_size (5MB) but smaller than max_size (10MB)
    large_data = b"x" * (6 * 1024 * 1024)
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="large"\r\n'
        b"\r\n" + large_data + b"\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    # Should not raise error, but truncate the part
    processor.read(body, f"multipart/form-data; boundary={boundary}")

    args_post = processor.get_collections()["args_post"]
    # Part should be truncated to max_part_size
    assert len(args_post["large"]) == processor.max_part_size


def test_multipart_processor_unicode_field_value():
    """Test Unicode in field values."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    body = (
        b"------WebKitFormBoundary\r\n"
        b'Content-Disposition: form-data; name="message"\r\n'
        b"\r\n"
        b"Hello \xe4\xb8\x96\xe7\x95\x8c \xf0\x9f\x8c\x8d\r\n"  # "Hello 世界 🌍" in UTF-8
        b"------WebKitFormBoundary--\r\n"
    )

    processor.read(body, f"multipart/form-data; boundary={boundary}")

    args_post = processor.get_collections()["args_post"]
    assert args_post["message"] == "Hello 世界 🌍"


def test_multipart_processor_invalid_part_structure():
    """Test malformed multipart structure."""
    processor = MultipartProcessor()
    boundary = "----WebKitFormBoundary"
    # Missing Content-Disposition header
    body = (
        b"------WebKitFormBoundary\r\n"
        b"\r\n"
        b"data without headers\r\n"
        b"------WebKitFormBoundary--\r\n"
    )

    # Should parse without error, but skip invalid parts
    processor.read(body, f"multipart/form-data; boundary={boundary}")

    args_post = processor.get_collections()["args_post"]
    assert len(args_post) == 0  # Invalid part should be skipped
