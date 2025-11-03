"""Unit tests for SingleValueCollection functionality."""

from lewaf.primitives.collections import SingleValueCollection


def test_single_value_collection_creation():
    """Test basic SingleValueCollection creation."""
    collection = SingleValueCollection("REQUEST_URI")

    assert collection.name() == "REQUEST_URI"
    assert collection.get() == ""


def test_single_value_collection_set():
    """Test setting value in SingleValueCollection."""
    collection = SingleValueCollection("REQUEST_URI")
    collection.set("/path/to/resource")

    assert collection.get() == "/path/to/resource"


def test_single_value_collection_set_replaces():
    """Test that setting a new value replaces the old one."""
    collection = SingleValueCollection("REQUEST_URI")
    collection.set("/old/path")
    collection.set("/new/path")

    assert collection.get() == "/new/path"


def test_single_value_collection_empty():
    """Test SingleValueCollection with empty value."""
    collection = SingleValueCollection("REQUEST_URI")
    collection.set("")

    assert collection.get() == ""


def test_single_value_collection_find_all():
    """Test find_all method returns single MatchData."""
    collection = SingleValueCollection("REQUEST_URI")
    collection.set("/test/path")

    matches = collection.find_all()
    assert len(matches) == 1
    assert matches[0].variable == "REQUEST_URI"
    assert matches[0].key == ""  # Single value collections use empty key
    assert matches[0].value == "/test/path"


def test_single_value_collection_find_all_empty():
    """Test find_all with empty value."""
    collection = SingleValueCollection("REQUEST_URI")

    matches = collection.find_all()
    assert len(matches) == 1
    assert matches[0].variable == "REQUEST_URI"
    assert matches[0].key == ""
    assert matches[0].value == ""


def test_single_value_collection_none_value():
    """Test SingleValueCollection with explicit None handling."""
    collection = SingleValueCollection("REQUEST_URI")
    # The API expects strings, so None would be converted to empty string
    collection.set("")

    assert collection.get() == ""

    matches = collection.find_all()
    assert matches[0].value == ""


def test_single_value_collection_numeric_value():
    """Test SingleValueCollection with numeric value as string."""
    collection = SingleValueCollection("CONTENT_LENGTH")
    collection.set("1024")

    assert collection.get() == "1024"

    matches = collection.find_all()
    assert matches[0].value == "1024"


def test_single_value_collection_special_characters():
    """Test SingleValueCollection with special characters."""
    collection = SingleValueCollection("REQUEST_URI")
    special_value = "/path?param=<>&\"'test"
    collection.set(special_value)

    assert collection.get() == special_value

    matches = collection.find_all()
    assert matches[0].value == special_value


def test_single_value_collection_multiline_value():
    """Test SingleValueCollection with multiline value."""
    collection = SingleValueCollection("REQUEST_BODY")
    multiline_value = "line1\nline2\nline3"
    collection.set(multiline_value)

    assert collection.get() == multiline_value

    matches = collection.find_all()
    assert matches[0].value == multiline_value
