from coraza_poc.primitives.transformations import lowercase


def test_lowercase_transformation():
    """Tests the lowercase transformation function."""
    assert lowercase("HelloWorld") == ("helloworld", True)
    assert lowercase("helloworld") == ("helloworld", False)
    assert lowercase("") == ("", False)
