from coraza_poc.primitives.operators import RxOperator


def test_rx_operator():
    """Tests the RxOperator primitive."""
    op = RxOperator(r"^\d+$")
    assert op.evaluate(None, "12345") is True
    assert op.evaluate(None, "abc") is False
    assert op.evaluate(None, "123a") is False
