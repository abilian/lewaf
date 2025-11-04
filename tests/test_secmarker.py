"""Tests for SecMarker directive and skipAfter action integration."""

from lewaf.integration import WAF
from lewaf.seclang import SecLangParser


def test_secmarker_basic():
    """Test that SecMarker creates a marker rule."""
    waf = WAF({"rules": []})
    parser = SecLangParser(waf)

    # Parse a marker
    parser.from_string('SecMarker "TEST_MARKER"')

    # Should create one rule (the marker rule) in phase 1
    rules = waf.rule_group.rules_by_phase[1]
    assert len(rules) == 1
    # Marker rule should have the marker name as a tag
    assert "TEST_MARKER" in rules[0].tags


def test_skipafter_with_marker():
    """Test that skipAfter can target SecMarker."""
    waf = WAF({"rules": []})
    parser = SecLangParser(waf)

    # Create rules with skipAfter and marker
    parser.from_string("""
        SecRule ARGS:test "@rx pattern1" "id:1,phase:1,pass,log"
        SecRule REQUEST_URI "@unconditional" "id:2,phase:1,pass,skipAfter:END_TEST"
        SecRule ARGS:test "@rx pattern2" "id:3,phase:1,deny,log"
        SecMarker "END_TEST"
        SecRule ARGS:test "@rx pattern3" "id:4,phase:1,pass,log"
    """)

    # Should create 5 rules (3 regular + 1 skipAfter + 1 marker)
    rules = waf.rule_group.rules_by_phase[1]
    assert len(rules) >= 4

    # Test that skip logic works
    from lewaf.transaction import Transaction

    tx = Transaction(waf, "test-1")
    tx.variables.request_headers.add("Host", "example.com")
    tx.process_uri("/test", "GET")
    tx.variables.args.add("test", "pattern2_match")

    # Evaluate phase 1 rules
    waf.rule_group.evaluate(1, tx)

    # Rule 2 should trigger skipAfter:END_TEST
    # Rule 3 should be skipped (wouldn't deny)
    # Should reach rule 4 after marker
    assert tx.interruption is None


def test_skipafter_paranoia_level_pattern():
    """Test CRS paranoia level filtering pattern."""
    waf = WAF({"rules": []})
    parser = SecLangParser(waf)

    # Simulate CRS paranoia level pattern
    parser.from_string("""
        SecAction "id:1,phase:1,nolog,pass,setvar:tx.paranoia_level=1"
        SecRule TX:paranoia_level "@lt 2" "id:2,phase:1,pass,nolog,skipAfter:END_CHECKS"
        SecRule ARGS:test "@rx high_paranoia" "id:3,phase:1,deny,log"
        SecMarker "END_CHECKS"
        SecRule ARGS:test "@rx normal" "id:4,phase:1,pass,log"
    """)

    # Paranoia level 1 should skip rule 3 but execute rule 4
    from lewaf.transaction import Transaction

    tx = Transaction(waf, "test-2")
    tx.variables.request_headers.add("Host", "example.com")
    tx.process_uri("/test", "GET")
    tx.variables.args.add("test", "high_paranoia")

    waf.rule_group.evaluate(1, tx)

    # Rule 3 should have been skipped, so no denial
    assert tx.interruption is None


def test_seccomponentsignature():
    """Test that SecComponentSignature is parsed."""
    waf = WAF({"rules": []})
    parser = SecLangParser(waf)

    # Parse component signature
    parser.from_string('SecComponentSignature "OWASP_CRS/3.3.4"')

    # Should set component signature
    assert hasattr(waf, "component_signature")
    assert waf.component_signature == "OWASP_CRS/3.3.4"
