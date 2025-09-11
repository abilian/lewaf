"""Integration tests for loading and using CRS rules."""

import pytest
from pathlib import Path

from coraza_poc.integration import WAF
from coraza_poc.transaction import Transaction


def test_load_crs_method_enforcement():
    """Test loading and using CRS METHOD-ENFORCEMENT rules."""
    rules_dir = Path(__file__).parent.parent / "rules"
    method_file = rules_dir / "REQUEST-911-METHOD-ENFORCEMENT.conf"
    
    if not method_file.exists():
        pytest.skip("CRS METHOD-ENFORCEMENT file not found")
    
    content = method_file.read_text(encoding='utf-8')
    
    # Extract a simple rule we can parse
    simple_rules = []
    for line in content.split('\n'):
        line = line.strip()
        if (line.startswith('SecRule') and 
            'nolog' in line and 
            'skipAfter' in line and
            len(line) < 200):  # Simple rule
            simple_rules.append(line)
    
    if not simple_rules:
        pytest.skip("No suitable simple rules found in METHOD-ENFORCEMENT file")
    
    # Create WAF with one of the simple rules
    config = {"rules": [simple_rules[0]]}
    
    try:
        waf = WAF(config)
        tx = waf.new_transaction()
        
        assert isinstance(tx, Transaction)
        assert tx.waf is waf
        print(f"Successfully loaded CRS rule: {simple_rules[0][:80]}...")
        
    except Exception as e:
        pytest.fail(f"Failed to load CRS rule: {e}")


def test_crs_rule_components():
    """Test that CRS rules have expected components."""
    rules_dir = Path(__file__).parent.parent / "rules"
    files = list(rules_dir.glob("REQUEST-*.conf"))
    
    if not files:
        pytest.skip("No CRS REQUEST files found")
    
    # Check a few key files for expected content
    method_file = rules_dir / "REQUEST-911-METHOD-ENFORCEMENT.conf"
    sqli_file = rules_dir / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf" 
    xss_file = rules_dir / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
    
    for rule_file in [method_file, sqli_file, xss_file]:
        if rule_file.exists():
            content = rule_file.read_text(encoding='utf-8')
            
            # Should have rule IDs in expected ranges
            if "911" in rule_file.name:
                assert "id:911" in content, f"METHOD rules should have 911xxx IDs"
            elif "942" in rule_file.name:
                assert "id:942" in content, f"SQLI rules should have 942xxx IDs"  
            elif "941" in rule_file.name:
                assert "id:941" in content, f"XSS rules should have 941xxx IDs"
            
            # Should have phase declarations
            assert "phase:" in content, f"Rules should specify phases in {rule_file.name}"
            
            # Should have OWASP_CRS tags
            assert "OWASP_CRS" in content, f"Rules should have OWASP_CRS tag in {rule_file.name}"


def test_crs_paranoia_levels():
    """Test CRS paranoia level structure."""
    rules_dir = Path(__file__).parent.parent / "rules"
    files = list(rules_dir.glob("REQUEST-9*.conf"))
    
    if not files:
        pytest.skip("No CRS 9xx rule files found")
    
    paranoia_markers = []
    
    for rule_file in files:
        content = rule_file.read_text(encoding='utf-8')
        
        # Look for paranoia level markers
        lines = content.split('\n')
        for line in lines:
            if "Paranoia Level" in line and "=" in line:
                paranoia_markers.append(line.strip())
    
    # Should have multiple paranoia levels
    assert len(paranoia_markers) > 10, f"Expected multiple paranoia level markers, found {len(paranoia_markers)}"
    
    # Should have levels 0-4
    content_str = "\n".join(paranoia_markers)
    for level in [0, 1, 2, 3]:
        assert f"Level {level}" in content_str, f"Should have paranoia level {level} markers"


def test_crs_data_file_references():
    """Test that CRS rules reference existing data files."""
    rules_dir = Path(__file__).parent.parent / "rules"
    
    # Get all .conf files
    conf_files = list(rules_dir.glob("*.conf"))
    if not conf_files:
        pytest.skip("No CRS configuration files found")
    
    # Get all .data files
    data_files = list(rules_dir.glob("*.data"))
    data_file_names = [f.name for f in data_files]
    
    referenced_files = set()
    
    # Look for data file references in rules
    for conf_file in conf_files:
        if conf_file.name.endswith('.example'):
            continue
            
        content = conf_file.read_text(encoding='utf-8')
        
        # Look for .data file references
        for data_name in data_file_names:
            if data_name in content:
                referenced_files.add(data_name)
    
    # Should have references to major data files
    expected_files = ['php-errors.data', 'sql-errors.data', 'unix-shell.data']
    for expected in expected_files:
        if expected in data_file_names:
            assert expected in referenced_files, f"Expected reference to {expected} in CRS rules"


def test_sample_crs_rule_parsing():
    """Test parsing various types of CRS rules."""
    
    # Sample rules from different CRS files (simplified versions)
    sample_rules = [
        # Simple paranoia level check (from any 9xx file)
        'SecRule TX:DETECTION_PARANOIA_LEVEL "@lt 1" "id:911011,phase:1,pass,nolog,skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT"',
        
        # Basic method check (simplified from REQUEST-911)
        'SecRule REQUEST_METHOD "@within GET POST" "id:911100,phase:1,block,msg:\'Method is not allowed\'"',
        
        # XSS detection (simplified from REQUEST-941) 
        'SecRule ARGS "@detectXSS" "id:941100,phase:2,block,msg:\'XSS Attack Detected\'"',
        
        # SQL injection detection (simplified from REQUEST-942)
        'SecRule ARGS "@detectSQLi" "id:942100,phase:2,block,msg:\'SQL Injection Attack\'"',
    ]
    
    parsed_count = 0
    
    for rule in sample_rules:
        try:
            config = {"rules": [rule]}
            waf = WAF(config)
            tx = waf.new_transaction()
            parsed_count += 1
            print(f"✓ Parsed: {rule[:60]}...")
            
        except Exception as e:
            print(f"✗ Failed: {rule[:60]}... - {e}")
    
    # Should parse most sample rules
    success_rate = parsed_count / len(sample_rules)
    assert success_rate >= 0.75, f"Should parse most sample rules, got {success_rate:.1%} success rate"


def test_crs_rule_metadata():
    """Test that CRS rules contain expected metadata."""
    rules_dir = Path(__file__).parent.parent / "rules"
    
    # Read a few rule files
    test_files = [
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf", 
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf"
    ]
    
    metadata_found = {
        'rule_ids': [],
        'phases': set(),
        'messages': [],
        'tags': [],
        'severity': []
    }
    
    for filename in test_files:
        file_path = rules_dir / filename
        if not file_path.exists():
            continue
            
        content = file_path.read_text(encoding='utf-8')
        
        # Extract metadata from rules
        lines = content.split('\n')
        for line in lines:
            if 'id:' in line:
                # Extract rule ID
                import re
                id_match = re.search(r'id:(\d+)', line)
                if id_match:
                    metadata_found['rule_ids'].append(int(id_match.group(1)))
            
            if 'phase:' in line:
                # Extract phase
                phase_match = re.search(r'phase:(\d+)', line)
                if phase_match:
                    metadata_found['phases'].add(int(phase_match.group(1)))
            
            if 'msg:' in line:
                metadata_found['messages'].append(line)
                
            if 'tag:' in line:
                metadata_found['tags'].append(line)
                
            if 'severity:' in line:
                metadata_found['severity'].append(line)
    
    # Validate metadata
    assert len(metadata_found['rule_ids']) > 10, "Should find multiple rule IDs"
    assert len(metadata_found['phases']) >= 2, "Should find multiple phases"
    assert len(metadata_found['messages']) > 5, "Should find rule messages"
    assert len(metadata_found['tags']) > 5, "Should find rule tags"
    
    # Check phase ranges (should be 1-5)
    for phase in metadata_found['phases']:
        assert 1 <= phase <= 5, f"Phase {phase} should be in range 1-5"
    
    # Check rule ID ranges
    rule_id_ranges = {
        900: "initialization",
        910: "method enforcement", 
        920: "protocol enforcement",
        930: "LFI attacks",
        940: "XSS attacks", 
        942: "SQLi attacks"
    }
    
    found_ranges = set()
    for rule_id in metadata_found['rule_ids'][:20]:  # Check first 20
        rule_range = (rule_id // 10) * 10  # Get range like 940, 920, etc.
        if rule_range in rule_id_ranges:
            found_ranges.add(rule_range)
    
    assert len(found_ranges) >= 2, f"Should find rules from multiple ranges, found: {found_ranges}"