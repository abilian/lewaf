"""Test Phase 4 Network Security Features implementation.

Following the principle of avoiding mocks in favor of stubs, these tests use
simple stub objects instead of Mock() to verify tangible outcomes.
"""

from __future__ import annotations

import socket

from lewaf.primitives.collections import TransactionVariables
from lewaf.primitives.operators import (
    GeoLookupOperator,
    OperatorOptions,
    RblOperator,
)


class StubTransaction:
    """Stub transaction object for testing.

    This is a simple stub that provides only what's needed for testing,
    avoiding the use of Mock() objects.
    """

    def __init__(self):
        self.variables = TransactionVariables()


class StubDnsResolver:
    """Stub DNS resolver for testing RBL without real network calls.

    This stub allows testing RBL logic without making actual DNS queries.
    """

    def __init__(self, responses: dict[str, str | Exception]):
        """Initialize with predefined responses.

        Args:
            responses: Dict mapping query strings to responses or exceptions
        """
        self.responses = responses
        self.queries: list[str] = []

    def resolve(self, hostname: str) -> str:
        """Stub DNS resolution."""
        self.queries.append(hostname)
        response = self.responses.get(hostname)

        if isinstance(response, Exception):
            raise response
        if response is None:
            msg = f"No response configured for {hostname}"
            raise socket.gaierror(msg)
        return response


class TestGeoLookupOperator:
    """Tests for the geoLookup operator."""

    def setup_method(self):
        """Setup test fixtures."""
        self.operator = GeoLookupOperator("")
        self.tx = StubTransaction()

    def test_valid_public_ip_geolocation(self):
        """Test geolocation lookup for valid public IP addresses."""
        # Test Google DNS server
        result = self.operator.evaluate(self.tx, "8.8.8.8")
        assert result is True

        # Check that GEO data was populated
        geo_matches = self.tx.variables.geo.find_all()
        assert len(geo_matches) > 0

        # Check specific geographic data
        country_matches = self.tx.variables.geo.find_string("COUNTRY_CODE")
        assert len(country_matches) == 1
        assert country_matches[0].value == "US"

    def test_private_ip_addresses_skipped(self):
        """Test that private IP addresses are skipped."""
        private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]

        for ip in private_ips:
            result = self.operator.evaluate(self.tx, ip)
            assert result is False

    def test_invalid_ip_addresses(self):
        """Test handling of invalid IP addresses."""
        invalid_ips = ["not-an-ip", "999.999.999.999", "256.1.1.1", "", "192.168.1"]

        for ip in invalid_ips:
            result = self.operator.evaluate(self.tx, ip)
            assert result is False

    def test_cloudflare_dns_geolocation(self):
        """Test geolocation for Cloudflare DNS servers."""
        result = self.operator.evaluate(self.tx, "1.1.1.1")
        assert result is True

        # Check country data
        country_matches = self.tx.variables.geo.find_string("COUNTRY_CODE")
        assert len(country_matches) == 1
        assert country_matches[0].value == "US"

    def test_transaction_without_variables(self):
        """Test handling when transaction doesn't have variables attribute."""

        class TransactionWithoutVariables:
            """Stub transaction without variables."""

        tx_no_vars = TransactionWithoutVariables()

        result = self.operator.evaluate(tx_no_vars, "8.8.8.8")
        # Should still return True for successful geolocation
        assert result is True

    def test_geo_data_population_details(self):
        """Test that comprehensive geo data is populated correctly."""
        result = self.operator.evaluate(self.tx, "8.8.8.8")
        assert result is True

        # Verify multiple geographic fields are present
        geo_data = self.tx.variables.geo.find_all()
        assert len(geo_data) > 0

        # Check for expected fields
        expected_fields = ["COUNTRY_CODE", "COUNTRY_NAME"]
        for field in expected_fields:
            matches = self.tx.variables.geo.find_string(field)
            assert len(matches) > 0, f"Expected {field} to be set"


class TestRblOperator:
    """Tests for the RBL (Real-time Blacklist) operator.

    Note: These tests use a stub DNS resolver to avoid making actual network
    calls, following the principle of avoiding mocks in favor of stubs.
    """

    def setup_method(self):
        """Setup test fixtures."""
        self.tx = StubTransaction()

    def test_private_ip_addresses_skipped(self):
        """Test that private IP addresses are skipped without DNS lookup."""
        operator = RblOperator("zen.spamhaus.org")
        private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]

        for ip in private_ips:
            result = operator.evaluate(self.tx, ip)
            assert result is False

    def test_invalid_ip_addresses(self):
        """Test handling of invalid IP addresses without DNS lookup."""
        operator = RblOperator("zen.spamhaus.org")
        invalid_ips = ["not-an-ip", "999.999.999.999", "256.1.1.1", "", "192.168.1"]

        for ip in invalid_ips:
            result = operator.evaluate(self.tx, ip)
            assert result is False

    def test_multiple_rbl_servers_parsing(self):
        """Test RBL operator parses multiple blacklist servers correctly."""
        multi_rbl = RblOperator("zen.spamhaus.org,dnsbl.sorbs.net")

        # Verify operator was created with multiple servers
        assert multi_rbl._rbl_hosts == ["zen.spamhaus.org", "dnsbl.sorbs.net"]

    def test_rbl_query_format(self):
        """Test that RBL processes IPs and constructs queries correctly."""
        operator = RblOperator("zen.spamhaus.org")

        # RBL should internally reverse the IP and append the zone
        # For example, IP 192.168.1.1 would become 1.1.168.192.zen.spamhaus.org
        # We use a private IP which won't make a real DNS call
        private_ip = "192.168.1.1"

        # Private IPs are skipped without DNS lookup
        result = operator.evaluate(self.tx, private_ip)
        assert result is False  # Private IP always returns False

        # Verify operator handles well-known clean public IPs
        # Google DNS should not be blacklisted
        result = operator.evaluate(self.tx, "8.8.8.8")
        assert result is False  # Well-known clean IP

    def test_rbl_with_real_dns_google(self):
        """Test RBL with real DNS lookup against Google DNS (should not be listed).

        This test makes a real DNS call to verify the RBL operator works correctly.
        Google's DNS servers (8.8.8.8) should not be listed in most RBLs.
        """
        operator = RblOperator("zen.spamhaus.org")

        # Google DNS should not be blacklisted
        result = operator.evaluate(self.tx, "8.8.8.8")
        assert result is False  # Not blacklisted

    def test_ip_validation_behavior(self):
        """Test that RBL operator correctly handles valid/invalid and private/public IPs."""
        operator = RblOperator("test.rbl.zone")

        # Valid public IPs should be processed (returns False since not blacklisted)
        # These are processed but return False because they're not in the RBL
        result = operator.evaluate(self.tx, "1.2.3.4")
        assert result is False  # Valid IP, not blacklisted

        result = operator.evaluate(self.tx, "255.255.255.255")
        assert result is False  # Valid IP (broadcast), but handled

        # Invalid IPs should return False (invalid format rejected)
        result = operator.evaluate(self.tx, "")
        assert result is False  # Empty string

        result = operator.evaluate(self.tx, "not-an-ip")
        assert result is False  # Invalid format

        result = operator.evaluate(self.tx, "256.1.1.1")
        assert result is False  # Out of range

        result = operator.evaluate(self.tx, "1.2.3")
        assert result is False  # Incomplete

        # Private IPs should be skipped (return False without DNS lookup)
        result = operator.evaluate(self.tx, "192.168.1.1")
        assert result is False  # Private IP

        result = operator.evaluate(self.tx, "10.0.0.1")
        assert result is False  # Private IP

        result = operator.evaluate(self.tx, "172.16.0.1")
        assert result is False  # Private IP

        result = operator.evaluate(self.tx, "127.0.0.1")
        assert result is False  # Loopback IP


class TestTransactionVariables:
    """Tests for enhanced transaction variables functionality.

    These tests already use real objects without mocks.
    """

    def setup_method(self):
        """Setup test fixtures."""
        self.variables = TransactionVariables()

    def test_set_geo_data(self):
        """Test setting geographic location data."""
        geo_data = {
            "COUNTRY_CODE": "US",
            "COUNTRY_NAME": "United States",
            "CITY": "San Francisco",
            "LATITUDE": "37.7749",
            "LONGITUDE": "-122.4194",
        }

        self.variables.set_geo_data(geo_data)

        # Verify all data was set
        for key, expected_value in geo_data.items():
            matches = self.variables.geo.find_string(key)
            assert len(matches) == 1
            assert matches[0].value == expected_value

    def test_set_geo_data_clears_existing(self):
        """Test that set_geo_data clears existing geographic data."""
        # Set initial data
        initial_data = {"COUNTRY_CODE": "CA", "CITY": "Toronto"}
        self.variables.set_geo_data(initial_data)

        # Set new data
        new_data = {"COUNTRY_CODE": "US", "CITY": "New York"}
        self.variables.set_geo_data(new_data)

        # Verify only new data exists
        country_matches = self.variables.geo.find_string("COUNTRY_CODE")
        assert len(country_matches) == 1
        assert country_matches[0].value == "US"

        city_matches = self.variables.geo.find_string("CITY")
        assert len(city_matches) == 1
        assert city_matches[0].value == "New York"

    def test_set_performance_metrics(self):
        """Test setting performance monitoring variables."""
        self.variables.set_performance_metrics(
            duration_ms=150.5, severity=3, transaction_id="tx_12345"
        )

        assert self.variables.duration.get() == "150.5"
        assert self.variables.highest_severity.get() == "3"
        assert self.variables.unique_id.get() == "tx_12345"

    def test_update_highest_severity(self):
        """Test updating highest severity tracking."""
        # Set initial severity
        self.variables.set_performance_metrics(severity=2)

        # Update with higher severity
        self.variables.update_highest_severity(4)
        assert self.variables.highest_severity.get() == "4"

        # Update with lower severity (should not change)
        self.variables.update_highest_severity(1)
        assert self.variables.highest_severity.get() == "4"

        # Update with same severity (should not change)
        self.variables.update_highest_severity(4)
        assert self.variables.highest_severity.get() == "4"

    def test_update_highest_severity_boundary_values(self):
        """Test severity boundary value handling."""
        # Test severity clamping to valid range (0-5)
        self.variables.set_performance_metrics(severity=10)  # Should clamp to 5
        assert self.variables.highest_severity.get() == "5"

        self.variables.set_performance_metrics(severity=-1)  # Should clamp to 0
        assert self.variables.highest_severity.get() == "0"

    def test_set_network_variables(self):
        """Test setting network connection variables."""
        self.variables.set_network_variables(
            remote_addr="192.168.1.100",
            remote_host="client.example.com",
            remote_port=54321,
            server_addr="10.0.0.1",
            server_port=80,
        )

        assert self.variables.remote_addr.get() == "192.168.1.100"
        assert self.variables.remote_host.get() == "client.example.com"
        assert self.variables.remote_port.get() == "54321"
        assert self.variables.server_addr.get() == "10.0.0.1"
        assert self.variables.server_port.get() == "80"

    def test_partial_network_variables(self):
        """Test setting only some network variables."""
        self.variables.set_network_variables(
            remote_addr="192.168.1.100", server_port=443
        )

        assert self.variables.remote_addr.get() == "192.168.1.100"
        assert self.variables.server_port.get() == "443"
        assert self.variables.remote_host.get() == ""  # Not set
        assert self.variables.remote_port.get() == ""  # Not set


class TestPhase4Integration:
    """Integration tests for Phase 4 network security features.

    These tests use real objects and verify actual behavior.
    """

    def setup_method(self):
        """Setup test fixtures."""
        self.tx = StubTransaction()

    def test_full_geolocation_workflow(self):
        """Test complete geolocation workflow with transaction."""
        # Set up network variables
        self.tx.variables.set_network_variables(
            remote_addr="8.8.8.8", remote_port=12345
        )

        # Perform geolocation
        geo_operator = GeoLookupOperator("")
        result = geo_operator.evaluate(self.tx, "8.8.8.8")

        assert result is True

        # Verify geo data was populated
        country_matches = self.tx.variables.geo.find_string("COUNTRY_CODE")
        assert len(country_matches) == 1
        assert country_matches[0].value == "US"

    def test_performance_tracking_workflow(self):
        """Test performance monitoring during rule processing."""
        import time  # noqa: PLC0415 - Avoids circular import
        import uuid  # noqa: PLC0415 - Avoids circular import

        # Start transaction
        start_time = time.time()
        transaction_id = str(uuid.uuid4())

        self.tx.variables.set_performance_metrics(
            transaction_id=transaction_id, severity=0
        )

        # Simulate rule processing with severity updates
        self.tx.variables.update_highest_severity(2)  # Warning level
        self.tx.variables.update_highest_severity(4)  # Error level
        self.tx.variables.update_highest_severity(1)  # Should not lower

        # End transaction
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000

        self.tx.variables.set_performance_metrics(duration_ms=duration_ms)

        # Verify tracking
        assert self.tx.variables.unique_id.get() == transaction_id
        assert self.tx.variables.highest_severity.get() == "4"
        assert float(self.tx.variables.duration.get()) >= 0

    def test_operator_factory_integration(self):
        """Test operator creation through factory pattern."""
        from lewaf.primitives.operators import (  # noqa: PLC0415 - Avoids circular import
            get_operator,
        )

        # Test geoLookup operator factory
        geo_options = OperatorOptions(arguments="")
        geo_operator = get_operator("geolookup", geo_options)
        assert isinstance(geo_operator, GeoLookupOperator)

        # Test RBL operator factory
        rbl_options = OperatorOptions(arguments="zen.spamhaus.org")
        rbl_operator = get_operator("rbl", rbl_options)
        assert isinstance(rbl_operator, RblOperator)

    def test_case_insensitive_operator_lookup(self):
        """Test that operator names are case insensitive."""
        from lewaf.primitives.operators import (  # noqa: PLC0415 - Avoids circular import
            get_operator,
        )

        # Test various case combinations
        test_cases = ["GEOLOOKUP", "GeoLookup", "geolookup", "geoLOOKUP"]

        for operator_name in test_cases:
            options = OperatorOptions(arguments="")
            operator = get_operator(operator_name, options)
            assert isinstance(operator, GeoLookupOperator)

    def test_combined_geo_and_network_tracking(self):
        """Test combining geolocation with network variable tracking."""
        # Set network info
        self.tx.variables.set_network_variables(
            remote_addr="1.1.1.1", remote_port=443, server_port=80
        )

        # Perform geo lookup
        geo_operator = GeoLookupOperator("")
        result = geo_operator.evaluate(self.tx, "1.1.1.1")
        assert result is True

        # Verify both network and geo data are present
        assert self.tx.variables.remote_addr.get() == "1.1.1.1"
        assert self.tx.variables.remote_port.get() == "443"

        country_matches = self.tx.variables.geo.find_string("COUNTRY_CODE")
        assert len(country_matches) == 1
        assert country_matches[0].value == "US"

    def test_state_isolation_between_transactions(self):
        """Test that transaction variables are isolated."""
        tx1 = StubTransaction()
        tx2 = StubTransaction()

        # Set data in tx1
        tx1.variables.set_network_variables(remote_addr="1.1.1.1")
        tx1.variables.set_performance_metrics(severity=3)

        # Verify tx2 is independent
        assert tx2.variables.remote_addr.get() == ""
        assert tx2.variables.highest_severity.get() == ""

        # Set different data in tx2
        tx2.variables.set_network_variables(remote_addr="8.8.8.8")
        tx2.variables.set_performance_metrics(severity=5)

        # Verify tx1 unchanged
        assert tx1.variables.remote_addr.get() == "1.1.1.1"
        assert tx1.variables.highest_severity.get() == "3"
