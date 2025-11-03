"""Test Phase 4 Network Security Features implementation."""

from unittest.mock import Mock, patch

import pytest

from lewaf.primitives.collections import TransactionVariables
from lewaf.primitives.operators import (
    GeoLookupOperator,
    RblOperator,
    OperatorOptions,
)


pytest.skip(allow_module_level=True)


class TestGeoLookupOperator:
    """Tests for the geoLookup operator."""

    def setup_method(self):
        """Setup test fixtures."""
        self.operator = GeoLookupOperator("")
        self.tx = Mock()
        self.tx.variables = TransactionVariables()

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
        """Test handling when transaction doesn't have variables."""
        tx_no_vars = Mock()
        tx_no_vars.variables = None

        result = self.operator.evaluate(tx_no_vars, "8.8.8.8")
        # Should still return True for successful geolocation
        assert result is True

    def test_set_geo_data_method_usage(self):
        """Test that set_geo_data method is preferred when available."""
        # Mock transaction with set_geo_data method
        tx_with_method = Mock()
        tx_with_method.variables = TransactionVariables()

        result = self.operator.evaluate(tx_with_method, "8.8.8.8")
        assert result is True

        # Verify geo data was set
        geo_data = tx_with_method.variables.geo.find_all()
        assert len(geo_data) > 0


class TestRblOperator:
    """Tests for the RBL (Real-time Blacklist) operator."""

    def setup_method(self):
        """Setup test fixtures."""
        self.operator = RblOperator("zen.spamhaus.org")
        self.tx = Mock()
        self.tx.variables = TransactionVariables()

    def test_valid_public_ip(self):
        """Test RBL lookup for valid public IP addresses."""
        with patch("socket.gethostbyname") as mock_dns:
            # Mock a positive RBL match
            mock_dns.return_value = "127.0.0.2"

            result = self.operator.evaluate(self.tx, "1.2.3.4")
            assert result is True

    def test_ip_not_blacklisted(self):
        """Test IP address not found in blacklist."""
        with patch("socket.gethostbyname") as mock_dns:
            # Mock DNS resolution failure (IP not blacklisted)
            mock_dns.side_effect = Exception("DNS resolution failed")

            result = self.operator.evaluate(self.tx, "8.8.8.8")
            assert result is False

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

    def test_multiple_rbl_servers(self):
        """Test RBL operator with multiple blacklist servers."""
        multi_rbl = RblOperator("zen.spamhaus.org,dnsbl.sorbs.net")

        with patch("socket.gethostbyname") as mock_dns:
            # Mock first RBL failure, second RBL success
            mock_dns.side_effect = [Exception("First RBL failed"), "127.0.0.2"]

            result = multi_rbl.evaluate(self.tx, "1.2.3.4")
            assert result is True

    def test_rbl_with_timeout(self):
        """Test RBL lookup with timeout handling."""
        with patch("socket.gethostbyname") as mock_dns:
            # Mock timeout exception
            mock_dns.side_effect = Exception("Timeout")

            result = self.operator.evaluate(self.tx, "1.2.3.4")
            assert result is False


class TestTransactionVariables:
    """Tests for enhanced transaction variables functionality."""

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
    """Integration tests for Phase 4 network security features."""

    def setup_method(self):
        """Setup test fixtures."""
        self.tx = Mock()
        self.tx.variables = TransactionVariables()

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

    def test_blacklist_check_workflow(self):
        """Test RBL blacklist checking workflow."""
        with patch("socket.gethostbyname") as mock_dns:
            mock_dns.return_value = "127.0.0.2"  # Positive match

            # Set up network variables
            self.tx.variables.set_network_variables(remote_addr="1.2.3.4")

            # Perform RBL check
            rbl_operator = RblOperator("zen.spamhaus.org")
            result = rbl_operator.evaluate(self.tx, "1.2.3.4")

            assert result is True

    def test_performance_tracking_workflow(self):
        """Test performance monitoring during rule processing."""
        import time
        import uuid

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
        from lewaf.primitives.operators import get_operator

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
        from lewaf.primitives.operators import get_operator

        # Test various case combinations
        test_cases = ["GEOLOOKUP", "GeoLookup", "geolookup", "geoLOOKUP"]

        for operator_name in test_cases:
            options = OperatorOptions(arguments="")
            operator = get_operator(operator_name, options)
            assert isinstance(operator, GeoLookupOperator)
