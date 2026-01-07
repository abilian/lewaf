"""Network-related operators (IP matching, geolocation, RBL)."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket

from ._base import (
    Operator,
    TransactionProtocol,
    get_dataset,
    register_operator,
)


@register_operator("ipmatch")
class IpMatchOperator(Operator):
    """IP address/network matching operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        # Parse IP address or CIDR network
        try:
            self._network = ipaddress.ip_network(argument, strict=False)
        except ValueError:
            # Fallback to exact IP match
            try:
                self._network = ipaddress.ip_network(f"{argument}/32", strict=False)
            except ValueError:
                self._network = None

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if IP address matches the network/address."""
        if not self._network:
            return False

        try:
            ip = ipaddress.ip_address(value.strip())
            return ip in self._network
        except ValueError:
            return False


@register_operator("ipmatchfromfile")
class IpMatchFromFileOperator(Operator):
    """IP address matching from file operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._file_path = argument.strip()
        self._ip_list = self._load_ip_list()

    def _load_ip_list(self) -> list[str]:
        """Load IP addresses and networks from file."""
        if not self._file_path:
            msg = "IpMatchFromFile operator requires a file path"
            raise ValueError(msg)

        # Security check: prevent path traversal
        if ".." in self._file_path:
            msg = f"IpMatchFromFile: Path traversal not allowed: {self._file_path}"
            raise ValueError(msg)

        ip_list: list[str] = []
        try:
            # Check if file exists
            if not os.path.exists(self._file_path):
                # For now, just log and continue with empty list
                logging.warning(f"IpMatchFromFile: File not found: {self._file_path}")
                return ip_list

            with open(self._file_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        ip_list.append(line)
        except Exception as e:
            logging.error(f"IpMatchFromFile: Error loading file {self._file_path}: {e}")

        return ip_list

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if IP address matches any in the file."""
        if not self._ip_list:
            return False

        try:
            # Parse the input IP address
            input_ip = ipaddress.ip_address(value.strip())

            # Check against each IP/network in the list
            for ip_entry in self._ip_list:
                try:
                    # Try as network first (CIDR notation)
                    if "/" in ip_entry:
                        network = ipaddress.ip_network(ip_entry, strict=False)
                        if input_ip in network:
                            return True
                    else:
                        # Try as individual IP
                        list_ip = ipaddress.ip_address(ip_entry)
                        if input_ip == list_ip:
                            return True
                except ValueError:
                    # Invalid IP format in file, skip it
                    continue

        except ValueError:
            # Invalid input IP address
            return False

        return False


@register_operator("ipmatchfromdataset")
class IpMatchFromDatasetOperator(Operator):
    """IP address matching from dataset operator."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._dataset_name = argument.strip()
        if not self._dataset_name:
            msg = "IpMatchFromDataset operator requires a dataset name"
            raise ValueError(msg)

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Check if IP address matches any in the dataset."""
        ip_list = get_dataset(self._dataset_name)
        if not ip_list:
            return False

        try:
            # Parse the input IP address
            input_ip = ipaddress.ip_address(value.strip())

            # Check against each IP/network in the dataset
            for ip_entry in ip_list:
                try:
                    # Try as network first (CIDR notation)
                    if "/" in ip_entry:
                        network = ipaddress.ip_network(ip_entry, strict=False)
                        if input_ip in network:
                            return True
                    else:
                        # Try as individual IP
                        list_ip = ipaddress.ip_address(ip_entry)
                        if input_ip == list_ip:
                            return True
                except ValueError:
                    # Invalid IP format in dataset, skip it
                    continue

        except ValueError:
            # Invalid input IP address
            return False

        return False


@register_operator("geolookup")
class GeoLookupOperator(Operator):
    """
    Geographic IP lookup operator for threat assessment.

    Performs IP geolocation and populates GEO collection variables:
    - GEO:COUNTRY_CODE (ISO 3166-1 alpha-2)
    - GEO:COUNTRY_CODE3 (ISO 3166-1 alpha-3)
    - GEO:COUNTRY_NAME (full country name)
    - GEO:COUNTRY_CONTINENT (continent code)
    - GEO:REGION (region/state code)
    - GEO:CITY (city name)
    - GEO:POSTAL_CODE (postal/zip code)
    - GEO:LATITUDE (latitude coordinate)
    - GEO:LONGITUDE (longitude coordinate)
    """

    def __init__(self, argument: str):
        super().__init__(argument)
        # Argument can specify the geolocation database path
        # For now, we'll use a simple mock implementation for demonstration
        self._db_path = argument if argument else None

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """
        Perform geolocation lookup on the input IP address.

        Args:
            tx: Transaction context
            value: IP address to lookup

        Returns:
            bool: True if geolocation data was successfully populated
        """
        try:
            # Validate IP address format
            ip_addr = ipaddress.ip_address(value.strip())

            # Skip private/local IP addresses
            if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_reserved:
                return False

            # For this implementation, we'll provide mock geolocation data
            # In a real implementation, this would query MaxMind GeoIP2 or similar
            geo_data = self._get_geolocation_data(str(ip_addr))

            if geo_data:
                # Populate GEO collection variables in transaction
                tx.variables.set_geo_data(geo_data)
                return True

            return False

        except ValueError:
            # Invalid IP address format
            return False

    def _get_geolocation_data(self, ip_address: str) -> dict[str, str] | None:
        """
        Get geolocation data for an IP address.

        This is a mock implementation. In production, this would integrate
        with MaxMind GeoIP2, IP2Location, or another geolocation service.

        Args:
            ip_address: IP address to lookup

        Returns:
            dict: Geolocation data or None if not found
        """
        # Mock data for common IP ranges for demonstration
        # In production, this would query an actual geolocation database

        # Example: Classify some known IP ranges
        if ip_address.startswith(("8.8.8.", "8.8.4.")):
            # Google DNS servers - mock as US
            return {
                "COUNTRY_CODE": "US",
                "COUNTRY_CODE3": "USA",
                "COUNTRY_NAME": "United States",
                "COUNTRY_CONTINENT": "NA",
                "REGION": "CA",
                "CITY": "Mountain View",
                "POSTAL_CODE": "94043",
                "LATITUDE": "37.4056",
                "LONGITUDE": "-122.0775",
            }
        if ip_address.startswith(("1.1.1.", "1.0.0.")):
            # Cloudflare DNS - mock as US
            return {
                "COUNTRY_CODE": "US",
                "COUNTRY_CODE3": "USA",
                "COUNTRY_NAME": "United States",
                "COUNTRY_CONTINENT": "NA",
                "REGION": "CA",
                "CITY": "San Francisco",
                "POSTAL_CODE": "94102",
                "LATITUDE": "37.7749",
                "LONGITUDE": "-122.4194",
            }
        # Default/unknown - mock as generic location
        return {
            "COUNTRY_CODE": "XX",
            "COUNTRY_CODE3": "XXX",
            "COUNTRY_NAME": "Unknown",
            "COUNTRY_CONTINENT": "XX",
            "REGION": "XX",
            "CITY": "Unknown",
            "POSTAL_CODE": "",
            "LATITUDE": "0.0000",
            "LONGITUDE": "0.0000",
        }


@register_operator("rbl")
class RblOperator(Operator):
    """
    Real-time Blacklist (RBL) operator for threat intelligence integration.

    Checks IP addresses against DNS-based blacklists (DNSBL) for known threats:
    - Spam sources
    - Malware command & control servers
    - Known attackers
    - Compromised hosts
    - Tor exit nodes
    """

    def __init__(self, argument: str):
        super().__init__(argument)
        # Argument specifies the RBL hostname(s) to check
        # Format: "rbl1.example.com,rbl2.example.com" or single hostname
        self._rbl_hosts = []
        if argument:
            self._rbl_hosts = [host.strip() for host in argument.split(",")]
        else:
            # Default to common RBL services
            self._rbl_hosts = [
                "zen.spamhaus.org",
                "bl.spamcop.net",
                "dnsbl.sorbs.net",
                "cbl.abuseat.org",
            ]

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """
        Check if IP address is listed in configured RBL services.

        Args:
            tx: Transaction context
            value: IP address to check

        Returns:
            bool: True if IP is found in any RBL
        """
        try:
            # Validate IP address format
            ip_addr = ipaddress.ip_address(value.strip())

            # Skip private/local IP addresses - they won't be in public RBLs
            if ip_addr.is_private or ip_addr.is_loopback or ip_addr.is_reserved:
                return False

            # Reverse the IP address for DNS lookup
            # e.g., 192.168.1.1 becomes 1.1.168.192
            ip_parts = str(ip_addr).split(".")
            reversed_ip = ".".join(reversed(ip_parts))

            # Check each configured RBL
            for rbl_host in self._rbl_hosts:
                rbl_query = f"{reversed_ip}.{rbl_host}"

                try:
                    # Perform DNS lookup - if it resolves, IP is blacklisted
                    result = socket.gethostbyname(rbl_query)

                    # Most RBLs return 127.0.0.x for positive matches
                    if result.startswith("127.0.0."):
                        # Log which RBL triggered
                        tx.variables.tx.add("RBL_MATCH", rbl_host)
                        tx.variables.tx.add("RBL_RESULT", result)
                        return True

                except socket.gaierror:
                    # DNS lookup failed - IP not in this RBL
                    continue
                except Exception:
                    # Other DNS errors - skip this RBL
                    continue

            return False

        except ValueError:
            # Invalid IP address format
            return False
