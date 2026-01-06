"""LeWAF - Python Web Application Firewall.

LeWAF is a Python Web Application Firewall implementing the ModSecurity
SecLang specification with 92% OWASP CRS compatibility.

Basic usage:
    from lewaf import WAF, Transaction

    # Create WAF with rules
    waf = WAF({"rules": ['SecRule ARGS "@rx attack" "id:1,phase:1,deny"']})

    # Process a request
    tx = waf.new_transaction()
    tx.process_uri("/api/test?id=attack", "GET")
    result = tx.process_request_headers()

    if result:
        print(f"Request blocked by rule {result['rule_id']}")

For framework integration, use the middleware classes:
    from lewaf.integrations.starlette import LeWAFMiddleware
    from lewaf.integration.asgi import ASGIMiddleware
"""

from __future__ import annotations

__version__ = "0.7.1"

# Public API - these are the stable interfaces for 1.0
from lewaf.integration import WAF
from lewaf.transaction import Transaction

__all__ = [
    "WAF",
    "Transaction",
    "__version__",
]
