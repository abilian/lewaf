# LeWAF - Python Web Application Firewall

A Web Application Firewall for Python that stops attacks before they reach your application code, with comprehensive audit logging and compliance support.

## Features

- **Attack Prevention** - SQL injection, XSS, command injection, path traversal
- **Framework Support** - FastAPI, Flask, Django, Starlette
- **OWASP CRS Compatible** - 92% compatibility with Core Rule Set
- **Compliance Ready** - PCI-DSS and GDPR compliant audit logging
- **High Performance** - <5ms latency overhead with regex caching

## Quick Installation

```bash
pip install lewaf
```

## Basic Usage

=== "FastAPI"

    ```python
    from fastapi import FastAPI
    from lewaf.integration import WAF
    from lewaf.integrations.starlette import LeWAFMiddleware

    app = FastAPI()
    waf = WAF({"rules": [
        'SecRule ARGS "@rx (?i)(union.*select|insert.*into)" "id:1,deny,status:403"'
    ]})
    app.add_middleware(LeWAFMiddleware, waf=waf)
    ```

=== "Flask"

    ```python
    from flask import Flask
    from lewaf.integration import WAF
    from lewaf.integrations.flask import LeWAFMiddleware

    app = Flask(__name__)
    waf = WAF({"rules": [
        'SecRule ARGS "@rx (?i)(union.*select|insert.*into)" "id:1,deny,status:403"'
    ]})
    app.wsgi_app = LeWAFMiddleware(app.wsgi_app, waf=waf)
    ```

=== "Django"

    ```python
    # settings.py
    MIDDLEWARE = [
        'lewaf.integrations.django.LeWAFMiddleware',
        # ... other middleware
    ]

    LEWAF_CONFIG = {
        "rules": [
            'SecRule ARGS "@rx (?i)(union.*select)" "id:1,deny,status:403"'
        ]
    }
    ```

## Why LeWAF?

### Protect Your Application

Most web applications handle sensitive data and are exposed to automated attacks. LeWAF blocks SQL injection, XSS, and command injection attempts at the middleware layer, before they reach your business logic.

### Meet Compliance Requirements

Organizations subject to PCI-DSS, GDPR, or SOC 2 need audit logs showing what security controls are in place. LeWAF provides structured logging with automatic data masking.

### Reduce Security Maintenance

LeWAF uses the OWASP Core Rule Set (CRS), maintained by security experts. Deploy rule updates without changing your application code.

## Next Steps

- [Quick Start Guide](guides/quickstart.md) - Get started in 5 minutes
- [Framework Integration](guides/integration-fastapi.md) - Detailed integration guides
- [Custom Rules](guides/custom-rules.md) - Write your own security rules
- [API Reference](api/reference.md) - Complete API documentation
