# LeWAF - Python Web Application Firewall

[![Tests](https://img.shields.io/badge/tests-1258%20total-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12+-blue)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)]()
[![Code Quality](https://img.shields.io/badge/code%20quality-100%25-brightgreen)]()
[![Documentation](https://img.shields.io/badge/docs-10%2C210%2B%20lines-blue)]()

A Web Application Firewall for Python that stops attacks before they reach your application code, with comprehensive audit logging and compliance support.

## Why Use LeWAF?

### Protect Your Application from Common Attacks

Most web applications handle sensitive data and are exposed to automated attacks. LeWAF blocks SQL injection, XSS, and command injection attempts at the middleware layer, before they reach your business logic. Instead of implementing security checks in every endpoint, deploy LeWAF once and protect your entire application.

### Meet Compliance Requirements

Organizations subject to PCI-DSS, GDPR, or SOC 2 need audit logs showing what security controls are in place and which attacks were blocked. LeWAF provides structured logging with automatic data masking (credit cards, passwords, tokens) and detailed attack records that satisfy auditor requirements.

### Reduce Security Maintenance Burden

Security vulnerabilities evolve constantly. LeWAF uses the OWASP Core Rule Set (CRS), maintained by security experts and updated regularly. Deploy rule updates without changing your application code. When new attack patterns emerge, update your WAF rules instead of patching multiple endpoints.

### Integrate Security Teams with Development

Security teams can write and test WAF rules independently of application deployments. Development teams continue shipping features while security teams tune protection rules. LeWAF's rule language (SecLang) is standard across ModSecurity-compatible systems, enabling knowledge transfer and shared rule sets.

## Use Cases

### API Protection
Block malicious requests to REST or GraphQL APIs before they consume database resources or trigger expensive operations. Rate limit requests per client, validate JWT tokens at the edge, and log all blocked attempts for security analysis.

### Legacy Application Security
Add security controls to applications that can't be easily modified. Deploy LeWAF as a reverse proxy or middleware to protect applications written years ago, without source code changes or redeployment.

### Multi-Tenant SaaS
Different tenants may require different security policies. Load tenant-specific rule sets dynamically, enforce rate limits per organization, and maintain separate audit logs for each customer.

### Microservices Gateway
Deploy once at the API gateway to protect all downstream microservices. Centralized security policy enforcement reduces duplicated security code across services and provides unified logging.

### Development and Staging Environments
Test security rules in staging before production deployment. Catch configuration errors early and validate that legitimate traffic passes through while attacks are blocked.

## Who Should Use LeWAF?

- **Python web applications** using FastAPI, Flask, Django, or Starlette
- **Organizations** requiring audit logs for compliance (PCI-DSS, GDPR, SOC 2)
- **API providers** needing rate limiting and attack protection
- **Security teams** wanting centralized rule management
- **DevOps teams** deploying containerized applications with security requirements

## What is LeWAF?

LeWAF is a Python implementation of the ModSecurity/Coraza Web Application Firewall specification. It runs as middleware in your web application, inspecting HTTP requests and responses against security rules before they reach your application code.

The system uses the OWASP Core Rule Set (CRS) - 681 security rules maintained by security researchers and updated as new threats emerge. LeWAF is compatible with ASGI (async) and WSGI (sync) frameworks: FastAPI, Flask, Django, and Starlette.

**Key capabilities:**
- Blocks SQL injection, XSS, command injection, path traversal attacks
- PCI-DSS and GDPR compliant audit logging with automatic data masking
- Drop-in middleware with minimal performance impact
- Configurable through code or YAML files
- Scales horizontally, no shared state between instances
- 1258 automated tests, load tested at 1000+ requests/second

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/abilian/lewaf.git
cd lewaf

# Install with uv
uv sync

# Run tests
uv run pytest -q
# Output: 1183 passed, 75 skipped in ~38s
```

### Basic Usage

```python
from lewaf.integration import WAF

# Create WAF with CRS rules
waf = WAF({
    "rules": [
        'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS Attack\'"',
        'SecRule ARGS "@rx (union.*select)" "id:1002,phase:2,deny,msg:\'SQL Injection\'"',
    ]
})

# Process request
tx = waf.new_transaction()
tx.process_uri("/api/users?id=123", "GET")

# Check for attacks
result = tx.process_request_headers()
if result:
    print(f"Attack detected: {result['rule_id']}")
```

### Starlette/FastAPI Integration

```python
from starlette.applications import Starlette
from lewaf.integrations.starlette import create_waf_app

app = Starlette(routes=[...])

# Add WAF protection
waf_app = create_waf_app(app, rules=[
    'SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:\'XSS\'"'
])
```

See [docs/guides/quickstart.md](docs/guides/quickstart.md) for detailed setup instructions.

## Project Status

**Version**: 0.7.0
**Status**: Beta
**Test Coverage**: 1258 automated tests
**Code Quality**: Zero linting/type errors
**Documentation**: 15000+ lines of documentation

### Test Coverage

1258 automated tests covering:
- Core WAF engine and rule processing
- Framework integrations (FastAPI, Flask, Django, Starlette)
- Attack detection and blocking
- Compliance logging and data masking
- Performance under load
- Error handling and edge cases

See [CHANGELOG.md](CHANGELOG.md) for release history and feature details.

## Documentation

### Getting Started
- **[Quickstart Guide](docs/guides/quickstart.md)** - Get LeWAF running in 5 minutes with examples
- **[API Reference](docs/api/reference.md)** - Complete API documentation (1,538 lines)

### Integration Guides
- **[Django Integration](docs/guides/integration-django.md)** - Integrate with Django applications
- **[FastAPI Integration](docs/guides/integration-fastapi.md)** - Integrate with FastAPI applications
- **[Flask Integration](docs/guides/integration-flask.md)** - Integrate with Flask applications
- **[Starlette Integration](docs/guides/integration-starlette.md)** - Integrate with Starlette applications

### Deployment
- **[Docker Deployment](docs/deployment/docker.md)** - Deploy LeWAF in Docker containers
- **[Kubernetes Deployment](docs/deployment/kubernetes.md)** - Deploy LeWAF in Kubernetes clusters
- **[Performance Tuning](docs/deployment/performance.md)** - Optimize LeWAF for high-traffic applications
- **[Troubleshooting](docs/deployment/troubleshooting.md)** - Diagnose and resolve common issues

### Security Operations
- **[Custom Rules Guide](docs/guides/custom-rules.md)** - Write application-specific WAF rules
- **[Audit Logging](examples/audit_logging_example.py)** - Configure compliance logging

### For Contributors
- **[Developer Guide](CONTRIBUTING.md)** - Setup, coding guidelines, testing requirements
- **[Changelog](CHANGELOG.md)** - Release history and feature details

## Working Examples

The `examples/` directory contains ready-to-run code:
- **Framework integrations**: FastAPI, Flask, Django, Starlette implementations
- **Audit logging**: PCI-DSS and GDPR compliant logging setup
- **Production deployment**: Docker and Kubernetes configurations
- **Custom rules**: Application-specific security rules

## How It Works

LeWAF operates as middleware in your web application stack. When an HTTP request arrives:

1. **Request inspection**: Headers, URI, query parameters, and body are extracted
2. **Rule evaluation**: Security rules run in phases (headers → body → response)
3. **Pattern matching**: Requests are checked against threat patterns (SQL injection, XSS, etc.)
4. **Action execution**: Malicious requests are blocked; legitimate requests pass through
5. **Audit logging**: All security events are logged with masked sensitive data

The rule engine uses the ModSecurity SecLang specification, the same rule language used by enterprise WAF systems. This means security professionals can apply existing knowledge and rule sets directly to LeWAF.

## Compatibility

LeWAF implements the ModSecurity/Coraza WAF specification and is compatible with:
- **OWASP Core Rule Set**: 681 rules loaded (100% file compatibility)
- **ModSecurity rules**: Standard SecLang syntax
- **Python frameworks**: FastAPI, Flask, Django, Starlette
- **Deployment platforms**: Docker, Kubernetes, traditional servers

This compatibility means you can use community-maintained rule sets, share security policies across different WAF implementations, and leverage existing security team expertise.

## Known Limitations

### `drop` Action

The `drop` action in ModSecurity forcefully terminates TCP connections. This requires low-level socket access that is **not available in Python WSGI/ASGI middleware**. In LeWAF, `drop` behaves identically to `deny` - it returns an error response but the TCP connection may remain open.

**Workaround**: Use `deny` instead. For true connection dropping, deploy a native WAF (nginx ModSecurity module, Apache mod_security) in front of your Python application.

### `exec` Action

The `exec` action is **intentionally disabled** for security reasons. Executing arbitrary shell commands from WAF rules creates significant security risks including remote code execution and privilege escalation.

**Workaround**: If you need external command execution, implement it through a secure hook mechanism outside the WAF rule engine with proper auditing and access controls.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development setup
- Coding guidelines
- Testing requirements
- Git workflow

### Development Commands

```bash
# Run tests
uv run pytest

# Run linting
uv run ruff check .

# Auto-fix issues
uv run ruff check . --fix && uv run ruff format .

# Build package
uv build
```

## License

Apache Software License 2.0 (matching OWASP CRS and Coraza)

## Credits

- **Architecture**: Based on [Go Coraza](https://coraza.io/) project
- **Rules**: [OWASP Core Rule Set](https://coreruleset.org/)
- **Standards**: ModSecurity/Coraza SecLang specification

## Support

- **Issues**: [GitHub Issues](https://github.com/abilian/lewaf/issues)
- **Documentation**: See docs above
- **CRS Documentation**: https://coreruleset.org/
- **Coraza Documentation**: https://coraza.io/

---

**LeWAF**: Lightweight Web Application Firewall for Python 🛡️
