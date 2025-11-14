# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2025-11-20

First public release of LeWAF - a Python Web Application Firewall implementing the ModSecurity SecLang specification.

### Core Features

- **WAF Engine**: Complete 5-phase request/response processing engine
  - Request headers inspection (Phase 1)
  - Request body inspection (Phase 2)
  - Response headers inspection (Phase 3)
  - Response body inspection (Phase 4)
  - Logging phase (Phase 5)

- **SecLang Compatibility**: ModSecurity-compatible rule language
  - 32 operators (@rx, @streq, @contains, @pm, etc.)
  - 48 transformations (urlDecode, lowercase, base64Decode, etc.)
  - 36 actions (deny, allow, block, log, pass, drop, etc.)
  - ~40 variables (REQUEST_URI, ARGS, REQUEST_HEADERS, TX, etc.)
  - Chain rules support
  - Variable expansion and macros

- **OWASP Core Rule Set (CRS)**: 594 CRS rules loaded successfully
  - SQL injection detection
  - Cross-site scripting (XSS) protection
  - Command injection blocking
  - Path traversal detection
  - Protocol violation enforcement

- **Body Processors**: Multi-format request/response body parsing
  - JSON body processor
  - XML body processor with XPath-like access
  - Multipart/form-data processor
  - URL-encoded form processor
  - Automatic content-type detection

- **Persistent Storage**: Cross-request state tracking
  - Memory, File, and Redis backends
  - Rate limiting per IP/user/session
  - Brute force detection
  - Session anomaly scoring
  - TTL support with automatic expiration

- **Audit Logging**: Compliance-ready structured logging
  - JSON-formatted security event logs
  - PCI-DSS compliant data masking (credit cards, passwords)
  - GDPR compliant IP anonymization
  - Performance metrics logging
  - Configuration change audit trail

### Framework Integrations

- **FastAPI**: ASGI middleware with async support
- **Flask**: WSGI middleware integration
- **Django**: Django middleware with DRF support
- **Starlette**: ASGI middleware base

### Documentation

- Comprehensive API reference
- Integration guides for FastAPI, Flask, Django, Starlette
- Deployment guides (Docker, Kubernetes)
- Custom rule writing guide
- Troubleshooting and performance tuning guides

### Testing & Quality

- 905 automated tests with 100% pass rate
- Zero linting errors (ruff)
- Zero type checking errors (pyrefly)
- Load tested at 1000+ requests/second

---

[0.7.0]: https://github.com/abilian/lewaf/releases/tag/v0.7.0
