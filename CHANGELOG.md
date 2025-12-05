# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **VariableSpec dataclass**: Replaced tuples with proper dataclass for rule variables
- **Variable count modifier (`&ARGS`)**: Returns count of items in a collection
- **Variable negation (`!ARGS:foo`)**: Excludes specific keys from matching
- **ARGS_PATH collection**: REST path parameters populated by `@restpath` operator
- **WAF configuration storage**: `SecRuleEngine`, `SecRequestBodyAccess`, `SecResponseBodyAccess` directives now stored

### Changed

- **Redirect action**: Now properly passes redirect URL to middleware
- **Skip action**: Now integrates with rule engine skip_state
- **Audit log actions**: `auditlog`/`noauditlog` update transaction state
- **TransactionProtocol**: Extended with audit and skip attributes

### Fixed

- Starlette middleware now reads request body before processing
- Response phase 3 (headers) now processed in middleware
- Config file loading now works via ConfigLoader

### Documentation

- Added "Known Limitations" section to README for `drop` and `exec` actions
- Updated action docstrings with clear limitation explanations

---

## [0.7.0] - 2025-12-05

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
  - 45 transformations (urlDecode, lowercase, base64Decode, etc.)
  - 37 actions (deny, allow, block, log, pass, drop, etc.)
  - ~40 variables (REQUEST_URI, ARGS, REQUEST_HEADERS, TX, etc.)
  - Chain rules support
  - Variable expansion and macros

- **OWASP Core Rule Set (CRS)**: 92% compatibility (594 of ~650 rules load successfully)
  - SQL injection detection
  - Cross-site scripting (XSS) protection
  - Remote code execution (RCE) blocking
  - Local/Remote file inclusion (LFI/RFI) detection
  - Path traversal detection
  - Protocol violation enforcement

- **FTW Test Suite Integration**: Official OWASP CRS regression test support
  - FTW (Framework for Testing WAFs) YAML parser
  - 60% pass rate on 4063 official CRS test cases
  - Automated test runner for CRS compatibility validation

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

- 1258 automated tests
- Zero linting errors (ruff)
- Zero type checking errors (pyrefly, mypy, ty)
- Load tested at 1000+ requests/second
- Comprehensive CRS validation with 134 attack payloads across 8 categories

---

[0.7.0]: https://github.com/abilian/lewaf/releases/tag/v0.7.0
