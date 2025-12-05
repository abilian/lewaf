# LeWAF Developer Guide

**Current Version**: 0.7.0 (Beta)

This guide contains coding guidelines, development commands, and architecture documentation for LeWAF contributors.

## Development Commands

### Testing
- Run all tests: `uv run pytest`
- Run specific test file: `uv run pytest tests/test_core.py`
- Run tests with coverage: `uv run pytest --cov=lewaf`

### Code Quality
- Run linting checks: `make check` or `ruff check .`
- Auto-fix linting issues: `make format` or `ruff check . --fix && ruff format .`
- Format code: `ruff format .`
- Type checking: `uv run pyrefly`

### Build & Package
- Build package: `make build` or `uv build`
- Clean build artifacts: `make clean`

## Project Documentation

- **[README.md](README.md)** - Project overview and quick start
- **[CHANGELOG.md](CHANGELOG.md)** - Release history and features
- **[docs/guides/quickstart.md](docs/guides/quickstart.md)** - Detailed setup guide
- **[docs/api/reference.md](docs/api/reference.md)** - Complete API reference
- **[docs/guides/](docs/guides/)** - Integration and custom rules guides
- **[docs/deployment/](docs/deployment/)** - Docker, Kubernetes deployment guides

## Architecture Overview

LeWAF is a Python Web Application Firewall implementing the ModSecurity SecLang specification. The implementation is structured in a modular architecture with **92% CRS compatibility** and comprehensive framework integration support.

**Key Achievement**: 1258 automated tests, with zero linting/type errors.

### Core Modules

- **`src/lewaf/core/`** - Core utilities including regex compilation with LRU caching
- **`src/lewaf/primitives/`** - Fundamental WAF components:
  - `collections.py` - Data structures for request variables (ARGS, REQUEST_HEADERS, TX, REQUEST_URI)
  - `operators.py` - 32 pattern matching operators (@rx, @streq, @contains, @pm, etc.)
  - `transformations.py` - 45 data transformations (urlDecode, lowercase, base64Decode, etc.)
  - `actions.py` - 37 rule actions (deny, allow, block, log, pass, etc.)
  - `variable_expansion.py` - Runtime variable expansion and macros
- **`src/lewaf/rules/`** - Rule processing engine with 5-phase evaluation
- **`src/lewaf/engine/`** - Main WAF engine (RuleGroup)
- **`src/lewaf/transaction/`** - Request/response transaction handling
- **`src/lewaf/integration/`** - WAF integration layer with SecLang parser
- **`src/lewaf/integrations/`** - Framework middleware (FastAPI, Flask, Django, Starlette)
- **`src/lewaf/bodyprocessors/`** - Body parsers (JSON, XML, multipart, urlencoded)
- **`src/lewaf/storage/`** - Persistent storage backends (Memory, File, Redis)
- **`src/lewaf/seclang/`** - ModSecurity SecLang parser
- **`src/lewaf/logging/`** - Audit logging with PCI-DSS/GDPR compliance
- **`src/lewaf/config/`** - Configuration management with YAML/JSON support

### Key Design Patterns

- **Registry Pattern**: Operators, transformations, and actions use decorator-based registration (`@register_operator`, `@register_transformation`)
- **Collection Abstraction**: Request data is abstracted through Collection classes (MapCollection, SingleValueCollection) with unified MatchData interface
- **Performance Optimization**: Regex compilation is cached using `@lru_cache` in core module
- **Protocol-Based Typing**: Uses typing.Protocol for flexible interfaces between components

### Testing Structure

Tests are organized by category with 1258 total tests:
- **Unit tests** (`tests/a_unit/`) - Unit tests covering primitives, actions, operators
- **Integration tests** (`tests/b_integration/`) - Integration tests for framework integrations
- **E2E security tests** (`tests/c_e2e/`) - E2E tests for attack detection
- **Production tests** (`tests/d_production/`) - Production tests for load, performance, CRS
- **Example tests** (`tests/e_examples/`) - Tests validating example code

Each test module focuses on a specific component and uses pytest fixtures and assertions. All tests must pass before merging code.

## ModSecurity Compatibility

LeWAF implements the ModSecurity SecLang specification with high compatibility:

### Current Compatibility Status

- **CRS Compatibility**: 92% (594 of ~650 OWASP Core Rule Set rules load successfully)
- **Operators**: 100% (32/32 operators implemented)
- **Transformations**: 136% (45 transformations vs 33 in Go Coraza)
- **Actions**: 103% (37 actions vs 36 in Go Coraza)
- **Variables**: ~40 core variables (sufficient for CRS compatibility)
- **Test Coverage**: 1258 automated tests (including FTW integration)
- **Type Safety**: Zero type errors (pyrefly)
- **Code Quality**: Zero linting errors (ruff)

### Implementation Guidelines

- **Security First**: Security-focused implementation with comprehensive input validation
- **Test-Driven Development**: All new features require tests; bug fixes require regression tests
- **Protocol-Based Design**: Use typing.Protocol for flexible interfaces
- **Registry Pattern**: Follow existing decorator-based registration for extensibility
- **Performance**: Optimized regex compilation with LRU caching
- **Compliance**: PCI-DSS and GDPR compliant audit logging
