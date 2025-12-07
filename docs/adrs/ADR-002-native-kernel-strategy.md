# ADR-002: Native Kernel Extension Strategy

**Status:** Prospective
**Date:** 2024-12-07
**Authors:** LeWAF Team

## Context

LeWAF is a Python WAF with 92% CRS compatibility. Performance analysis (see `experimental/notes/`) shows:

| Metric | Current (Python) | With Native Kernel | Potential Gain |
|--------|------------------|-------------------|----------------|
| Regex (@rx) | Baseline | DFA-based engine | 10-75x |
| Phrase match (@pm) | O(n×p) linear | Aho-Corasick O(n+m) | 3-50x |
| Transform chain | Sequential | Batched/SIMD | 5-10x |
| Full evaluation | ~25µs/rule | ~0.5µs/rule | 30-50x |

Python's `re` module and linear search are adequate for low-traffic scenarios, but native implementations unlock:

- **High-throughput:** 10,000+ requests/second
- **Low-latency:** <1ms per request
- **Edge deployment:** WASM, embedded systems

This ADR outlines the strategy for developing and integrating native kernels **separately from the main LeWAF repository**.

## Decision

### 1. Kernel Development Lives Outside Main Repo

Native kernels are developed in **separate repositories**:

```
lewaf/              # Main Python library (this repo)
lewaf-kernel-rust/  # Rust kernel (separate repo)
lewaf-kernel-zig/   # Zig kernel (separate repo)
```

**Rationale:**
- Main repo stays clean, Python-only
- Different build toolchains (cargo, zig build) don't complicate CI
- Can version kernels independently
- Easier for contributors (no Rust/Zig knowledge required for Python work)

### 2. Kernels Are Optional Dependencies

Installation options:

```bash
# Python-only (default)
pip install lewaf

# With Rust kernel
pip install lewaf lewaf-kernel-rust

# With Zig kernel (future)
pip install lewaf lewaf-kernel-zig

# Or via extras
pip install lewaf[rust]
pip install lewaf[native]  # Best available native kernel
```

### 3. Auto-Detection with Graceful Fallback

```python
from lewaf.kernel import default_kernel, KernelType

# Auto-detection (default behavior)
kernel = default_kernel()
# Tries in order: Rust > Zig > Python
# Falls back gracefully if native not installed

# Explicit selection
kernel = default_kernel(KernelType.RUST)  # Raises if not available
kernel = default_kernel(KernelType.PYTHON)  # Always available

# Environment override (useful for debugging/testing)
# LEWAF_KERNEL=python pytest  # Force Python kernel in tests
```

### 4. Three Extension Levels

Native kernels can implement at three levels of optimization:

#### Level 1: Primitive Operations (Recommended Starting Point)

```python
class KernelProtocol(Protocol):
    def regex_match(self, pattern: str, text: str) -> bool: ...
    def phrase_match(self, phrases: list[str], text: str) -> bool: ...
    def transform(self, name: str, value: str) -> str: ...
```

**Benefit:** 2-10x speedup on hot path operations
**Effort:** Low (implement 3-5 functions)
**Risk:** Low (Python still handles orchestration)

#### Level 2: Operator Evaluation

```python
class KernelProtocol(Protocol):
    def evaluate_rx(self, pattern: str, value: str, capture: bool) -> tuple[bool, list[str]]: ...
    def evaluate_pm(self, phrases: list[str], value: str) -> bool: ...
    # ... 30+ operators
```

**Benefit:** 5-20x speedup (eliminates Python dispatch per value)
**Effort:** Medium (implement all operators)
**Risk:** Medium (must match ModSecurity semantics exactly)

#### Level 3: Complete Rule Evaluation (Future)

```python
class KernelProtocol(Protocol):
    def evaluate_rule(
        self,
        operator_name: str,
        operator_arg: str,
        transforms: list[str],
        values: list[tuple[str, str]],
        negated: bool,
    ) -> tuple[bool, str | None, str | None]: ...
```

**Benefit:** 30-50x speedup (entire hot loop in native)
**Effort:** High (reimplement Rule.evaluate logic)
**Risk:** Higher (must handle all edge cases)

### 5. Rust Kernel Architecture (Primary Path)

```
lewaf-kernel-rust/
├── Cargo.toml
├── src/
│   ├── lib.rs           # PyO3 bindings
│   ├── kernel.rs        # KernelProtocol implementation
│   ├── regex.rs         # DFA regex (rust regex crate)
│   ├── phrase.rs        # Aho-Corasick (aho-corasick crate)
│   └── transforms.rs    # Transform implementations
├── python/
│   └── lewaf_kernel_rust/
│       └── __init__.py  # Python wrapper
└── pyproject.toml       # maturin build config
```

**Key Dependencies:**
- `regex` - DFA-based regex (no catastrophic backtracking)
- `aho-corasick` - Multi-pattern matching
- `pyo3` - Python bindings
- `maturin` - Build system

### 6. Zig Kernel Architecture (Research Path)

```
lewaf-kernel-zig/
├── build.zig
├── src/
│   ├── main.zig         # C ABI exports
│   ├── regex.zig        # Wrap rure (Rust regex C API)
│   ├── phrase.zig       # Aho-Corasick implementation
│   └── transforms.zig   # Transform implementations
├── c_shim/              # HPy C shim for Python binding
│   ├── hpy_shim.h
│   └── hpy_shim.c
└── python/
    └── lewaf_kernel_zig/
        └── __init__.py
```

**Interesting for:**
- WASM compilation (edge deployment)
- Comptime rule compilation
- Smaller binary size
- Learning/research

### 7. Versioning and Compatibility

Native kernels must be compatible with specific LeWAF versions:

```python
# In native kernel package
LEWAF_PROTOCOL_VERSION = "1.0"
SUPPORTED_LEWAF_VERSIONS = ["0.7.*", "0.8.*"]

# LeWAF checks on import
def _validate_kernel(kernel):
    if kernel.protocol_version != KERNEL_PROTOCOL_VERSION:
        raise IncompatibleKernelError(
            f"Kernel protocol {kernel.protocol_version} "
            f"incompatible with LeWAF {KERNEL_PROTOCOL_VERSION}"
        )
```

**Semantic versioning:**
- Protocol version bump = breaking change in KernelProtocol
- Native kernel must declare compatible protocol versions
- Major LeWAF releases may bump protocol version

### 8. Testing Strategy

Native kernels must pass the same test suite as Python:

```bash
# In native kernel repo
pytest --kernel=rust tests/  # Run LeWAF test suite with Rust kernel
pytest --kernel=zig tests/   # Run with Zig kernel

# Or via environment
LEWAF_KERNEL=rust pytest     # Force kernel for all tests
```

**Test categories:**
1. **Unit tests** - Each kernel operation in isolation
2. **Operator tests** - All 32 operators match Python behavior
3. **CRS tests** - Full OWASP CRS compatibility
4. **Performance tests** - Benchmarks against Python baseline

### 9. Build and Distribution

#### Rust Kernel (maturin)

```toml
# pyproject.toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "lewaf-kernel-rust"
requires-python = ">=3.10"
dependencies = ["lewaf>=0.7"]
```

```bash
# Build wheels
maturin build --release

# Publish
maturin publish
```

#### Zig Kernel (custom)

```bash
# Build shared library
zig build -Doptimize=ReleaseFast

# Package for PyPI
python -m build
```

### 10. Migration Path

#### Phase 1: Foundation (ADR-001)
- Integrate kernel into Rule.evaluate()
- Python kernel as default
- All tests pass

#### Phase 2: Rust Kernel MVP
- Implement Level 1 (regex, phrase, transform)
- Publish lewaf-kernel-rust 0.1.0
- Benchmark and validate

#### Phase 3: Rust Kernel Complete
- Implement Level 2 (all operators)
- Implement Level 3 (rule evaluation)
- Target: 10x+ speedup

#### Phase 4: Zig Kernel (Optional)
- Implement for WASM use case
- Research comptime optimization
- Evaluate for edge deployment

## Consequences

### Positive

1. **Clean separation** - Main repo stays simple
2. **Independent release cycles** - Kernel can iterate faster
3. **Optional complexity** - Users who don't need performance avoid native builds
4. **Multiple implementations** - Rust for production, Zig for research
5. **Graceful degradation** - Python always works

### Negative

1. **Multiple repos to maintain** - More coordination needed
2. **Version compatibility** - Must track protocol versions
3. **Build complexity for native** - Users need Rust/Zig toolchain for development
4. **Testing burden** - Must run tests against all kernel types

### Risks

| Risk | Mitigation |
|------|------------|
| Protocol drift | Strict versioning, CI tests all kernels |
| Build failures on platforms | Pre-built wheels for common platforms |
| Performance regression | Continuous benchmarking in CI |
| Semantic mismatches | Comprehensive operator test suite |

## Alternatives Considered

### Alternative 1: Monorepo with Native Code
Keep Rust/Zig code in main LeWAF repo.

**Rejected:** Complicates CI, requires all contributors to have native toolchains.

### Alternative 2: Native-Only Future
Eventually drop Python kernel entirely.

**Rejected:** Python kernel is valuable for debugging, testing, and platforms without native support.

### Alternative 3: FFI Over Protocol
Use low-level FFI instead of high-level protocol.

**Rejected:** High-level protocol is more maintainable, type-safe, and testable.

## References

- `experimental/notes/BENCHMARK-REPORT.md` - Performance analysis
- `experimental/notes/STRATEGIC-REPORT.md` - Strategic findings
- `experimental/notes/extended-kernel-analysis.md` - Rule Engine analysis
- `experimental/notes/future-vision.md` - Architecture vision
- `src/lewaf/kernel/protocol.py` - KernelProtocol definition
