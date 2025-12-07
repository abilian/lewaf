# ADR-002: Native Extension Strategy

**Status:** Prospective
**Date:** 2025-12-07
**Authors:** LeWAF Team

## Context

LeWAF is a Python WAF with 92% CRS compatibility. Performance analysis (see `experimental/notes/`) shows significant optimization potential:

| Metric | Current (Python) | Native Kernel | Native Engine |
|--------|------------------|---------------|---------------|
| Regex (@rx) | Baseline | 10-75x faster | 10-75x faster |
| Phrase match (@pm) | O(n×p) linear | Aho-Corasick 3-50x | Aho-Corasick 3-50x |
| Per-rule overhead | ~15-25µs | ~5-10µs | ~0.5µs |
| **Overall speedup** | 1x | **2-10x** | **30-50x** |

The difference between "Kernel" and "Engine" levels:

- **Kernel:** Native code for individual operations, Python orchestrates
- **Engine:** Native code for entire evaluation loop, eliminates Python overhead

Python's implementation is adequate for low-traffic scenarios, but native implementations would unlock:

- **High-throughput:** 10,000+ requests/second
- **Low-latency:** <1ms per request
- **Edge deployment:** WASM, embedded systems

This ADR outlines the strategy for developing and integrating native extensions **separately from the main LeWAF repository**.

## Decision

### 1. Two Integration Levels: Kernel and Engine

We define two distinct integration points with different trade-offs:

```
┌─────────────────────────────────────────────────────────────┐
│  ENGINE LEVEL                                                │
│  EngineProtocol.evaluate_phase(compiled_rules, tx_data)     │
│                                                              │
│  • 1 FFI call per phase                                     │
│  • Rules compiled once at startup                           │
│  • Native loops, native memory management                   │
│  • 30-50x speedup                                           │
│  • ~3,500 LOC native code                                   │
├─────────────────────────────────────────────────────────────┤
│  KERNEL LEVEL                                                │
│  KernelProtocol.regex_match(), transform(), phrase_match()  │
│                                                              │
│  • Many FFI calls (per operation)                           │
│  • Python orchestrates rule evaluation                      │
│  • 2-10x speedup                                            │
│  • ~500 LOC native code                                     │
└─────────────────────────────────────────────────────────────┘
```

**Both levels are valuable:**
- Kernel: Quick wins, low risk, validates approach
- Engine: Maximum performance when needed

### 2. Protocol Definitions

#### Kernel Protocol (ADR-001)

```python
class KernelProtocol(Protocol):
    """Low-level operations - Python still orchestrates."""

    # Level 1: Primitives
    def regex_match(self, pattern: str, text: str) -> bool: ...
    def phrase_match(self, phrases: list[str], text: str) -> bool: ...
    def transform(self, name: str, value: str) -> str: ...
    def transform_chain(self, transforms: list[str], value: str) -> str: ...

    # Level 2: Operators
    def evaluate_rx(self, pattern: str, value: str, capture: bool) -> tuple[bool, list[str]]: ...
    def evaluate_pm(self, phrases: list[str], value: str) -> bool: ...
    # ... all 32 operators
```

#### Engine Protocol (New)

```python
class TransactionData(TypedDict):
    """Serializable transaction data for native engine."""
    method: str
    uri: str
    headers: dict[str, list[str]]
    args: dict[str, list[str]]
    body: bytes | None
    tx_variables: dict[str, str]
    score: int

class PhaseResult(TypedDict):
    """Result from phase evaluation."""
    matched_rules: list[int]
    score: int
    interrupted: bool
    interruption_rule: int | None
    interruption_status: int | None

class CompiledRuleset:
    """Opaque handle to native compiled rules."""
    pass

class EngineProtocol(Protocol):
    """High-level engine - native orchestration."""

    def compile_rules(self, rules: list[Rule]) -> CompiledRuleset:
        """Compile rules to native format (done once at startup)."""
        ...

    def evaluate_phase(
        self,
        ruleset: CompiledRuleset,
        tx_data: TransactionData,
        phase: int,
    ) -> PhaseResult:
        """Evaluate all rules for a phase in a single native call."""
        ...
```

### 3. Native Extensions Live Outside Main Repo

```
lewaf/              # Main Python library (this repo)
lewaf-kernel-rust/  # Rust kernel + engine (separate repo)
lewaf-kernel-zig/   # Zig kernel + engine (separate repo, future)
```

**Rationale:**
- Main repo stays clean, Python-only
- Different build toolchains don't complicate CI
- Can version independently
- Easier for contributors

### 4. Optional Dependencies

```bash
# Python-only (default)
pip install lewaf

# With Rust extensions
pip install lewaf lewaf-kernel-rust

# Or via extras
pip install lewaf[rust]
pip install lewaf[native]  # Best available
```

### 5. Auto-Detection with Graceful Fallback

```python
from lewaf.kernel import default_kernel
from lewaf.engine import default_engine

# Kernel: Tries Rust > Zig > Python
kernel = default_kernel()

# Engine: Tries Rust > Zig > None (falls back to kernel-based evaluation)
engine = default_engine()

# Environment override
# LEWAF_KERNEL=python pytest
# LEWAF_ENGINE=none pytest  # Disable engine, use kernel only
```

### 6. Engine Integration Point

```python
class RuleGroup:
    def __init__(self, rules: list[Rule]):
        self._rules = rules
        self._compiled: CompiledRuleset | None = None
        self._engine: EngineProtocol | None = None

    def _ensure_compiled(self) -> tuple[EngineProtocol | None, CompiledRuleset | None]:
        if self._engine is None:
            self._engine = default_engine()
            if self._engine:
                self._compiled = self._engine.compile_rules(self._rules)
        return self._engine, self._compiled

    def evaluate(self, tx: Transaction, phase: int) -> None:
        engine, compiled = self._ensure_compiled()

        if engine and compiled:
            # Fast path: native engine (30-50x faster)
            tx_data = tx.to_dict()
            result = engine.evaluate_phase(compiled, tx_data, phase)
            tx.apply_result(result)
        else:
            # Fallback: kernel-based evaluation (2-10x faster)
            # Or pure Python if no kernel available
            for rule in self._rules:
                if rule.phase == phase:
                    rule.evaluate(tx)
```

### 7. Data Flow Comparison

**Kernel Level (many FFI calls):**
```
Python                          Native Kernel
──────                          ─────────────
for rule in rules:
  for value in values:
    transform(name, value) ───────> transform
                           <─────── result
    regex_match(pat, val) ────────> match
                           <─────── bool
```

**Engine Level (one FFI call):**
```
Python                          Native Engine
──────                          ─────────────
compile_rules(rules) ─────────────> CompiledRuleset (once)

to_dict(transaction) ─────────────> TransactionData
                                    │
                                    ▼ (native loops)
                                    for each rule:
                                      extract vars
                                      apply transforms
                                      evaluate operator
                                      execute actions
                                    │
                      <───────────── PhaseResult
apply_result(result)
```

### 8. Performance Projections

| Scenario | Python | Kernel (2-10x) | Engine (30-50x) |
|----------|--------|----------------|-----------------|
| 50 rules | 1.2ms | 200-600µs | 25µs |
| 200 rules | 4ms | 600µs-2ms | 100µs |
| 500 rules | 12ms | 2-6ms | 250µs |
| 1000 rules | 25ms | 4-12ms | 500µs |

**Why engine is so much faster:**
- 1 FFI call vs hundreds
- No Python loop overhead (~15µs/rule saved)
- No per-match object allocation
- Arena allocator for per-request data
- SIMD for transforms
- Aho-Corasick compiled once

### 9. Rust Implementation Architecture

```
lewaf-kernel-rust/
├── Cargo.toml
├── src/
│   ├── lib.rs              # PyO3 bindings
│   ├── kernel/
│   │   ├── mod.rs          # KernelProtocol impl
│   │   ├── regex.rs        # DFA regex (regex crate)
│   │   ├── phrase.rs       # Aho-Corasick
│   │   └── transforms.rs   # 45 transforms
│   └── engine/
│       ├── mod.rs          # EngineProtocol impl
│       ├── compiler.rs     # Rule compilation
│       ├── evaluator.rs    # Phase evaluation
│       └── transaction.rs  # Native TransactionData
├── python/
│   └── lewaf_kernel_rust/
│       └── __init__.py
└── pyproject.toml          # maturin config
```

**Key Dependencies:**
- `regex` - DFA-based regex
- `aho-corasick` - Multi-pattern matching
- `pyo3` - Python bindings
- `bumpalo` - Arena allocator

### 10. Zig Implementation (Future/Research)

```
lewaf-kernel-zig/
├── build.zig
├── src/
│   ├── kernel/             # KernelProtocol
│   └── engine/             # EngineProtocol
│       ├── compiler.zig    # Comptime rule compilation
│       └── evaluator.zig   # SIMD-optimized evaluation
├── c_shim/                 # HPy C shim
└── python/
```

**Interesting for:**
- WASM compilation (edge deployment)
- Comptime rule compilation (rules baked into binary)
- Smaller binary size

### 11. Migration Path

#### Phase 1: Kernel Integration (ADR-001)
- Wire up KernelProtocol in Rule.evaluate()
- Python kernel as default
- All tests pass

#### Phase 2: Rust Kernel
- Implement KernelProtocol in Rust
- Publish lewaf-kernel-rust 0.1.0
- Target: 2-10x speedup

#### Phase 3: Engine Protocol
- Define EngineProtocol
- Add integration point in RuleGroup
- Implement Python reference engine (uses kernel)

#### Phase 4: Rust Engine
- Implement rule compilation
- Implement evaluate_phase
- Target: 30-50x speedup

#### Phase 5: Zig (Optional)
- WASM target
- Comptime optimization research

### 12. Versioning and Compatibility

```python
# Protocol versions
KERNEL_PROTOCOL_VERSION = "1.0"
ENGINE_PROTOCOL_VERSION = "1.0"

# Native package declares compatibility
SUPPORTED_LEWAF_VERSIONS = ["0.7.*", "0.8.*"]
```

### 13. Testing Strategy

```bash
# Test with specific implementations
LEWAF_KERNEL=rust LEWAF_ENGINE=rust pytest
LEWAF_KERNEL=python LEWAF_ENGINE=none pytest  # Pure Python

# Performance regression tests
pytest tests/benchmarks/ --kernel=rust --engine=rust
```

## Consequences

### Positive

1. **Two optimization tiers** - Choose based on needs
2. **Clean separation** - Main repo stays simple
3. **Graceful degradation** - Python always works
4. **Maximum performance available** - 30-50x with engine

### Negative

1. **Complexity** - Two protocols to maintain
2. **Engine requires more native code** - ~3,500 LOC vs ~500
3. **Rule compilation overhead** - Startup cost (mitigated by caching)
4. **Harder to debug engine** - Less visibility into native execution

### Trade-offs

| Aspect | Kernel Only | Kernel + Engine |
|--------|-------------|-----------------|
| Speedup | 2-10x | 30-50x |
| Native code | ~500 LOC | ~4,000 LOC |
| Complexity | Low | Medium |
| Debugging | Easy | Harder for engine |
| Startup cost | None | Rule compilation |

## Recommendation

**Implement both levels incrementally:**

1. Start with Kernel (quick wins, validates approach)
2. Add Engine when performance requirements demand it
3. Auto-select based on ruleset size and available implementations

```python
def get_evaluator(rules: list[Rule]) -> Evaluator:
    engine = default_engine()
    kernel = default_kernel()

    # Engine beneficial for many rules
    if engine and len(rules) > 50:
        return EngineEvaluator(engine, rules)

    # Kernel for smaller rulesets
    if kernel:
        return KernelEvaluator(kernel, rules)

    # Pure Python fallback
    return PythonEvaluator(rules)
```

## References

- ADR-001 - Kernel integration (immediate refactoring)
- `experimental/notes/BENCHMARK-REPORT.md` - Performance analysis
- `experimental/notes/extended-kernel-analysis.md` - Engine-level analysis
- `experimental/notes/future-vision.md` - Architecture vision
- `src/lewaf/kernel/protocol.py` - KernelProtocol definition
