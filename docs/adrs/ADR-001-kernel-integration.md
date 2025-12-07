# ADR-001: Kernel Integration for Rule Evaluation

**Status:** Proposed
**Date:** 2025-12-07
**Authors:** LeWAF Team

## Context

LeWAF has a well-designed `KernelProtocol` in `src/lewaf/kernel/protocol.py` that defines a pluggable interface for performance-critical operations:

- **Level 1:** Primitive operations (regex_match, transform, phrase_match)
- **Level 2:** Operator evaluation (evaluate_rx, evaluate_pm, etc.)
- **Level 3:** Complete rule evaluation (evaluate_rule)

Three kernel implementations exist:
- `PythonKernel` - Pure Python reference implementation
- `RustKernel` - Stub for Rust/PyO3 bindings
- `ZigKernel` - Stub for Zig/cffi bindings

**Problem:** The kernel infrastructure is not yet integrated into the main rule evaluation loop. `Rule.evaluate()` still calls operators directly, bypassing the kernel abstraction.

This creates two issues:
1. **No benefit from pluggable kernels** - Native implementations cannot be used
2. **Duplicated logic** - Operators implement evaluation logic that could be delegated to kernels

## Decision

We will complete the kernel integration by:

1. **Making `Rule.evaluate()` use the kernel** for the hot path
2. **Keeping operators for parsing and configuration** but delegating execution
3. **Maintaining full backwards compatibility** - existing code continues to work
4. **Using auto-detection** for kernel selection with environment override

### Integration Points

#### 1. Rule Evaluation (Primary Change)

**Current** (`rules/__init__.py`):
```python
# Direct operator call
match_result = self.operator.op.evaluate(
    cast("Any", transaction), transformed_value
)
```

**Proposed**:
```python
from lewaf.kernel import default_kernel

# Delegate to kernel
kernel = default_kernel()
match_result, captures = kernel.evaluate_operator(
    self.operator.name,
    self.operator.argument,
    transformed_value,
)
if captures and transaction.capturing():
    for i, capture in enumerate(captures[:9]):
        transaction.capture_field(i + 1, capture)
```

#### 2. Transformation Chain (Secondary Change)

**Current**:
```python
for t_name in self.transformations:
    transformed_value, _ = TRANSFORMATIONS[t_name.lower()](transformed_value)
```

**Proposed**:
```python
kernel = default_kernel()
transformed_value = kernel.transform_chain(self.transformations, value)
```

#### 3. Kernel Selection

The kernel is selected once at startup via `default_kernel()`:

```python
# Auto-detection (default)
kernel = default_kernel()  # Tries: Rust > Zig > Python

# Environment override
# LEWAF_KERNEL=python python app.py  # Force Python kernel
# LEWAF_KERNEL=rust python app.py    # Force Rust kernel

# Programmatic override
from lewaf.kernel import set_default_kernel, KernelType
set_default_kernel(KernelType.PYTHON)
```

### What Changes

| Component | Before | After |
|-----------|--------|-------|
| `Rule.evaluate()` | Calls operator directly | Delegates to kernel |
| Transform loop | Calls TRANSFORMATIONS dict | Delegates to kernel |
| Operator classes | Contain evaluation logic | Configuration only (parse, store args) |
| Kernel | Exists but unused | Used for all hot path operations |

### What Stays the Same

- **Operator registration** - `@register_operator` decorator unchanged
- **Transformation registration** - `@register_transformation` decorator unchanged
- **Action execution** - Remains in Python (not performance-critical)
- **Variable extraction** - Remains in Python (collection iteration)
- **Rule parsing** - SecLang parser unchanged
- **Public API** - `WAF`, `Transaction`, `RuleGroup` APIs unchanged

## Consequences

### Positive

1. **Enables native kernels** - Rust/Zig implementations can now accelerate hot paths
2. **Single source of truth** - Evaluation logic lives in kernel, not scattered across operators
3. **Easier testing** - Can test kernels in isolation
4. **No breaking changes** - Existing code works unchanged
5. **Gradual migration** - Can switch kernels without code changes

### Negative

1. **Slight indirection** - One additional function call per evaluation
2. **Kernel must implement all operators** - 32 operators to support
3. **Captures handling complexity** - Kernel returns captures, caller handles transaction

### Neutral

1. **Operators become "dumb"** - Just store configuration, don't execute
2. **PythonKernel wraps existing code** - No duplication, just delegation

## Implementation Plan

### Phase 1: Wire Up Kernel (Minimal Change)
1. Add `kernel.evaluate_operator()` calls in `Rule.evaluate()`
2. Add `kernel.transform_chain()` calls for transforms
3. Ensure `PythonKernel` delegates to existing operator/transform code
4. All tests must pass with Python kernel

### Phase 2: Validate Equivalence
1. Run full test suite with each kernel type
2. Benchmark to ensure no regression
3. Verify CRS compatibility unchanged

### Phase 3: Documentation
1. Document kernel selection options
2. Document how to implement custom kernels

## Alternatives Considered

### Alternative 1: Keep Operators as Primary
Leave operators as the execution path, have them optionally call kernel.

**Rejected:** Creates two code paths, harder to maintain.

### Alternative 2: Remove Operator Classes
Replace operators entirely with kernel methods.

**Rejected:** Breaks backwards compatibility, operators useful for configuration.

### Alternative 3: Lazy Integration
Only use kernel for specific operators (@rx, @pm).

**Rejected:** Inconsistent behavior, harder to reason about.

## References

- `src/lewaf/kernel/protocol.py` - KernelProtocol definition
- `src/lewaf/kernel/python_kernel.py` - Python reference implementation
- `src/lewaf/rules/__init__.py` - Rule.evaluate() (lines 63-161)
- `experimental/notes/extended-kernel-analysis.md` - Performance analysis
