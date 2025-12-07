# ADR-001: Kernel Integration for Rule Evaluation

**Status:** Implemented
**Date:** 2025-12-07
**Authors:** LeWAF Team

## Context

LeWAF has a well-designed `KernelProtocol` in `src/lewaf/kernel/protocol.py` that defines a pluggable interface for performance-critical operations:

- **Level 1:** Primitive operations (regex_match, transform, phrase_match)
- **Level 2:** Operator evaluation (evaluate_rx, evaluate_pm, etc.)
- **Level 2.5:** Generic operator dispatch (evaluate_operator)
- **Level 3:** Complete rule evaluation (evaluate_rule)

The main codebase provides:
- `KernelProtocol` - The interface that all kernels must implement
- `PythonKernel` - Pure Python reference implementation

**Design Principle:** The main LeWAF codebase does not know about native implementations (Rust, Zig, etc.). External packages (e.g., `lewaf-kernel-rust`) provide their own kernel implementations and register them explicitly.

## Decision

We have completed the kernel integration by:

1. **Making `Rule.evaluate()` use the kernel** for the hot path
2. **Keeping operators for parsing and configuration** but delegating execution
3. **Maintaining full backwards compatibility** - existing code continues to work
4. **Using explicit kernel registration** - external packages call `set_default_kernel()`

### Integration Points

#### 1. Rule Evaluation (Primary Change)

**Before**:
```python
# Direct operator call
match_result = self.operator.op.evaluate(
    cast("Any", transaction), transformed_value
)
```

**After**:
```python
from lewaf.kernel import default_kernel

# Delegate to kernel
kernel = default_kernel()
match_result, captures = kernel.evaluate_operator(
    self.operator.name,
    self.operator.argument,
    transformed_value,
    capture=capturing,
)
if captures and capturing:
    for i, capture in enumerate(captures[:9]):
        transaction.capture_field(i + 1, capture)
```

#### 2. Transformation Chain (Secondary Change)

**Before**:
```python
for t_name in self.transformations:
    transformed_value, _ = TRANSFORMATIONS[t_name.lower()](transformed_value)
```

**After**:
```python
kernel = default_kernel()
transformed_value = kernel.transform_chain(
    [str(t) for t in self.transformations], value
)
```

#### 3. Kernel Selection (Explicit Registration)

The kernel is managed via explicit registration:

```python
from lewaf.kernel import default_kernel, set_default_kernel, reset_default_kernel

# Get current kernel (PythonKernel by default)
kernel = default_kernel()

# External packages register their kernel:
from lewaf_kernel_rust import RustKernel
set_default_kernel(RustKernel())

# Reset to default (useful for testing)
reset_default_kernel()
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

1. **Enables native kernels** - External packages can provide Rust/Zig implementations
2. **Clean separation** - Main codebase doesn't know about native implementations
3. **Single source of truth** - Evaluation logic lives in kernel, not scattered across operators
4. **Easier testing** - Can test kernels in isolation
5. **No breaking changes** - Existing code works unchanged
6. **Explicit control** - Users explicitly choose which kernel to use

### Negative

1. **Slight indirection** - One additional function call per evaluation
2. **Kernel must implement all operators** - 32 operators to support (with fallback for unknown operators)
3. **Captures handling complexity** - Kernel returns captures, caller handles transaction

### Neutral

1. **Operators become "dumb"** - Just store configuration, don't execute
2. **PythonKernel wraps existing code** - No duplication, just delegation

## Implementation Notes

### Fallback Mechanism

The `PythonKernel.evaluate_operator()` includes a fallback for operators not yet implemented in the kernel:

```python
def evaluate_operator(self, operator_name, operator_arg, value, capture=False):
    # Try kernel-native operators first
    if op_name == "rx":
        return self.evaluate_rx(operator_arg, value, capture)
    # ... other operators ...

    # Unknown operator - fall back to existing operator implementation
    return self._fallback_evaluate(operator_name, operator_arg, value, capture)
```

This ensures backwards compatibility while operators are migrated to the kernel.

### External Kernel Registration

External packages should register their kernel at import time or application startup:

```python
# In lewaf_kernel_rust/__init__.py
from lewaf.kernel import set_default_kernel
from .kernel import RustKernel

# Auto-register when package is imported
set_default_kernel(RustKernel())
```

Or let users explicitly register:

```python
# In user's application
import lewaf_kernel_rust  # Provides RustKernel
from lewaf.kernel import set_default_kernel

set_default_kernel(lewaf_kernel_rust.RustKernel())
```

## References

- `src/lewaf/kernel/protocol.py` - KernelProtocol definition
- `src/lewaf/kernel/python_kernel.py` - Python reference implementation
- `src/lewaf/kernel/__init__.py` - Kernel module with registration functions
- `src/lewaf/rules/__init__.py` - Rule.evaluate() using kernel
- ADR-002 - Native kernel strategy (separate repos)
