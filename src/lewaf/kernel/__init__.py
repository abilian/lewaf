"""Pluggable kernel module for LeWAF.

This module provides a strategy pattern for swapping between different
kernel implementations at runtime. The main codebase provides PythonKernel
as the default. External packages (e.g., lewaf-kernel-rust) can register
their own implementations.

Plugin API (for kernel authors):
    KernelProtocol - Interface that kernel implementations must satisfy
    set_default_kernel - Register a custom kernel implementation

Internal API:
    PythonKernel, default_kernel, reset_default_kernel

Example (for plugin authors):
    from lewaf.kernel import KernelProtocol, set_default_kernel

    class MyKernel:
        # Implement KernelProtocol methods...
        pass

    set_default_kernel(MyKernel())
"""

from __future__ import annotations

from lewaf.kernel.protocol import KernelProtocol
from lewaf.kernel.python_kernel import PythonKernel

# Only export the minimal public API
__all__ = [
    # Plugin API (stable for 1.0)
    "KernelProtocol",
    # Internal API (may change between versions)
    "PythonKernel",
    "default_kernel",
    "reset_default_kernel",
    "set_default_kernel",
]


# Default kernel singleton
_default_kernel: KernelProtocol | None = None


def default_kernel() -> KernelProtocol:
    """
    Get the default kernel (cached singleton).

    Returns PythonKernel by default. External packages can override
    this by calling set_default_kernel() with their implementation.
    """
    global _default_kernel
    if _default_kernel is None:
        _default_kernel = PythonKernel()
    return _default_kernel


def set_default_kernel(kernel: KernelProtocol) -> None:
    """
    Set the default kernel to use.

    This allows external packages (e.g., lewaf-kernel-rust) to register
    their kernel implementation without the main codebase knowing about them.

    Args:
        kernel: A kernel instance implementing KernelProtocol.

    Example:
        from lewaf.kernel import set_default_kernel
        from lewaf_kernel_rust import RustKernel
        set_default_kernel(RustKernel())
    """
    global _default_kernel
    _default_kernel = kernel


def reset_default_kernel() -> None:
    """Reset the default kernel singleton (useful for testing)."""
    global _default_kernel
    _default_kernel = None
