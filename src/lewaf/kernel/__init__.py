"""
Pluggable kernel module for LeWAF.

This module provides a strategy pattern for swapping between different
kernel implementations at runtime. The main codebase only provides the
PythonKernel as default. External packages (e.g., lewaf-kernel-rust)
can register their own implementations.

Usage:
    from lewaf.kernel import default_kernel, set_default_kernel

    # Get the current kernel (PythonKernel by default)
    kernel = default_kernel()

    # External packages can register their kernel:
    from lewaf.kernel import set_default_kernel
    from lewaf_kernel_rust import RustKernel
    set_default_kernel(RustKernel())
"""

from __future__ import annotations

from lewaf.kernel.protocol import KernelProtocol
from lewaf.kernel.python_kernel import PythonKernel

__all__ = [
    "KernelProtocol",
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
