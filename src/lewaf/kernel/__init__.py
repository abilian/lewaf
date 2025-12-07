"""
Pluggable kernel module for LeWAF.

This module provides a strategy pattern for swapping between different
kernel implementations (Python, Rust, Zig) at runtime.

Usage:
    from lewaf.kernel import get_kernel, KernelType

    # Auto-detect best available kernel
    kernel = get_kernel()

    # Force specific kernel
    kernel = get_kernel(KernelType.PYTHON)
    kernel = get_kernel(KernelType.RUST)
    kernel = get_kernel(KernelType.ZIG)

    # Or via environment variable
    # LEWAF_KERNEL=rust python your_script.py
    # LEWAF_KERNEL=zig python your_script.py
"""

from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lewaf.kernel.protocol import KernelProtocol

__all__ = [
    "KernelType",
    "default_kernel",
    "get_kernel",
    "rust_available",
    "zig_available",
]


class KernelType(Enum):
    """Available kernel implementations."""

    PYTHON = "python"
    RUST = "rust"
    ZIG = "zig"
    AUTO = "auto"  # Rust if available, else Zig, else Python


@lru_cache(maxsize=1)
def rust_available() -> bool:
    """Check if Rust kernel is available."""
    try:
        import lewaf_core  # noqa: F401

        return True
    except ImportError:
        return False


@lru_cache(maxsize=1)
def zig_available() -> bool:
    """Check if Zig kernel is available."""
    try:
        from lewaf.kernel.zig_kernel import is_available

        return is_available()
    except ImportError:
        return False


def get_kernel(kernel_type: KernelType | str = KernelType.AUTO) -> KernelProtocol:
    """
    Get a kernel implementation.

    Args:
        kernel_type: Which kernel to use. Can be KernelType enum or string.
                     Can also be overridden via LEWAF_KERNEL environment variable.

    Returns:
        Kernel implementation instance.

    Raises:
        ImportError: If Rust kernel requested but lewaf_core not installed.
        ValueError: If invalid kernel type specified.
    """
    # Environment variable override
    env_kernel = os.environ.get("LEWAF_KERNEL", "").lower()
    if env_kernel:
        try:
            kernel_type = KernelType(env_kernel)
        except ValueError:
            valid = ", ".join(k.value for k in KernelType)
            msg = f"Invalid LEWAF_KERNEL value: {env_kernel}. Valid: {valid}"
            raise ValueError(msg) from None
    elif isinstance(kernel_type, str):
        try:
            kernel_type = KernelType(kernel_type.lower())
        except ValueError:
            valid = ", ".join(k.value for k in KernelType)
            msg = f"Invalid kernel_type: {kernel_type}. Valid: {valid}"
            raise ValueError(msg) from None

    if kernel_type == KernelType.AUTO:
        if rust_available():
            kernel_type = KernelType.RUST
        elif zig_available():
            kernel_type = KernelType.ZIG
        else:
            kernel_type = KernelType.PYTHON

    if kernel_type == KernelType.RUST:
        if not rust_available():
            msg = (
                "Rust kernel requested but lewaf_core not installed. "
                "Install with: pip install lewaf-core"
            )
            raise ImportError(msg)
        from lewaf.kernel.rust_kernel import RustKernel

        return RustKernel()

    if kernel_type == KernelType.ZIG:
        if not zig_available():
            msg = (
                "Zig kernel requested but lewaf-zig not available. "
                "Build with: cd lewaf-zig && zig build -Doptimize=ReleaseFast"
            )
            raise ImportError(msg)
        from lewaf.kernel.zig_kernel import ZigKernel

        return ZigKernel()

    from lewaf.kernel.python_kernel import PythonKernel

    return PythonKernel()


# Default kernel singleton
_default_kernel: KernelProtocol | None = None


def default_kernel() -> KernelProtocol:
    """
    Get the default kernel (cached singleton).

    Uses AUTO detection on first call, then caches the result.
    """
    global _default_kernel
    if _default_kernel is None:
        _default_kernel = get_kernel()
    return _default_kernel


def reset_default_kernel() -> None:
    """Reset the default kernel singleton (useful for testing)."""
    global _default_kernel
    _default_kernel = None
