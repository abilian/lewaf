"""Configuration management for LeWAF.

Public API:
    WAFConfig - Main configuration dataclass
    ConfigLoader - Load configuration from YAML/JSON files
    load_config - Convenience function for loading config

Internal API (subject to change):
    ConfigManager, ConfigProfile, ConfigValidator, etc.
"""

from __future__ import annotations

# Public API
from lewaf.config.loader import ConfigLoader, load_config

# Internal API - exposed for advanced use cases but not part of stable API
from lewaf.config.manager import ConfigManager, ConfigVersion
from lewaf.config.models import WAFConfig
from lewaf.config.profiles import (
    ConfigProfile,
    Environment,
    load_config_with_profile,
    merge_configs,
)
from lewaf.config.validator import ConfigValidator

# Only export the minimal public API
__all__ = [
    "ConfigLoader",
    # Internal API (may change between versions)
    # Exposed for advanced users but not guaranteed stable
    "ConfigManager",
    "ConfigProfile",
    "ConfigValidator",
    "ConfigVersion",
    "Environment",
    # Public API (stable for 1.0)
    "WAFConfig",
    "load_config",
    "load_config_with_profile",
    "merge_configs",
]
