"""Configuration file loader with environment variable substitution."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

from lewaf.config.models import WAFConfig


class ConfigLoader:
    """Load WAF configuration from YAML or JSON files."""

    # Pattern for environment variable substitution: ${VAR_NAME} or ${VAR_NAME:-default}
    ENV_VAR_PATTERN = re.compile(r"\$\{([A-Z_][A-Z0-9_]*?)(?::-(.*?))?\}")

    def __init__(self, env_vars: dict[str, str] | None = None):
        """Initialize config loader.

        Args:
            env_vars: Environment variables to use (defaults to os.environ)
        """
        self.env_vars = env_vars if env_vars is not None else dict(os.environ)

    def load_from_file(self, file_path: str | Path) -> WAFConfig:
        """Load configuration from file.

        Args:
            file_path: Path to YAML or JSON configuration file

        Returns:
            WAFConfig instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file format is unsupported or invalid
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        # Read file content
        with open(file_path, encoding="utf-8") as f:
            content = f.read()

        # Substitute environment variables
        content = self._substitute_env_vars(content)

        # Parse based on file extension
        if file_path.suffix in [".yaml", ".yml"]:
            data = yaml.safe_load(content)
        elif file_path.suffix == ".json":
            data = json.loads(content)
        else:
            raise ValueError(
                f"Unsupported file format: {file_path.suffix}. Use .yaml, .yml, or .json"
            )

        if not isinstance(data, dict):
            raise ValueError("Configuration file must contain a dictionary/object")

        # Handle nested "waf" key (common pattern)
        if "waf" in data and isinstance(data["waf"], dict):
            data = data["waf"]

        return WAFConfig.from_dict(data)

    def load_from_dict(self, data: dict[str, Any]) -> WAFConfig:
        """Load configuration from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            WAFConfig instance
        """
        # Convert dict to JSON and back to apply env var substitution
        json_str = json.dumps(data)
        json_str = self._substitute_env_vars(json_str)
        data = json.loads(json_str)

        return WAFConfig.from_dict(data)

    def _substitute_env_vars(self, content: str) -> str:
        """Substitute environment variables in content.

        Supports patterns:
        - ${VAR_NAME} - Required variable
        - ${VAR_NAME:-default_value} - Optional with default

        Args:
            content: String content with potential env var references

        Returns:
            Content with substituted values

        Raises:
            ValueError: If required environment variable is not set
        """

        def replace_var(match: re.Match) -> str:
            var_name = match.group(1)
            default_value = match.group(2)

            # Get value from environment
            value = self.env_vars.get(var_name)

            if value is None:
                if default_value is not None:
                    return default_value
                raise ValueError(f"Required environment variable not set: {var_name}")

            return value

        return self.ENV_VAR_PATTERN.sub(replace_var, content)


def load_config(file_path: str | Path) -> WAFConfig:
    """Convenience function to load configuration from file.

    Args:
        file_path: Path to configuration file

    Returns:
        WAFConfig instance
    """
    loader = ConfigLoader()
    return loader.load_from_file(file_path)
