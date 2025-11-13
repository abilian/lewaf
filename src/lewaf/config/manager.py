"""Configuration manager with hot-reload support."""

from __future__ import annotations

import logging
import signal
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from lewaf.config.models import WAFConfig
from lewaf.config.profiles import Environment, load_config_with_profile

logger = logging.getLogger(__name__)


class ConfigVersion:
    """Configuration version tracking."""

    def __init__(self, version: int, config: WAFConfig, loaded_at: datetime):
        """Initialize config version.

        Args:
            version: Version number
            config: Configuration data
            loaded_at: Timestamp when loaded
        """
        self.version = version
        self.config = config
        self.loaded_at = loaded_at


class ConfigManager:
    """Manages configuration with hot-reload support.

    Features:
    - Hot-reload without restart
    - Signal-based reload (SIGHUP)
    - Configuration versioning
    - Thread-safe updates
    - Reload callbacks
    """

    def __init__(
        self,
        config_file: str | Path | None = None,
        environment: Environment | None = None,
        auto_reload_on_signal: bool = True,
    ):
        """Initialize configuration manager.

        Args:
            config_file: Path to configuration file
            environment: Environment (auto-detected if None)
            auto_reload_on_signal: Enable SIGHUP signal handler
        """
        self.config_file = Path(config_file) if config_file else None
        self.environment = environment

        # Thread safety
        self._lock = threading.RLock()

        # Current configuration
        self._current_version = 0
        self._current_config: WAFConfig | None = None
        self._config_history: list[ConfigVersion] = []
        self._max_history = 10

        # Reload callbacks
        self._reload_callbacks: list[Callable[[WAFConfig, WAFConfig], None]] = []

        # Signal handling
        self._signal_handler_installed = False
        if auto_reload_on_signal:
            self._install_signal_handler()

        # Load initial configuration
        self.reload()

    def get_config(self) -> WAFConfig:
        """Get current configuration.

        Returns:
            Current WAFConfig instance

        Raises:
            RuntimeError: If no configuration loaded
        """
        with self._lock:
            if self._current_config is None:
                msg = "No configuration loaded"
                raise RuntimeError(msg)
            return self._current_config

    def reload(self, overrides: dict[str, Any] | None = None) -> WAFConfig:
        """Reload configuration from file.

        Args:
            overrides: Optional override dictionary

        Returns:
            New WAFConfig instance

        Raises:
            Exception: If reload fails
        """
        logger.info("Reloading configuration...")

        try:
            # Load new configuration
            new_config = load_config_with_profile(
                config_file=str(self.config_file) if self.config_file else None,
                environment=self.environment,
                overrides=overrides,
            )

            with self._lock:
                old_config = self._current_config

                # Update version
                self._current_version += 1

                # Save to history
                if old_config:
                    version = ConfigVersion(
                        self._current_version - 1,
                        old_config,
                        datetime.now(timezone.utc),
                    )
                    self._config_history.append(version)

                    # Trim history
                    if len(self._config_history) > self._max_history:
                        self._config_history = self._config_history[
                            -self._max_history :
                        ]

                # Update current
                self._current_config = new_config

                logger.info(
                    f"Configuration reloaded successfully (version {self._current_version})"
                )

                # Notify callbacks
                if old_config:
                    self._notify_reload_callbacks(old_config, new_config)

            return new_config

        except Exception as e:
            logger.error("Failed to reload configuration: %s", e)
            raise

    def register_reload_callback(
        self, callback: Callable[[WAFConfig, WAFConfig], None]
    ) -> None:
        """Register callback for configuration reloads.

        Callback receives (old_config, new_config) as arguments.

        Args:
            callback: Callback function
        """
        with self._lock:
            self._reload_callbacks.append(callback)

    def unregister_reload_callback(
        self, callback: Callable[[WAFConfig, WAFConfig], None]
    ) -> None:
        """Unregister reload callback.

        Args:
            callback: Callback function to remove
        """
        with self._lock:
            if callback in self._reload_callbacks:
                self._reload_callbacks.remove(callback)

    def _notify_reload_callbacks(
        self, old_config: WAFConfig, new_config: WAFConfig
    ) -> None:
        """Notify all registered callbacks of config reload.

        Args:
            old_config: Previous configuration
            new_config: New configuration
        """
        for callback in self._reload_callbacks:
            try:
                callback(old_config, new_config)
            except Exception as e:
                logger.error("Error in reload callback: %s", e)

    def get_version(self) -> int:
        """Get current configuration version.

        Returns:
            Version number
        """
        with self._lock:
            return self._current_version

    def get_history(self) -> list[ConfigVersion]:
        """Get configuration history.

        Returns:
            List of previous configuration versions
        """
        with self._lock:
            return list(self._config_history)

    def get_config_at_version(self, version: int) -> WAFConfig | None:
        """Get configuration at specific version.

        Args:
            version: Version number

        Returns:
            Configuration at that version, or None if not found
        """
        with self._lock:
            if version == self._current_version and self._current_config:
                return self._current_config

            for config_version in self._config_history:
                if config_version.version == version:
                    return config_version.config

            return None

    def _install_signal_handler(self) -> None:
        """Install SIGHUP signal handler for hot reload."""
        if self._signal_handler_installed:
            return

        def handle_sighup(signum: int, frame: Any) -> None:
            """Handle SIGHUP signal by reloading configuration."""
            logger.info("Received SIGHUP, reloading configuration...")
            try:
                self.reload()
            except Exception as e:
                logger.error("Failed to reload configuration on SIGHUP: %s", e)

        # Only install on Unix-like systems
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, handle_sighup)
            self._signal_handler_installed = True
            logger.debug("SIGHUP signal handler installed")

    def validate_config_file(self) -> tuple[bool, list[str], list[str]]:
        """Validate configuration file without loading.

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        from lewaf.config.validator import ConfigValidator

        try:
            # Load config
            config = load_config_with_profile(
                config_file=str(self.config_file) if self.config_file else None,
                environment=self.environment,
            )

            # Validate
            validator = ConfigValidator()
            return validator.validate(config)

        except Exception as e:
            return False, [f"Failed to load config: {e}"], []

    def watch_file(self, interval: float = 5.0) -> None:
        """Watch config file for changes and auto-reload.

        This starts a background thread that checks the file modification time.

        Args:
            interval: Check interval in seconds
        """
        if not self.config_file:
            msg = "Cannot watch file: no config file specified"
            raise ValueError(msg)

        def watch_thread() -> None:
            """Background thread to watch for file changes."""
            import time

            last_mtime = self.config_file.stat().st_mtime if self.config_file else 0

            while True:
                try:
                    time.sleep(interval)

                    if not self.config_file or not self.config_file.exists():
                        continue

                    current_mtime = self.config_file.stat().st_mtime
                    if current_mtime != last_mtime:
                        logger.info("Config file changed, reloading...")
                        self.reload()
                        last_mtime = current_mtime

                except Exception as e:
                    logger.error("Error in file watch thread: %s", e)

        thread = threading.Thread(target=watch_thread, daemon=True)
        thread.start()
        logger.info(f"Started watching config file: {self.config_file}")
