"""Tests for configuration manager with hot-reload."""

from __future__ import annotations

import signal
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from lewaf.config.manager import ConfigManager, ConfigVersion
from lewaf.config.models import WAFConfig
from lewaf.config.profiles import Environment


def test_config_manager_initialization():
    """Test ConfigManager initialization."""
    manager = ConfigManager(auto_reload_on_signal=False)

    assert manager.get_version() == 1
    config = manager.get_config()
    assert isinstance(config, WAFConfig)


def test_config_manager_with_file():
    """Test ConfigManager with config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": ['SecRule ARGS "@rx test" "id:1,deny"'],
            },
            f,
        )
        temp_path = f.name

    try:
        manager = ConfigManager(config_file=temp_path, auto_reload_on_signal=False)

        config = manager.get_config()
        assert config.engine == "On"
        assert len(config.rules) == 1
    finally:
        Path(temp_path).unlink()


def test_config_manager_with_environment():
    """Test ConfigManager with explicit environment."""
    manager = ConfigManager(
        environment=Environment.DEVELOPMENT,
        auto_reload_on_signal=False,
    )

    config = manager.get_config()
    assert config.engine == "DetectionOnly"
    assert config.storage.backend == "memory"


def test_config_manager_reload():
    """Test configuration reload."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"engine": "DetectionOnly"}, f)
        temp_path = f.name

    try:
        manager = ConfigManager(config_file=temp_path, auto_reload_on_signal=False)

        # Initial config
        config1 = manager.get_config()
        assert config1.engine == "DetectionOnly"
        version1 = manager.get_version()

        # Update file
        with open(temp_path, "w") as f:
            yaml.dump({"engine": "On"}, f)

        # Reload
        config2 = manager.reload()
        assert config2.engine == "On"
        version2 = manager.get_version()

        assert version2 == version1 + 1
    finally:
        Path(temp_path).unlink()


def test_config_manager_reload_with_overrides():
    """Test reload with overrides."""
    manager = ConfigManager(auto_reload_on_signal=False)

    # Reload with overrides
    config = manager.reload(overrides={"engine": "On"})

    assert config.engine == "On"


def test_config_manager_version_tracking():
    """Test version tracking across reloads."""
    manager = ConfigManager(auto_reload_on_signal=False)

    version1 = manager.get_version()
    assert version1 == 1

    manager.reload()
    version2 = manager.get_version()
    assert version2 == 2

    manager.reload()
    version3 = manager.get_version()
    assert version3 == 3


def test_config_manager_history():
    """Test configuration history."""
    manager = ConfigManager(auto_reload_on_signal=False)

    # Initial load
    assert len(manager.get_history()) == 0

    # Reload twice
    manager.reload(overrides={"engine": "DetectionOnly"})
    manager.reload(overrides={"engine": "On"})

    # Check history
    history = manager.get_history()
    assert len(history) == 2
    assert all(isinstance(v, ConfigVersion) for v in history)


def test_config_manager_get_config_at_version():
    """Test retrieving config at specific version."""
    manager = ConfigManager(auto_reload_on_signal=False)

    # Current version
    current_config = manager.get_config_at_version(1)
    assert current_config is not None
    assert current_config == manager.get_config()

    # Reload
    manager.reload(overrides={"engine": "On"})

    # Get old version
    old_config = manager.get_config_at_version(1)
    assert old_config is not None

    # Get current version
    new_config = manager.get_config_at_version(2)
    assert new_config is not None
    assert new_config.engine == "On"

    # Non-existent version
    missing = manager.get_config_at_version(999)
    assert missing is None


def test_config_manager_history_limit():
    """Test history is limited to max size."""
    manager = ConfigManager(auto_reload_on_signal=False)
    manager._max_history = 3

    # Reload many times
    for i in range(10):
        manager.reload()

    # History should be limited
    history = manager.get_history()
    assert len(history) <= 3


def test_config_manager_reload_callback():
    """Test reload callbacks."""
    manager = ConfigManager(auto_reload_on_signal=False)

    callback_called = []

    def callback(old_config: WAFConfig, new_config: WAFConfig) -> None:
        callback_called.append((old_config, new_config))

    manager.register_reload_callback(callback)

    # Reload
    manager.reload(overrides={"engine": "On"})

    # Check callback was called
    assert len(callback_called) == 1
    old_config, new_config = callback_called[0]
    assert isinstance(old_config, WAFConfig)
    assert isinstance(new_config, WAFConfig)
    assert new_config.engine == "On"


def test_config_manager_multiple_callbacks():
    """Test multiple reload callbacks."""
    manager = ConfigManager(auto_reload_on_signal=False)

    callback1_calls = []
    callback2_calls = []

    def callback1(old: WAFConfig, new: WAFConfig) -> None:
        callback1_calls.append((old, new))

    def callback2(old: WAFConfig, new: WAFConfig) -> None:
        callback2_calls.append((old, new))

    manager.register_reload_callback(callback1)
    manager.register_reload_callback(callback2)

    # Reload
    manager.reload()

    # Both callbacks should be called
    assert len(callback1_calls) == 1
    assert len(callback2_calls) == 1


def test_config_manager_unregister_callback():
    """Test unregistering callbacks."""
    manager = ConfigManager(auto_reload_on_signal=False)

    callback_calls = []

    def callback(old: WAFConfig, new: WAFConfig) -> None:
        callback_calls.append((old, new))

    manager.register_reload_callback(callback)
    manager.unregister_reload_callback(callback)

    # Reload
    manager.reload()

    # Callback should not be called
    assert len(callback_calls) == 0


def test_config_manager_callback_error_handling():
    """Test that callback errors don't break reload."""
    manager = ConfigManager(auto_reload_on_signal=False)

    def bad_callback(old: WAFConfig, new: WAFConfig) -> None:
        raise RuntimeError("Callback error")

    manager.register_reload_callback(bad_callback)

    # Reload should succeed despite callback error
    config = manager.reload()
    assert isinstance(config, WAFConfig)


def test_config_manager_thread_safety():
    """Test thread-safe config access."""
    import threading

    manager = ConfigManager(auto_reload_on_signal=False)

    results = []
    errors = []

    def reader_thread() -> None:
        try:
            for _ in range(10):
                config = manager.get_config()
                results.append(config)
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)

    def writer_thread() -> None:
        try:
            for _ in range(5):
                manager.reload()
                time.sleep(0.002)
        except Exception as e:
            errors.append(e)

    # Start threads
    threads = [
        threading.Thread(target=reader_thread),
        threading.Thread(target=reader_thread),
        threading.Thread(target=writer_thread),
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # Should have no errors
    assert len(errors) == 0
    assert len(results) > 0


def test_config_manager_validate_config_file():
    """Test config file validation."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "On",
                "rules": [],
            },
            f,
        )
        temp_path = f.name

    try:
        manager = ConfigManager(config_file=temp_path, auto_reload_on_signal=False)

        is_valid, errors, warnings = manager.validate_config_file()

        assert is_valid is True
        assert len(errors) == 0
    finally:
        Path(temp_path).unlink()


def test_config_manager_validate_invalid_config():
    """Test validation of invalid config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump(
            {
                "engine": "InvalidMode",  # Invalid
            },
            f,
        )
        temp_path = f.name

    try:
        manager = ConfigManager(config_file=temp_path, auto_reload_on_signal=False)

        is_valid, errors, warnings = manager.validate_config_file()

        assert is_valid is False
        assert len(errors) > 0
    finally:
        Path(temp_path).unlink()


def test_config_manager_signal_handler_installation():
    """Test SIGHUP signal handler installation."""
    # Only test on systems with SIGHUP
    if not hasattr(signal, "SIGHUP"):
        pytest.skip("SIGHUP not available on this platform")

    manager = ConfigManager(auto_reload_on_signal=True)

    assert manager._signal_handler_installed is True


def test_config_manager_no_signal_handler():
    """Test manager without signal handler."""
    manager = ConfigManager(auto_reload_on_signal=False)

    assert manager._signal_handler_installed is False


def test_config_manager_reload_failure_handling():
    """Test handling of reload failures."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        yaml.dump({"engine": "On"}, f)
        temp_path = f.name

    try:
        manager = ConfigManager(config_file=temp_path, auto_reload_on_signal=False)

        # Get initial config
        config1 = manager.get_config()

        # Corrupt the file
        Path(temp_path).write_text("invalid: yaml: [unclosed")

        # Reload should fail
        with pytest.raises(Exception):
            manager.reload()

        # Original config should still be accessible
        config2 = manager.get_config()
        assert config2 == config1
    finally:
        Path(temp_path).unlink()


def test_config_manager_watch_file_without_file():
    """Test watch_file raises error without config file."""
    manager = ConfigManager(auto_reload_on_signal=False)

    with pytest.raises(ValueError, match="no config file specified"):
        manager.watch_file()


def test_config_manager_get_config_before_load():
    """Test get_config raises error if no config loaded."""
    manager = ConfigManager(auto_reload_on_signal=False)
    manager._current_config = None

    with pytest.raises(RuntimeError, match="No configuration loaded"):
        manager.get_config()


def test_config_version_attributes():
    """Test ConfigVersion attributes."""
    from datetime import datetime, timezone

    config = WAFConfig()
    now = datetime.now(timezone.utc)
    version = ConfigVersion(1, config, now)

    assert version.version == 1
    assert version.config == config
    assert version.loaded_at == now
