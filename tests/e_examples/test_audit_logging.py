"""Tests for audit logging example."""

from __future__ import annotations

from .conftest import EXAMPLES_DIR, import_module_from_file


class TestAuditLoggingExample:
    """Test audit logging example."""

    def test_audit_logging_import(self):
        """Test that audit logging example can be imported."""
        audit_example = EXAMPLES_DIR / "audit_logging_example.py"
        module = import_module_from_file("audit_logging_test", audit_example)

        assert hasattr(module, "basic_audit_logging_example")
        assert hasattr(module, "attack_detection_example")
        assert hasattr(module, "performance_monitoring_example")

    def test_audit_logging_functions_callable(self):
        """Test that all example functions are callable."""
        audit_example = EXAMPLES_DIR / "audit_logging_example.py"
        module = import_module_from_file("audit_logging_test2", audit_example)

        functions = [
            "basic_audit_logging_example",
            "attack_detection_example",
            "global_logging_configuration",
            "performance_monitoring_example",
            "configuration_change_example",
            "error_logging_example",
            "sensitive_data_masking_example",
        ]

        for func_name in functions:
            assert hasattr(module, func_name)
            assert callable(getattr(module, func_name))
