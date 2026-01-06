"""File inspection operators."""

from __future__ import annotations

import contextlib
import os
import subprocess
import tempfile

from ._base import (
    Operator,
    OperatorFactory,
    OperatorOptions,
    TransactionProtocol,
    register_operator,
)


@register_operator("inspectfile")
class InspectFileOperatorFactory(OperatorFactory):
    """Factory for InspectFile operators."""

    @staticmethod
    def create(options: OperatorOptions) -> InspectFileOperator:
        return InspectFileOperator(options.arguments)


class InspectFileOperator(Operator):
    """File inspection operator that executes external programs."""

    def __init__(self, argument: str):
        super().__init__(argument)
        self._script_path = argument.strip()
        if not self._script_path:
            msg = "InspectFile operator requires a script path"
            raise ValueError(msg)

    def evaluate(self, tx: TransactionProtocol, value: str) -> bool:
        """Execute external script for file inspection."""
        # Security check: only allow certain file extensions
        allowed_extensions = [".pl", ".py", ".sh", ".lua"]
        if not any(self._script_path.endswith(ext) for ext in allowed_extensions):
            msg = f"InspectFile: Script type not allowed: {self._script_path}"
            raise ValueError(msg)

        # Security check: prevent path traversal
        if ".." in self._script_path:
            msg = f"InspectFile: Path traversal not allowed: {self._script_path}"
            raise ValueError(msg)

        try:
            # Create temporary file with the content to inspect
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
                temp_file.write(value)
                temp_file_path = temp_file.name

            try:
                # Execute the script with the temporary file path
                result = subprocess.run(
                    [self._script_path, temp_file_path],
                    capture_output=True,
                    text=True,
                    timeout=30,  # 30 second timeout
                    check=False,
                )

                # Parse output: expect "1 message" for clean, "0 message" for threat
                output = result.stdout.strip()
                if output.startswith("1 "):
                    return False  # Clean file
                if output.startswith("0 "):
                    return True  # Threat detected
                # Unexpected output format, treat as error
                return True

            finally:
                # Clean up temporary file
                with contextlib.suppress(OSError):
                    os.unlink(temp_file_path)

        except subprocess.TimeoutExpired:
            # Script timed out, treat as error
            return True
        except Exception:
            # Any other error, treat as failed inspection
            return True
