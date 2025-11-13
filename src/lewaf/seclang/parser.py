"""SecLang parser for ModSecurity .conf files.

This parser implements the ModSecurity SecLang language specification for loading
rule files.

Reference: ModSecurity v2/v3 and Coraza SecLang syntax
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from lewaf.exceptions import IncludeRecursionError, ParseError

if TYPE_CHECKING:
    from lewaf.integration import WAF

logger = logging.getLogger(__name__)


class SecLangParser:
    """Parser for ModSecurity SecLang configuration files.

    This parser can load .conf files containing SecLang directives and convert them
    into LeWAF Rule objects and configuration settings.

    Example:
        parser = SecLangParser(waf)
        parser.from_file("rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
    """

    MAX_INCLUDE_RECURSION = 100

    def __init__(self, waf: WAF):
        """Initialize the SecLang parser.

        Args:
            waf: WAF instance to add parsed rules to
        """
        self.waf = waf
        self.current_line = 0
        self.current_file = ""
        self.current_dir = ""
        self.include_count = 0

        # Default actions for each phase
        self.default_actions: dict[int, str] = {
            2: "phase:2,log,auditlog,pass",
        }

        # Markers for skipAfter flow control
        self.markers: dict[str, int] = {}  # marker_name -> rule_index

    def from_file(self, file_path: str | Path) -> None:
        """Load and parse a SecLang configuration file.

        Args:
            file_path: Path to the .conf file to load

        Raises:
            ParseError: If the file cannot be parsed
            FileNotFoundError: If the file does not exist
        """
        file_path = Path(file_path)

        # Handle glob patterns
        if "*" in str(file_path):
            files = sorted(file_path.parent.glob(file_path.name))
            if not files:
                logger.warning("No files matching pattern: %s", file_path)
                return

            for f in files:
                self._parse_single_file(f)
        else:
            self._parse_single_file(file_path)

    def _parse_single_file(self, file_path: Path) -> None:
        """Parse a single configuration file.

        Args:
            file_path: Path to the file to parse
        """
        old_file = self.current_file
        old_dir = self.current_dir
        old_line = self.current_line

        try:
            self.current_file = str(file_path)
            self.current_dir = str(file_path.parent)
            self.current_line = 0

            logger.info("Parsing SecLang file: %s", file_path)

            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            self.from_string(content)

        finally:
            # Restore context
            self.current_file = old_file
            self.current_dir = old_dir
            self.current_line = old_line

    def from_string(self, content: str) -> None:
        """Parse SecLang directives from a string.

        Args:
            content: String containing SecLang directives

        Raises:
            ParseError: If the content cannot be parsed
        """
        if not self.current_file:
            self.current_file = "<inline>"

        lines = content.split("\n")
        line_buffer = []
        in_backticks = False

        for line in lines:
            self.current_line += 1
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip comments
            if line.startswith("#"):
                continue

            # Handle backtick-quoted sections (multi-line action lists)
            if not in_backticks and line.endswith("`"):
                in_backticks = True
                line_buffer.append(line)
                continue
            if in_backticks:
                line_buffer.append(line)
                if line.startswith("`"):
                    in_backticks = False
                    # Process the accumulated backtick section
                    full_line = "\\n".join(line_buffer)
                    line_buffer = []
                    self._evaluate_line(full_line)
                continue

            # Handle line continuation
            if line.endswith("\\"):
                line_buffer.append(line[:-1])  # Remove the backslash
                continue
            line_buffer.append(line)
            full_line = "".join(line_buffer)
            line_buffer = []
            self._evaluate_line(full_line)

        if in_backticks:
            msg = "Unclosed backtick section"
            raise ParseError(
                msg, file_path=self.current_file, line_number=self.current_line
            )

        if line_buffer:
            # Process any remaining buffered line
            full_line = "".join(line_buffer)
            self._evaluate_line(full_line)

    def _evaluate_line(self, line: str) -> None:
        """Evaluate a single SecLang directive line.

        Args:
            line: The directive line to evaluate

        Raises:
            ParseError: If the directive cannot be parsed
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return

        # Split directive name from arguments
        parts = line.split(None, 1)
        if not parts:
            return

        directive = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""

        # Remove quotes from arguments if present
        if len(args) >= 2 and args[0] == '"' and args[-1] == '"':
            args = args[1:-1]

        logger.debug(f"Processing directive: {directive} with args: {args[:100]}...")

        # Handle Include directive specially (prevents recursion issues)
        if directive == "include":
            self._handle_include(args)
            return

        # Route to appropriate handler
        handler_name = f"_handle_{directive.replace('-', '_')}"
        handler = getattr(self, handler_name, None)

        if handler:
            try:
                handler(args)
            except Exception as e:
                msg = f"Failed to process {directive}: {e}"
                raise ParseError(
                    msg,
                    file_path=self.current_file,
                    line_number=self.current_line,
                ) from e
        else:
            logger.warning(
                f"Unknown directive '{directive}' at {self.current_file}:{self.current_line}"
            )

    def _handle_include(self, path: str) -> None:
        """Handle Include directive.

        Args:
            path: Path to the file(s) to include

        Raises:
            ParseError: If recursion limit exceeded or file not found
        """
        if self.include_count >= self.MAX_INCLUDE_RECURSION:
            raise IncludeRecursionError(
                file_path=path,
                depth=self.include_count,
                max_depth=self.MAX_INCLUDE_RECURSION,
            )

        self.include_count += 1

        # Resolve path relative to current directory
        if not os.path.isabs(path):
            path = os.path.join(self.current_dir, path)

        self.from_file(path)
        self.include_count -= 1

    def _handle_secrule(self, args: str) -> None:
        """Handle SecRule directive.

        Format: SecRule VARIABLES OPERATOR "ACTIONS"

        Args:
            args: Arguments for SecRule

        Raises:
            ParseError: If the rule cannot be parsed
        """
        from lewaf.seclang.rule_parser import (  # noqa: PLC0415 - Avoids circular import
            SecRuleParser,
        )

        parser = SecRuleParser(self)
        parser.parse_rule(args)

    def _handle_secaction(self, args: str) -> None:
        """Handle SecAction directive.

        Format: SecAction "ACTIONS"

        Args:
            args: Actions to execute
        """
        # SecAction is like SecRule with no variables/operator
        # It unconditionally executes actions
        # Use a dummy variable that always exists
        self._handle_secrule(f'REQUEST_URI "@unconditional" "{args}"')

    def _handle_secruleengine(self, args: str) -> None:
        """Handle SecRuleEngine directive.

        Args:
            args: Engine mode (On, Off, DetectionOnly)
        """
        mode = args.lower()
        logger.info("Setting rule engine to: %s", mode)
        # TODO: Store in WAF configuration
        # self.waf.rule_engine = mode

    def _handle_secrequestbodyaccess(self, args: str) -> None:
        """Handle SecRequestBodyAccess directive.

        Args:
            args: On or Off
        """
        enabled = args.lower() == "on"
        logger.info("Request body access: %s", enabled)
        # TODO: Store in WAF configuration

    def _handle_secresponsebodyaccess(self, args: str) -> None:
        """Handle SecResponseBodyAccess directive.

        Args:
            args: On or Off
        """
        enabled = args.lower() == "on"
        logger.info("Response body access: %s", enabled)
        # TODO: Store in WAF configuration

    def _handle_secdefaultaction(self, args: str) -> None:
        """Handle SecDefaultAction directive.

        Args:
            args: Default actions for the phase
        """
        # Parse phase from actions
        phase_match = re.search(r"phase:(\d+)", args)
        if phase_match:
            phase = int(phase_match.group(1))
            self.default_actions[phase] = args
            logger.info("Set default actions for phase %s: %s", phase, args)
        else:
            logger.warning("SecDefaultAction without phase specification: %s", args)

    def _handle_secmarker(self, args: str) -> None:
        """Handle SecMarker directive.

        SecMarker defines a named location in the rule set that can be used
        as a target for skipAfter actions. This is commonly used in CRS for
        paranoia level filtering.

        Args:
            args: Marker name (e.g., "END-REQUEST-920-PROTOCOL-ENFORCEMENT")

        Example:
            SecMarker "END-HOST-CHECK"
            SecRule TX:PARANOIA_LEVEL "@lt 2" "skipAfter:END-HOST-CHECK"
        """
        marker_name = args.strip()
        if not marker_name:
            logger.warning(
                f"SecMarker with empty name at {self.current_file}:{self.current_line}"
            )
            return

        # Create a marker "rule" - a pass-through rule with the marker name
        # This allows skipAfter to find it during rule evaluation
        from lewaf.seclang.rule_parser import (  # noqa: PLC0415 - Avoids circular import
            SecRuleParser,
        )

        # Create a dummy rule that always passes and has the marker name as a tag
        marker_rule_str = f'REQUEST_URI "@unconditional" "id:marker_{marker_name},phase:1,nolog,pass,tag:{marker_name}"'

        parser = SecRuleParser(self)
        try:
            parser.parse_rule(marker_rule_str)
        except Exception as e:
            logger.warning("Failed to create marker rule for '%s': %s", marker_name, e)

        logger.debug("Registered marker '%s' as rule", marker_name)

    def _handle_seccomponentsignature(self, args: str) -> None:
        """Handle SecComponentSignature directive.

        SecComponentSignature identifies the WAF component and version.
        This is informational only and doesn't affect rule processing.

        Args:
            args: Component signature string

        Example:
            SecComponentSignature "OWASP_CRS/3.3.4"
        """
        signature = args.strip()
        logger.info("Component signature: %s", signature)
        # Store in WAF metadata
        self.waf.component_signature = signature
