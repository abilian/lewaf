"""SecLang parser for loading ModSecurity .conf rule files.

This module provides functionality to parse ModSecurity/Coraza SecLang configuration
files and convert them into LeWAF Rule objects.

Key components:
- SecLangParser: Main parser class for .conf files
- SecRuleParser: Parser for SecRule directives
- DirectiveHandler: Handlers for various SecLang directives
"""

from __future__ import annotations

__all__ = ["ParseError", "SecLangParser"]

from lewaf.seclang.parser import ParseError, SecLangParser
