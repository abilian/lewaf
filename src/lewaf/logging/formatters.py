"""JSON formatters for structured logging."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, cast


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""

    def __init__(
        self,
        include_timestamp: bool = True,
        additional_fields: dict[str, Any] | None = None,
    ):
        """Initialize JSON formatter.

        Args:
            include_timestamp: Whether to include timestamp
            additional_fields: Additional fields to include in every log
        """
        super().__init__()
        self.include_timestamp = include_timestamp
        self.additional_fields = additional_fields or {}

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON.

        Args:
            record: Log record to format

        Returns:
            JSON string
        """
        log_data: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add timestamp
        if self.include_timestamp:
            log_data["timestamp"] = (
                time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                + f".{int(record.msecs):03d}Z"
            )

        # Add additional fields
        log_data.update(self.additional_fields)

        # Add all custom fields from record (from extra parameter)
        # Skip standard logging attributes
        skip_attrs = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "message",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "thread",
            "threadName",
            "exc_info",
            "exc_text",
            "taskName",
        }

        log_data.update({
            key: value
            for key, value in record.__dict__.items()
            if key not in skip_attrs and not key.startswith("_")
        })

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


class CompactJSONFormatter(JSONFormatter):
    """Compact JSON formatter with minimal fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as compact JSON.

        Args:
            record: Log record to format

        Returns:
            Compact JSON string
        """
        log_data: dict[str, Any] = {
            "ts": int(record.created * 1000),  # Milliseconds timestamp
            "lvl": record.levelname[0],  # First letter (D/I/W/E/C)
            "msg": record.getMessage(),
        }

        # Add only critical custom fields
        if hasattr(record, "transaction_id"):
            log_data["tx"] = record.transaction_id

        if hasattr(record, "event_type"):
            log_data["evt"] = record.event_type

        if hasattr(record, "rule"):
            rule = record.rule
            if isinstance(rule, dict) and "id" in rule:
                log_data["rule"] = cast("dict[str, Any]", rule)["id"]

        return json.dumps(log_data)
