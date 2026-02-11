"""
Structured logging configuration for JSON-formatted logs.
Compatible with Azure Monitor, Application Insights, and Log Analytics.
Supports pretty format for local development.
"""

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

from common.telemetry import get_current_trace_fields

# Context variable for correlation ID (request tracing)
correlation_id_var: ContextVar[Optional[str]] = ContextVar(
    "correlation_id", default=None
)

# Log format: "json" for production, "pretty" for local dev
LOG_FORMAT = os.getenv("LOG_FORMAT", "json").strip().lower()


class JSONFormatter(logging.Formatter):
    """
    Custom formatter that outputs logs as JSON.
    Fields are automatically indexed by Azure Monitor and Application Insights.
    """

    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        log_data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "service": self.service_name,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add correlation ID if present
        correlation_id = correlation_id_var.get()
        if correlation_id:
            log_data["correlation_id"] = correlation_id

        # Add active trace/span IDs when OpenTelemetry context is available.
        trace_fields = get_current_trace_fields()
        if trace_fields:
            log_data.update(trace_fields)

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields from LoggerAdapter or extra kwargs
        extra_fields = getattr(record, "extra_fields", None)
        if extra_fields:
            log_data.update(extra_fields)

        # Common fields that might be in the record
        for field in [
            "job_id",
            "url",
            "scan_id",
            "duration_ms",
            "size_bytes",
            "status_code",
        ]:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)

        return json.dumps(log_data)


class PrettyFormatter(logging.Formatter):
    """
    Human-readable formatter for local development.
    Easier to scan visually than JSON.
    """

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"
    DIM = "\033[2m"

    def __init__(self, service_name: str):
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        # Timestamp (local time, shorter format)
        timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")

        # Level with color
        color = self.COLORS.get(record.levelname, "")
        level = f"{color}{record.levelname:<7}{self.RESET}"

        # Service name
        service = f"{self.DIM}{self.service_name}{self.RESET}"

        # Base message
        message = record.getMessage()

        # Build context string from extra fields
        context_parts = []

        # Add correlation ID if present (shortened)
        correlation_id = correlation_id_var.get()
        if correlation_id:
            short_id = correlation_id[:8]
            context_parts.append(f"id={short_id}")

        trace_fields = get_current_trace_fields()
        if trace_fields.get("trace_id"):
            context_parts.append(f"trace={trace_fields['trace_id'][:8]}")

        # Add extra fields
        extra_fields = getattr(record, "extra_fields", None)
        if extra_fields:
            for key, value in extra_fields.items():
                if key == "correlation_id":
                    continue  # Already handled
                if key == "url" and isinstance(value, str):
                    # Shorten URLs
                    from urllib.parse import urlparse

                    try:
                        parsed = urlparse(value)
                        value = parsed.netloc or value
                    except Exception:
                        pass
                if key == "job_id" and isinstance(value, str) and len(value) > 8:
                    value = value[:8]
                if key == "duration_ms":
                    value = f"{value}ms"
                if key == "size_bytes":
                    value = f"{value}B"
                context_parts.append(f"{key}={value}")

        # Format final output
        context = (
            f" {self.DIM}[{', '.join(context_parts)}]{self.RESET}"
            if context_parts
            else ""
        )
        output = f"{timestamp} {level} {service} │ {message}{context}"

        # Add exception if present
        if record.exc_info:
            output += f"\n{self.formatException(record.exc_info)}"

        return output


def setup_logging(service_name: str, level: int = logging.INFO) -> None:
    """
    Configure structured logging for a service.

    Uses LOG_FORMAT env var to determine format:
    - "json" (default): JSON format for Azure Monitor/production
    - "pretty": Human-readable format for local development

    Args:
        service_name: Name of the service (e.g., 'api', 'worker', 'clamav')
        level: Logging level (default: INFO)
    """
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Choose formatter based on LOG_FORMAT env var
    if LOG_FORMAT == "pretty":
        formatter = PrettyFormatter(service_name)
    else:
        formatter = JSONFormatter(service_name)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)

    # Configure uvicorn loggers to use same format
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        logger = logging.getLogger(logger_name)
        logger.handlers = []
        logger.addHandler(console_handler)
        logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance configured with JSON formatting
    """
    return logging.getLogger(name)


def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for request tracing."""
    correlation_id_var.set(correlation_id)


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID."""
    return correlation_id_var.get()


def clear_correlation_id() -> None:
    """Clear correlation ID."""
    correlation_id_var.set(None)


def log_with_context(
    logger: logging.Logger, level: int, message: str, **kwargs
) -> None:
    """
    Log a message with additional context fields.

    Args:
        logger: Logger instance
        level: Log level (e.g., logging.INFO)
        message: Log message
        **kwargs: Additional fields to include in JSON output
    """
    extra = {"extra_fields": kwargs}
    logger.log(level, message, extra=extra)
