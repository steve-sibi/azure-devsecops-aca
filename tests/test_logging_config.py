"""Tests for common/logging_config.py structured output."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.logging_config import (  # noqa: E402
    JSONFormatter,
    clear_correlation_id,
    log_with_context,
    set_correlation_id,
)


def _record_with_extra() -> logging.LogRecord:
    logger = logging.getLogger("test.logger")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers = []
    log_with_context(
        logger,
        logging.INFO,
        "test message",
        job_id="job-123",
        duration_ms=17,
    )
    # Build a record equivalent to log_with_context output for formatter assertions.
    return logger.makeRecord(
        name="test.logger",
        level=logging.INFO,
        fn="test_logging_config.py",
        lno=1,
        msg="test message",
        args=(),
        exc_info=None,
        extra={"extra_fields": {"job_id": "job-123", "duration_ms": 17}},
    )


def test_json_formatter_includes_correlation_and_trace(monkeypatch):
    from common import logging_config

    monkeypatch.setattr(
        logging_config,
        "get_current_trace_fields",
        lambda: {"trace_id": "a" * 32, "span_id": "b" * 16},
    )
    set_correlation_id("corr-123")
    try:
        formatter = JSONFormatter(service_name="api")
        record = _record_with_extra()
        payload = json.loads(formatter.format(record))
    finally:
        clear_correlation_id()

    assert payload["service"] == "api"
    assert payload["message"] == "test message"
    assert payload["correlation_id"] == "corr-123"
    assert payload["trace_id"] == "a" * 32
    assert payload["span_id"] == "b" * 16
    assert payload["job_id"] == "job-123"
    assert payload["duration_ms"] == 17


def test_json_formatter_omits_trace_when_unavailable(monkeypatch):
    from common import logging_config

    monkeypatch.setattr(logging_config, "get_current_trace_fields", lambda: {})
    set_correlation_id("corr-xyz")
    try:
        formatter = JSONFormatter(service_name="worker")
        record = _record_with_extra()
        payload = json.loads(formatter.format(record))
    finally:
        clear_correlation_id()

    assert payload["service"] == "worker"
    assert payload["correlation_id"] == "corr-xyz"
    assert "trace_id" not in payload
    assert "span_id" not in payload
