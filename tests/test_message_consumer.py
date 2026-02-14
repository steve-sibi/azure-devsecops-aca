"""Tests for common/message_consumer.py - message decoding and shutdown handling."""

from __future__ import annotations

import json
import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.message_consumer import (  # noqa: E402
    ShutdownFlag,
    decode_redis_body,
    decode_servicebus_body,
    install_signal_handlers,
)


class TestShutdownFlag:
    def test_default_is_false(self):
        flag = ShutdownFlag()
        assert flag.shutdown is False

    def test_can_be_set_to_true(self):
        flag = ShutdownFlag()
        flag.shutdown = True
        assert flag.shutdown is True


class TestInstallSignalHandlers:
    def test_sets_shutdown_on_signal(self):
        import signal

        flag = ShutdownFlag()
        install_signal_handlers(flag)

        # Get the handler and call it directly
        handler = signal.getsignal(signal.SIGTERM)
        handler(signal.SIGTERM, None)

        assert flag.shutdown is True


class TestDecodeServicebusBody:
    def test_decodes_bytes_body(self):
        class FakeMessage:
            body = [b'{"job_id": "abc123", "url": "https://example.com"}']

        result = decode_servicebus_body(FakeMessage())
        assert result == {"job_id": "abc123", "url": "https://example.com"}

    def test_decodes_memoryview_body(self):
        data = b'{"job_id": "test", "url": "https://test.com"}'

        class FakeMessage:
            body = [memoryview(data)]

        result = decode_servicebus_body(FakeMessage())
        assert result == {"job_id": "test", "url": "https://test.com"}

    def test_decodes_chunked_body(self):
        class FakeMessage:
            body = [b'{"job_id":', b' "chunked",', b' "url": "https://example.com"}']

        result = decode_servicebus_body(FakeMessage())
        assert result == {"job_id": "chunked", "url": "https://example.com"}


class TestDecodeRedisBody:
    def test_decodes_envelope_format(self):
        envelope = {
            "schema": "scan-task-v1",
            "delivery_count": 2,
            "payload": {"job_id": "abc123", "url": "https://example.com"},
        }
        raw = json.dumps(envelope)

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task == {"job_id": "abc123", "url": "https://example.com"}
        assert env == envelope
        assert delivery_count == 2
        assert error is None

    def test_decodes_bare_dict_format(self):
        raw = json.dumps({"job_id": "abc123", "url": "https://example.com"})

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task == {"job_id": "abc123", "url": "https://example.com"}
        assert env is not None
        assert env["payload"] == task
        assert delivery_count == 1
        assert error is None

    def test_returns_error_for_invalid_json(self):
        raw = "not valid json"

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task is None
        assert env is None
        assert delivery_count == 1
        assert error is not None

    def test_returns_error_for_non_object(self):
        raw = json.dumps([1, 2, 3])

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task is None
        assert env is None
        assert delivery_count == 1
        assert isinstance(error, ValueError)
        assert "expected JSON object" in str(error)

    def test_handles_missing_delivery_count(self):
        envelope = {
            "schema": "scan-task-v1",
            "payload": {"job_id": "abc123", "url": "https://example.com"},
        }
        raw = json.dumps(envelope)

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task == {"job_id": "abc123", "url": "https://example.com"}
        assert delivery_count == 1
        assert error is None

    def test_handles_non_integer_delivery_count(self):
        envelope = {
            "schema": "scan-task-v1",
            "delivery_count": "not a number",
            "payload": {"job_id": "abc123", "url": "https://example.com"},
        }
        raw = json.dumps(envelope)

        task, env, delivery_count, error = decode_redis_body(raw)

        assert task == {"job_id": "abc123", "url": "https://example.com"}
        assert delivery_count == 1
        assert error is not None  # Conversion error
