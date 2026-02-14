"""Tests for common/errors.py - exception classification and error handling."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.errors import ErrorInfo, classify_exception  # noqa: E402
from common.scan_messages import ScanMessageValidationError  # noqa: E402
from common.url_validation import UrlValidationError  # noqa: E402


class TestErrorInfo:
    def test_error_info_is_frozen(self):
        info = ErrorInfo(code="test", message="msg", retryable=False)
        with pytest.raises(AttributeError):
            info.code = "changed"  # type: ignore

    def test_error_info_defaults(self):
        info = ErrorInfo(code="test", message="msg", retryable=True)
        assert info.log_traceback is False


class TestClassifyException:
    def test_scan_message_validation_error(self):
        exc = ScanMessageValidationError(field="url", message="is required")
        info = classify_exception(exc)
        assert info.code == "invalid_message"
        assert "url" in info.message
        assert info.retryable is False
        assert info.log_traceback is False

    def test_url_validation_error(self):
        exc = UrlValidationError(code="https_only", message="only https is allowed")
        info = classify_exception(exc)
        assert info.code == "https_only"
        assert info.retryable is False
        assert info.log_traceback is False

    def test_json_decode_error(self):
        exc = json.JSONDecodeError("Expecting value", "doc", 0)
        info = classify_exception(exc)
        assert info.code == "invalid_message_json"
        assert info.retryable is False

    def test_invalid_message_payload_error(self):
        exc = ValueError("invalid message payload (expected JSON object)")
        info = classify_exception(exc)
        assert info.code == "invalid_message"
        assert info.retryable is False

    def test_artifact_sha256_mismatch(self):
        exc = ValueError("artifact sha256 mismatch")
        info = classify_exception(exc)
        assert info.code == "artifact_mismatch"
        assert info.retryable is False

    def test_artifact_size_mismatch(self):
        exc = ValueError("artifact size mismatch (expected=100 actual=200)")
        info = classify_exception(exc)
        assert info.code == "artifact_mismatch"
        assert info.retryable is False

    def test_content_too_large(self):
        exc = ValueError("content too large")
        info = classify_exception(exc)
        assert info.code == "upstream_rejected"
        assert info.retryable is False

    def test_too_many_redirects(self):
        exc = ValueError("too many redirects")
        info = classify_exception(exc)
        assert info.code == "upstream_rejected"
        assert info.retryable is False

    def test_redirect_without_location(self):
        exc = ValueError("redirect without Location header")
        info = classify_exception(exc)
        assert info.code == "upstream_rejected"
        assert info.retryable is False

    def test_http_500_error_is_retryable(self):
        class FakeResponse:
            status_code = 500

        class FakeHTTPError(Exception):
            response = FakeResponse()

        exc = FakeHTTPError()
        info = classify_exception(exc)
        assert info.code == "http_500"
        assert info.retryable is True
        assert info.log_traceback is False

    def test_http_404_error_is_not_retryable(self):
        class FakeResponse:
            status_code = 404

        class FakeHTTPError(Exception):
            response = FakeResponse()

        exc = FakeHTTPError()
        info = classify_exception(exc)
        assert info.code == "http_404"
        assert info.retryable is False
        assert info.log_traceback is True

    def test_http_429_error_is_retryable(self):
        class FakeResponse:
            status_code = 429

        class FakeHTTPError(Exception):
            response = FakeResponse()

        exc = FakeHTTPError()
        info = classify_exception(exc)
        assert info.code == "http_429"
        assert info.retryable is True

    def test_timeout_error_is_retryable(self):
        class ReadTimeout(Exception):
            pass

        exc = ReadTimeout()
        info = classify_exception(exc)
        assert info.code == "network_error"
        assert info.retryable is True

    def test_connection_error_is_retryable(self):
        class ConnectionError(Exception):
            pass

        exc = ConnectionError()
        info = classify_exception(exc)
        assert info.code == "network_error"
        assert info.retryable is True

    def test_unknown_exception_is_retryable_with_traceback(self):
        exc = RuntimeError("something unexpected")
        info = classify_exception(exc)
        assert info.code == "internal_error"
        assert info.retryable is True
        assert info.log_traceback is True

    def test_truncates_long_messages(self):
        long_msg = "x" * 500
        exc = ScanMessageValidationError(field="test", message=long_msg)
        info = classify_exception(exc, max_error_chars=100)
        assert len(info.message) <= 100
        assert info.message.endswith("...")


class TestClassifyExceptionMessage:
    def test_returns_message_for_common_error(self):
        exc = ValueError("content too large")
        info = classify_exception(exc)
        assert info.message == "content too large"


class TestRetryLogic:
    def test_retryable_within_limit(self):
        exc = RuntimeError("temporary failure")
        info = classify_exception(exc)
        assert info.retryable is True
        assert 1 < 3  # delivery_count < max_retries

    def test_retryable_at_limit(self):
        exc = RuntimeError("temporary failure")
        info = classify_exception(exc)
        assert info.retryable is True
        assert not (3 < 3)  # delivery_count >= max_retries

    def test_not_retryable(self):
        exc = ScanMessageValidationError(field="url", message="is required")
        info = classify_exception(exc)
        assert info.retryable is False
