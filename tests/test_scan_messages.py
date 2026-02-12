"""Tests for common/scan_messages.py - message schema validation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.scan_messages import (
    ScanMessageValidationError,  # noqa: E402
    normalize_metadata,
    validate_scan_artifact_v1,
    validate_scan_task_v1,
)


class TestScanMessageValidationError:
    def test_str_with_field(self):
        err = ScanMessageValidationError(field="url", message="is required")
        assert str(err) == "url: is required"

    def test_str_without_field(self):
        err = ScanMessageValidationError(field="", message="payload must be an object")
        assert str(err) == "payload must be an object"


class TestNormalizeMetadata:
    def test_none_returns_empty_dict(self):
        assert normalize_metadata(None) == {}

    def test_empty_dict_returns_empty_dict(self):
        assert normalize_metadata({}) == {}

    def test_valid_metadata(self):
        meta = {"key1": "value1", "key2": 123, "key3": True, "key4": None}
        result = normalize_metadata(meta)
        assert result == {"key1": "value1", "key2": 123, "key3": True, "key4": None}

    def test_strips_string_values(self):
        meta = {"key": "  value  "}
        result = normalize_metadata(meta)
        assert result["key"] == "value"

    def test_rejects_non_dict(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            normalize_metadata("not a dict")
        assert "must be an object" in str(exc.value)

    def test_rejects_non_string_keys(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            normalize_metadata({123: "value"})
        assert "keys must be strings" in str(exc.value)

    def test_rejects_empty_keys(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            normalize_metadata({"  ": "value"})
        assert "keys cannot be empty" in str(exc.value)

    def test_rejects_list_values(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            normalize_metadata({"key": [1, 2, 3]})
        assert "must be a string, number, boolean, or null" in str(exc.value)

    def test_rejects_nested_dict_values(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            normalize_metadata({"key": {"nested": "value"}})
        assert "must be a string, number, boolean, or null" in str(exc.value)


class TestValidateScanTaskV1:
    def test_valid_minimal_payload(self):
        payload = {"job_id": "abc123", "url": "https://example.com"}
        result = validate_scan_task_v1(payload)
        assert result["job_id"] == "abc123"
        assert result["url"] == "https://example.com"
        assert result["type"] == "url"
        assert result["metadata"] == {}

    def test_valid_full_payload(self):
        payload = {
            "job_id": "abc123",
            "request_id": "req-123",
            "run_id": "run-123",
            "url": "https://example.com",
            "type": "url",
            "correlation_id": "corr-456",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "tracestate": "congo=t61rcWkgMzE",
            "source": "api",
            "submitted_at": "2025-01-21T12:00:00Z",
            "visibility": "shared",
            "metadata": {"client": "test"},
        }
        result = validate_scan_task_v1(payload)
        assert result["job_id"] == "abc123"
        assert result["request_id"] == "req-123"
        assert result["run_id"] == "run-123"
        assert result["correlation_id"] == "corr-456"
        assert result["traceparent"] == payload["traceparent"]
        assert result["tracestate"] == payload["tracestate"]
        assert result["source"] == "api"
        assert result["metadata"] == {"client": "test"}
        assert result["visibility"] == "shared"

    def test_traceparent_is_normalized_to_lowercase(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "traceparent": "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01",
        }
        result = validate_scan_task_v1(payload)
        assert (
            result["traceparent"]
            == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        )

    def test_rejects_invalid_traceparent(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "traceparent": "not-a-traceparent",
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1(payload)
        assert "traceparent" in str(exc.value)
        assert "W3C traceparent" in str(exc.value)

    def test_type_file_is_valid(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com/file.pdf",
            "type": "file",
        }
        result = validate_scan_task_v1(payload)
        assert result["type"] == "file"

    def test_type_is_lowercased(self):
        payload = {"job_id": "abc123", "url": "https://example.com", "type": "URL"}
        result = validate_scan_task_v1(payload)
        assert result["type"] == "url"

    def test_visibility_is_lowercased(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "visibility": "PrIvAtE",
        }
        result = validate_scan_task_v1(payload)
        assert result["visibility"] == "private"

    def test_rejects_invalid_visibility(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "visibility": "public",
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1(payload)
        assert "visibility" in str(exc.value)
        assert "'shared' or 'private'" in str(exc.value)

    def test_rejects_non_dict_payload(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1("not a dict")
        assert "payload must be an object" in str(exc.value)

    def test_rejects_missing_job_id(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1({"url": "https://example.com"})
        assert "job_id" in str(exc.value)
        assert "is required" in str(exc.value)

    def test_rejects_missing_url(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1({"job_id": "abc123"})
        assert "url" in str(exc.value)
        assert "is required" in str(exc.value)

    def test_rejects_empty_job_id(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1({"job_id": "  ", "url": "https://example.com"})
        assert "job_id" in str(exc.value)
        assert "cannot be empty" in str(exc.value)

    def test_rejects_invalid_type(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1(
                {"job_id": "abc", "url": "https://example.com", "type": "invalid"}
            )
        assert "type" in str(exc.value)
        assert "'url' or 'file'" in str(exc.value)

    def test_rejects_non_string_job_id(self):
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_task_v1({"job_id": 123, "url": "https://example.com"})
        assert "job_id" in str(exc.value)
        assert "must be a string" in str(exc.value)

    def test_strips_whitespace(self):
        payload = {"job_id": "  abc123  ", "url": "  https://example.com  "}
        result = validate_scan_task_v1(payload)
        assert result["job_id"] == "abc123"
        assert result["url"] == "https://example.com"


class TestValidateScanArtifactV1:
    def test_extends_scan_task_v1(self):
        payload = {"job_id": "abc123", "url": "https://example.com"}
        result = validate_scan_artifact_v1(payload)
        assert result["job_id"] == "abc123"
        assert result["url"] == "https://example.com"

    def test_valid_artifact_fields(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "artifact_path": "abc123.bin",
            "artifact_sha256": "abcdef1234567890",
            "artifact_size_bytes": 1024,
        }
        result = validate_scan_artifact_v1(payload)
        assert result["artifact_path"] == "abc123.bin"
        assert result["artifact_sha256"] == "abcdef1234567890"
        assert result["artifact_size_bytes"] == 1024

    def test_valid_download_field(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "download": {"status_code": 200, "content_type": "text/html"},
        }
        result = validate_scan_artifact_v1(payload)
        assert result["download"] == {"status_code": 200, "content_type": "text/html"}

    def test_rejects_non_dict_download(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "download": "not a dict",
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_artifact_v1(payload)
        assert "download" in str(exc.value)
        assert "must be an object" in str(exc.value)

    def test_rejects_negative_artifact_size(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "artifact_size_bytes": -1,
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_artifact_v1(payload)
        assert "artifact_size_bytes" in str(exc.value)
        assert ">= 0" in str(exc.value)

    def test_rejects_bool_artifact_size(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "artifact_size_bytes": True,
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_artifact_v1(payload)
        assert "artifact_size_bytes" in str(exc.value)
        assert "must be an integer" in str(exc.value)

    def test_rejects_non_integer_artifact_size(self):
        payload = {
            "job_id": "abc123",
            "url": "https://example.com",
            "artifact_size_bytes": "not a number",
        }
        with pytest.raises(ScanMessageValidationError) as exc:
            validate_scan_artifact_v1(payload)
        assert "artifact_size_bytes" in str(exc.value)

    def test_trace_fields_are_preserved_in_artifact_payload(self):
        payload = {
            "job_id": "abc123",
            "request_id": "req-123",
            "run_id": "run-123",
            "url": "https://example.com",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "tracestate": "congo=t61rcWkgMzE",
            "artifact_path": "abc123.bin",
            "artifact_size_bytes": 12,
        }
        result = validate_scan_artifact_v1(payload)
        assert result["request_id"] == payload["request_id"]
        assert result["run_id"] == payload["run_id"]
        assert result["traceparent"] == payload["traceparent"]
        assert result["tracestate"] == payload["tracestate"]
