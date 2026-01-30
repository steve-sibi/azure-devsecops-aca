"""Tests for common/limits.py - configuration limits and validation."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.limits import (
    ApiLimits,
    FileScanLimits,  # noqa: E402
    ResultStoreLimits,
    ScreenshotLimits,
    WebAnalysisLimits,
    WebFetchLimits,
    _env_bool,
    _env_float,
    _env_int,
    _require_range,
)


class TestEnvHelpers:
    def test_env_bool_returns_default_when_not_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert _env_bool("UNSET_VAR", True) is True
            assert _env_bool("UNSET_VAR", False) is False

    def test_env_bool_parses_truthy_values(self):
        for val in ("1", "true", "TRUE", "yes", "YES", "y", "Y", "on", "ON"):
            with mock.patch.dict(os.environ, {"TEST_VAR": val}):
                assert _env_bool("TEST_VAR", False) is True

    def test_env_bool_parses_falsy_values(self):
        for val in ("0", "false", "FALSE", "no", "NO", "n", "N", "off", "OFF", ""):
            with mock.patch.dict(os.environ, {"TEST_VAR": val}):
                assert _env_bool("TEST_VAR", True) is False

    def test_env_int_returns_default_when_not_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert _env_int("UNSET_VAR", 42) == 42

    def test_env_int_returns_default_when_empty(self):
        with mock.patch.dict(os.environ, {"TEST_VAR": "  "}):
            assert _env_int("TEST_VAR", 42) == 42

    def test_env_int_parses_value(self):
        with mock.patch.dict(os.environ, {"TEST_VAR": "123"}):
            assert _env_int("TEST_VAR", 0) == 123

    def test_env_int_strips_whitespace(self):
        with mock.patch.dict(os.environ, {"TEST_VAR": "  456  "}):
            assert _env_int("TEST_VAR", 0) == 456

    def test_env_float_returns_default_when_not_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            assert _env_float("UNSET_VAR", 3.14) == 3.14

    def test_env_float_parses_value(self):
        with mock.patch.dict(os.environ, {"TEST_VAR": "2.5"}):
            assert _env_float("TEST_VAR", 0.0) == 2.5


class TestRequireRange:
    def test_passes_when_within_range(self):
        _require_range("TEST", 5.0, min_value=1.0, max_value=10.0)

    def test_passes_at_boundaries(self):
        _require_range("TEST", 1.0, min_value=1.0)
        _require_range("TEST", 10.0, max_value=10.0)

    def test_raises_when_below_min(self):
        with pytest.raises(RuntimeError) as exc:
            _require_range("TEST", 0.5, min_value=1.0)
        assert "TEST must be >= 1.0" in str(exc.value)

    def test_raises_when_above_max(self):
        with pytest.raises(RuntimeError) as exc:
            _require_range("TEST", 15.0, max_value=10.0)
        assert "TEST must be <= 10.0" in str(exc.value)


class TestWebFetchLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = WebFetchLimits.from_env()
            assert limits.max_download_bytes == 1024 * 1024
            assert limits.request_timeout_seconds == 10.0
            assert limits.max_redirects == 5
            assert limits.block_private_networks is True
            assert limits.max_headers == 40
            assert limits.max_header_value_len == 600

    def test_from_env_with_custom_values(self):
        with mock.patch.dict(
            os.environ,
            {
                "MAX_DOWNLOAD_BYTES": "2097152",
                "REQUEST_TIMEOUT": "30",
                "MAX_REDIRECTS": "10",
                "BLOCK_PRIVATE_NETWORKS": "false",
            },
        ):
            limits = WebFetchLimits.from_env()
            assert limits.max_download_bytes == 2097152
            assert limits.request_timeout_seconds == 30.0
            assert limits.max_redirects == 10
            assert limits.block_private_networks is False

    def test_validate_rejects_invalid_download_bytes(self):
        limits = WebFetchLimits(
            max_download_bytes=0,
            request_timeout_seconds=10.0,
            max_redirects=5,
            block_private_networks=True,
            max_headers=40,
            max_header_value_len=600,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "MAX_DOWNLOAD_BYTES" in str(exc.value)

    def test_validate_rejects_invalid_timeout(self):
        limits = WebFetchLimits(
            max_download_bytes=1024,
            request_timeout_seconds=0.05,
            max_redirects=5,
            block_private_networks=True,
            max_headers=40,
            max_header_value_len=600,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "REQUEST_TIMEOUT" in str(exc.value)


class TestWebAnalysisLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = WebAnalysisLimits.from_env()
            assert limits.max_resources == 25
            assert limits.max_inline_script_chars == 80_000
            assert limits.max_html_bytes == 300_000
            assert limits.whois_timeout_seconds == 6.0

    def test_validate_rejects_zero_resources(self):
        limits = WebAnalysisLimits(
            max_resources=0,
            max_inline_script_chars=80_000,
            max_html_bytes=300_000,
            whois_timeout_seconds=3.0,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "WEB_MAX_RESOURCES" in str(exc.value)


class TestScreenshotLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = ScreenshotLimits.from_env()
            assert limits.timeout_seconds == 12.0
            assert limits.viewport_width == 1280
            assert limits.viewport_height == 720
            assert limits.full_page is False
            assert limits.jpeg_quality == 60
            assert limits.settle_ms == 750
            assert limits.ttl_seconds == 0

    def test_from_env_with_default_ttl(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = ScreenshotLimits.from_env(default_ttl_seconds=3600)
            assert limits.ttl_seconds == 3600

    def test_validate_rejects_invalid_jpeg_quality(self):
        limits = ScreenshotLimits(
            timeout_seconds=12.0,
            viewport_width=1280,
            viewport_height=720,
            full_page=False,
            jpeg_quality=101,
            settle_ms=750,
            ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "SCREENSHOT_JPEG_QUALITY" in str(exc.value)

    def test_validate_rejects_small_viewport(self):
        limits = ScreenshotLimits(
            timeout_seconds=12.0,
            viewport_width=32,
            viewport_height=720,
            full_page=False,
            jpeg_quality=60,
            settle_ms=750,
            ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "SCREENSHOT_VIEWPORT_WIDTH" in str(exc.value)


class TestApiLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = ApiLimits.from_env()
            assert limits.rate_limit_rpm == 60
            assert limits.rate_limit_window_seconds == 60
            assert limits.max_dashboard_poll_seconds == 180


class TestFileScanLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = FileScanLimits.from_env()
            assert limits.clamav_timeout_seconds == 8.0
            assert limits.max_bytes == 10 * 1024 * 1024
            assert limits.include_version is True

    def test_validate_rejects_invalid_timeout(self):
        limits = FileScanLimits(
            clamav_timeout_seconds=0.05,
            max_bytes=1024,
            include_version=True,
        )
        with pytest.raises(RuntimeError) as exc:
            limits.validate()
        assert "CLAMAV_TIMEOUT_SECONDS" in str(exc.value)


class TestResultStoreLimits:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            limits = ResultStoreLimits.from_env()
            assert limits.details_max_bytes == 60_000

    def test_validate_accepts_zero(self):
        limits = ResultStoreLimits(details_max_bytes=0)
        limits.validate()  # Should not raise
