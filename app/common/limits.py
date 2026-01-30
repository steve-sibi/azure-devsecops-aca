from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return int(str(raw).strip())


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return float(str(raw).strip())


def _require_range(
    name: str,
    value: float,
    *,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
) -> None:
    if min_value is not None and value < min_value:
        raise RuntimeError(f"{name} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise RuntimeError(f"{name} must be <= {max_value}")


@dataclass(frozen=True)
class WebFetchLimits:
    max_download_bytes: int
    request_timeout_seconds: float
    max_redirects: int
    block_private_networks: bool
    max_headers: int
    max_header_value_len: int

    @staticmethod
    def from_env() -> WebFetchLimits:
        limits = WebFetchLimits(
            max_download_bytes=_env_int("MAX_DOWNLOAD_BYTES", 1024 * 1024),  # 1MB
            request_timeout_seconds=_env_float("REQUEST_TIMEOUT", 10.0),
            max_redirects=_env_int("MAX_REDIRECTS", 5),
            block_private_networks=_env_bool("BLOCK_PRIVATE_NETWORKS", True),
            max_headers=_env_int("WEB_MAX_HEADERS", 40),
            max_header_value_len=_env_int("WEB_MAX_HEADER_VALUE_LEN", 600),
        )
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("MAX_DOWNLOAD_BYTES", float(self.max_download_bytes), min_value=1)
        _require_range("REQUEST_TIMEOUT", float(self.request_timeout_seconds), min_value=0.1)
        _require_range("MAX_REDIRECTS", float(self.max_redirects), min_value=0)
        _require_range("WEB_MAX_HEADERS", float(self.max_headers), min_value=1)
        _require_range(
            "WEB_MAX_HEADER_VALUE_LEN", float(self.max_header_value_len), min_value=0
        )


@dataclass(frozen=True)
class WebAnalysisLimits:
    max_resources: int
    max_inline_script_chars: int
    max_html_bytes: int
    whois_timeout_seconds: float

    @staticmethod
    def from_env() -> WebAnalysisLimits:
        limits = WebAnalysisLimits(
            max_resources=_env_int("WEB_MAX_RESOURCES", 25),
            max_inline_script_chars=_env_int("WEB_MAX_INLINE_SCRIPT_CHARS", 80_000),
            max_html_bytes=_env_int("WEB_MAX_HTML_BYTES", 300_000),
            whois_timeout_seconds=_env_float("WEB_WHOIS_TIMEOUT_SECONDS", 6.0),
        )
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("WEB_MAX_RESOURCES", float(self.max_resources), min_value=1)
        _require_range(
            "WEB_MAX_INLINE_SCRIPT_CHARS",
            float(self.max_inline_script_chars),
            min_value=1,
        )
        _require_range("WEB_MAX_HTML_BYTES", float(self.max_html_bytes), min_value=0)
        _require_range(
            "WEB_WHOIS_TIMEOUT_SECONDS", float(self.whois_timeout_seconds), min_value=0.1
        )


@dataclass(frozen=True)
class ScreenshotLimits:
    timeout_seconds: float
    viewport_width: int
    viewport_height: int
    full_page: bool
    jpeg_quality: int
    settle_ms: int
    ttl_seconds: int

    @staticmethod
    def from_env(*, default_ttl_seconds: int = 0) -> ScreenshotLimits:
        limits = ScreenshotLimits(
            timeout_seconds=_env_float("SCREENSHOT_TIMEOUT_SECONDS", 12.0),
            viewport_width=_env_int("SCREENSHOT_VIEWPORT_WIDTH", 1280),
            viewport_height=_env_int("SCREENSHOT_VIEWPORT_HEIGHT", 720),
            full_page=_env_bool("SCREENSHOT_FULL_PAGE", False),
            jpeg_quality=_env_int("SCREENSHOT_JPEG_QUALITY", 60),
            settle_ms=_env_int("SCREENSHOT_SETTLE_MS", 750),
            ttl_seconds=_env_int("SCREENSHOT_TTL_SECONDS", int(default_ttl_seconds or 0)),
        )
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("SCREENSHOT_TIMEOUT_SECONDS", float(self.timeout_seconds), min_value=0.1)
        _require_range("SCREENSHOT_VIEWPORT_WIDTH", float(self.viewport_width), min_value=64)
        _require_range("SCREENSHOT_VIEWPORT_HEIGHT", float(self.viewport_height), min_value=64)
        _require_range("SCREENSHOT_JPEG_QUALITY", float(self.jpeg_quality), min_value=1, max_value=100)
        _require_range("SCREENSHOT_SETTLE_MS", float(self.settle_ms), min_value=0)
        _require_range("SCREENSHOT_TTL_SECONDS", float(self.ttl_seconds), min_value=0)


@dataclass(frozen=True)
class ApiLimits:
    rate_limit_rpm: int
    rate_limit_window_seconds: int
    max_dashboard_poll_seconds: int

    @staticmethod
    def from_env() -> ApiLimits:
        limits = ApiLimits(
            rate_limit_rpm=_env_int("RATE_LIMIT_RPM", 60),
            rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 60),
            max_dashboard_poll_seconds=_env_int("MAX_DASHBOARD_POLL_SECONDS", 180),
        )
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("RATE_LIMIT_RPM", float(self.rate_limit_rpm), min_value=0)
        _require_range(
            "RATE_LIMIT_WINDOW_SECONDS", float(self.rate_limit_window_seconds), min_value=0
        )
        _require_range(
            "MAX_DASHBOARD_POLL_SECONDS", float(self.max_dashboard_poll_seconds), min_value=0
        )


@dataclass(frozen=True)
class FileScanLimits:
    clamav_timeout_seconds: float
    max_bytes: int
    include_version: bool

    @staticmethod
    def from_env() -> FileScanLimits:
        limits = FileScanLimits(
            clamav_timeout_seconds=_env_float("CLAMAV_TIMEOUT_SECONDS", 8.0),
            max_bytes=_env_int("FILE_SCAN_MAX_BYTES", 10 * 1024 * 1024),  # 10MB
            include_version=_env_bool("FILE_SCAN_INCLUDE_VERSION", True),
        )
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("CLAMAV_TIMEOUT_SECONDS", float(self.clamav_timeout_seconds), min_value=0.1)
        _require_range("FILE_SCAN_MAX_BYTES", float(self.max_bytes), min_value=1)


@dataclass(frozen=True)
class ResultStoreLimits:
    details_max_bytes: int

    @staticmethod
    def from_env() -> ResultStoreLimits:
        limits = ResultStoreLimits(details_max_bytes=_env_int("RESULT_DETAILS_MAX_BYTES", 60_000))
        limits.validate()
        return limits

    def validate(self) -> None:
        _require_range("RESULT_DETAILS_MAX_BYTES", float(self.details_max_bytes), min_value=0)


@lru_cache(maxsize=1)
def get_web_fetch_limits() -> WebFetchLimits:
    return WebFetchLimits.from_env()


@lru_cache(maxsize=1)
def get_web_analysis_limits() -> WebAnalysisLimits:
    return WebAnalysisLimits.from_env()


@lru_cache(maxsize=1)
def get_api_limits() -> ApiLimits:
    return ApiLimits.from_env()


@lru_cache(maxsize=1)
def get_file_scan_limits() -> FileScanLimits:
    return FileScanLimits.from_env()


@lru_cache(maxsize=1)
def get_result_store_limits() -> ResultStoreLimits:
    return ResultStoreLimits.from_env()
