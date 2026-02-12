"""Tests for common/telemetry.py exporter configuration helpers."""

from __future__ import annotations

import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common import telemetry  # noqa: E402


def test_otlp_traces_endpoint_appends_default_path(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")

    assert telemetry.get_otlp_traces_endpoint() == "http://jaeger:4318/v1/traces"


def test_otlp_traces_endpoint_prefers_traces_specific_env(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")
    monkeypatch.setenv(
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "http://collector:4318/custom/path",
    )

    assert telemetry.get_otlp_traces_endpoint() == "http://collector:4318/custom/path"


def test_otlp_headers_parses_key_value_pairs(monkeypatch):
    monkeypatch.setenv(
        "OTEL_EXPORTER_OTLP_HEADERS",
        "Authorization=Bearer token123,  X-Test = abc  , malformed",
    )

    assert telemetry.get_otlp_headers() == {
        "Authorization": "Bearer token123",
        "X-Test": "abc",
    }


def test_telemetry_enabled_auto_from_otlp_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_ENABLED", raising=False)
    monkeypatch.delenv("APPINSIGHTS_CONN", raising=False)
    monkeypatch.delenv("APPLICATIONINSIGHTS_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")

    assert telemetry.telemetry_enabled_from_env() is True


def test_telemetry_explicit_false_overrides_auto(monkeypatch):
    monkeypatch.setenv("OTEL_ENABLED", "false")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4318")

    assert telemetry.telemetry_enabled_from_env() is False
