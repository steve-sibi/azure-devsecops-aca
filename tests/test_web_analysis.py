from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.web_analysis import (  # noqa: E402
    analyze_html,
    classify_internal_external,
    parse_set_cookie_headers,
)


def test_parse_set_cookie_headers_flags_missing_secure():
    cookies = parse_set_cookie_headers(["SID=abc; Path=/; HttpOnly"])
    assert cookies and cookies[0]["name"] == "SID"
    assert "issues" in cookies[0]
    assert "Missing Secure" in cookies[0]["issues"]


def test_parse_set_cookie_headers_no_issue_when_secure_present():
    cookies = parse_set_cookie_headers(["SID=abc; Path=/; Secure; HttpOnly"])
    assert cookies and cookies[0]["name"] == "SID"
    assert "issues" not in cookies[0]


def test_analyze_html_suspicious_api_calls_when_external_absolute_url():
    parsed = analyze_html(
        "<html><head><script>fetch('https://evil.example/x');</script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.suspicious_api_calls is True


def test_analyze_html_not_suspicious_api_calls_for_same_host_absolute_url():
    parsed = analyze_html(
        "<html><head><script>fetch('https://example.com/api');</script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.suspicious_api_calls is False


def test_analyze_html_not_suspicious_api_calls_for_relative_url():
    parsed = analyze_html(
        "<html><head><script>fetch('/api');</script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.suspicious_api_calls is False


def test_analyze_html_suspicious_api_calls_for_external_websocket_url():
    parsed = analyze_html(
        "<html><head><script>new WebSocket('wss://evil.example/ws');</script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.suspicious_api_calls is True


def test_classify_internal_external_treats_subdomain_as_internal():
    assert (
        classify_internal_external(
            resource_url="https://cdn.example.com/app.js", page_host="example.com"
        )
        == "internal"
    )


def test_analyze_html_tracking_detected_for_google_analytics_script():
    pytest.importorskip("adblockparser")
    parsed = analyze_html(
        "<html><head><script src='https://www.google-analytics.com/analytics.js'></script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.tracking_scripts is True


def test_analyze_html_yara_detects_suspicious_js_and_eval_usage():
    pytest.importorskip("yara")
    parsed = analyze_html(
        "<html><head><script>var x = atob('aGVsbG8='); eval(x);</script></head></html>",
        base_url="https://example.com/",
    )
    assert parsed.suspicious_scripts >= 1
    assert parsed.eval_usage is True
