from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException
from starlette.requests import Request

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
API_ROOT = APP_ROOT / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

import main as api  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _request(path: str, method: str) -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "root_path": "",
    }
    return Request(scope)


@pytest.mark.parametrize("require_api_key", [False, True])
def test_admin_auth_required_for_admin_scope_in_all_modes(monkeypatch, require_api_key):
    monkeypatch.setattr(api, "REQUIRE_API_KEY", require_api_key)
    monkeypatch.setattr(api, "API_KEY", "user-key")
    monkeypatch.setattr(api, "API_KEYS", "")
    monkeypatch.setattr(api, "API_ADMIN_KEY", "admin-key")
    monkeypatch.setattr(api, "API_ADMIN_KEYS", "")
    monkeypatch.setattr(api, "API_KEY_STORE_ENABLED", False)
    monkeypatch.setattr(api, "table_client", None)
    monkeypatch.setattr(api, "redis_client", None)
    api._rate_buckets.clear()

    req = _request("/admin/api-keys", "GET")

    with pytest.raises(HTTPException) as missing:
        _run(api.require_admin_api_key(req, None))
    assert missing.value.status_code == 401

    with pytest.raises(HTTPException) as non_admin:
        _run(api.require_admin_api_key(req, "user-key"))
    assert non_admin.value.status_code == 403

    admin_hash = _run(api.require_admin_api_key(req, "admin-key"))
    assert isinstance(admin_hash, str)
    assert len(admin_hash) == 64


def test_non_admin_auth_can_still_be_disabled(monkeypatch):
    monkeypatch.setattr(api, "REQUIRE_API_KEY", False)
    api._rate_buckets.clear()
    req = _request("/scan", "POST")
    assert _run(api.require_api_key(req, None)) is None


def test_list_jobs_still_requires_key_when_auth_toggle_disabled(monkeypatch):
    monkeypatch.setattr(api, "REQUIRE_API_KEY", False)
    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)

    with pytest.raises(HTTPException) as exc:
        _run(
            api.list_jobs(
                _request("/jobs", "GET"),
                limit=10,
                scan_type=None,
                status=None,
                api_key_hash=None,
            )
        )
    assert exc.value.status_code == 401
    assert "Missing API key" in str(exc.value.detail)


def test_clear_jobs_still_requires_key_when_auth_toggle_disabled(monkeypatch):
    monkeypatch.setattr(api, "REQUIRE_API_KEY", False)
    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)

    with pytest.raises(HTTPException) as exc:
        _run(api.clear_jobs(scan_type=None, api_key_hash=None))
    assert exc.value.status_code == 401
    assert "Missing API key" in str(exc.value.detail)
