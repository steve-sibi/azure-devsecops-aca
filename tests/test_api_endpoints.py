from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from starlette.requests import Request
from starlette.responses import JSONResponse

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
API_ROOT = APP_ROOT / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

import main as api  # noqa: E402
from common.url_dedupe import UrlDedupeConfig  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _request(path: str, method: str, *, request_id: str = "req-corr-1") -> Request:
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
    req = Request(scope)
    req.state.request_id = request_id
    return req


def test_enqueue_scan_persists_and_enqueues(monkeypatch):
    captured: dict = {}
    upserts: list[dict] = []
    ids = iter(
        [
            UUID("00000000-0000-0000-0000-000000000001"),
            UUID("00000000-0000-0000-0000-000000000002"),
        ]
    )

    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)
    monkeypatch.setattr(
        api,
        "_URL_DEDUPE",
        UrlDedupeConfig(
            ttl_seconds=0,
            in_progress_ttl_seconds=0,
            scope="global",
            index_partition="urlidx",
            redis_prefix="urlidx:",
        ),
    )
    monkeypatch.setattr(api, "uuid4", lambda: next(ids))
    monkeypatch.setattr(
        api,
        "inject_trace_context",
        lambda carrier: carrier.update(
            {
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "tracestate": "congo=t61rcWkgMzE",
            }
        ),
    )

    async def fake_validate_scan_url(_url: str) -> None:
        return None

    async def fake_enqueue_json(
        payload: dict,
        *,
        schema: str,
        message_id: str,
        application_properties: dict[str, str] | None = None,
    ) -> None:
        captured["payload"] = payload
        captured["schema"] = schema
        captured["message_id"] = message_id
        captured["application_properties"] = application_properties or {}

    async def fake_upsert_result(
        job_id: str,
        status: str,
        details: dict | None = None,
        verdict: str | None = None,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        upserts.append(
            {
                "job_id": job_id,
                "status": status,
                "details": details or {},
                "verdict": verdict,
                "error": error,
                "extra": extra or {},
            }
        )

    async def fake_upsert_job_index_record_async(**_kwargs):
        return True

    monkeypatch.setattr(api, "_validate_scan_url", fake_validate_scan_url)
    monkeypatch.setattr(api, "_enqueue_json", fake_enqueue_json)
    monkeypatch.setattr(api, "_upsert_result", fake_upsert_result)
    monkeypatch.setattr(
        api, "upsert_job_index_record_async", fake_upsert_job_index_record_async
    )

    req = api.ScanRequest(url="https://example.com", type="url", metadata={"a": "b"})
    out = _run(api.enqueue_scan(_request("/scan", "POST"), req, api_key_hash="a" * 64))

    assert out["status"] == "queued"
    assert out["deduped"] is False
    assert captured["schema"] == "scan-v1"
    assert captured["message_id"] == out["run_id"]
    assert captured["payload"]["request_id"] == out["job_id"]
    assert captured["payload"]["run_id"] == out["run_id"]
    assert captured["payload"]["traceparent"].startswith("00-")
    assert len(upserts) == 2
    assert {item["job_id"] for item in upserts} == {out["job_id"], out["run_id"]}


def test_get_scan_status_returns_pending_for_missing_job(monkeypatch):
    async def fake_get_result_entity(_job_id: str):
        return None

    monkeypatch.setattr(api, "_get_result_entity", fake_get_result_entity)
    out = _run(
        api.get_scan_status(
            "missing-job",
            _request("/scan/missing-job", "GET"),
            view="summary",
            api_key_hash="a" * 64,
        )
    )
    assert out == {"job_id": "missing-job", "status": "pending", "summary": None}


def test_list_jobs_accepts_blocked_status_filter(monkeypatch):
    captured: dict = {}

    async def fake_list_jobs_async(
        *,
        backend: str,
        api_key_hash_value: str,
        limit: int,
        statuses: list[str] | None,
        table_client=None,
        redis_client=None,
    ):
        captured["backend"] = backend
        captured["api_key_hash_value"] = api_key_hash_value
        captured["limit"] = limit
        captured["statuses"] = statuses
        captured["table_client"] = table_client
        captured["redis_client"] = redis_client
        return [
            {
                "job_id": "req-1",
                "run_id": "run-1",
                "status": "queued",
                "submitted_at": "2026-01-01T00:00:00+00:00",
                "url": "https://example.com",
                "type": "url",
            }
        ]

    async def fake_get_result_entity(job_id: str):
        if job_id == "run-1":
            return {
                "status": "blocked",
                "scanned_at": "2026-01-01T00:00:10+00:00",
                "error": "upstream blocked",
                "correlation_id": "corr-1",
            }
        return None

    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)
    monkeypatch.setattr(api, "list_jobs_async", fake_list_jobs_async)
    monkeypatch.setattr(api, "_get_result_entity", fake_get_result_entity)

    out = _run(
        api.list_jobs(
            _request("/jobs", "GET"),
            limit=25,
            scan_type=None,
            status="blocked",
            api_key_hash="a" * 64,
        )
    )

    assert captured["statuses"] == ["blocked"]
    assert len(out["jobs"]) == 1
    assert out["jobs"][0]["status"] == "blocked"
    assert out["jobs"][0]["dashboard_url"].endswith("/?job=req-1")


def test_scan_file_payload_path(monkeypatch):
    persisted: dict = {}

    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)
    monkeypatch.setattr(api, "FILE_SCAN_INCLUDE_VERSION", False)
    monkeypatch.setattr(api, "clamd_ping", lambda **_kwargs: True)
    monkeypatch.setattr(
        api,
        "clamd_scan_bytes",
        lambda *_args, **_kwargs: SimpleNamespace(
            verdict="clean", signature=None, raw="stream: OK", error=None
        ),
    )

    async def fake_upsert_result(
        job_id: str,
        status: str,
        details: dict | None = None,
        verdict: str | None = None,
        error: str | None = None,
        extra: dict | None = None,
    ) -> None:
        persisted["job_id"] = job_id
        persisted["status"] = status
        persisted["details"] = details or {}
        persisted["verdict"] = verdict
        persisted["error"] = error
        persisted["extra"] = extra or {}

    async def fake_upsert_job_index_record_async(**_kwargs):
        return True

    monkeypatch.setattr(api, "_upsert_result", fake_upsert_result)
    monkeypatch.setattr(
        api, "upsert_job_index_record_async", fake_upsert_job_index_record_async
    )

    out = _run(
        api.scan_file(
            _request("/file/scan", "POST"),
            file=None,
            payload="hello world",
            payload_base64=False,
            api_key_hash="a" * 64,
        )
    )

    assert out["status"] == "completed"
    assert out["type"] == "file"
    assert out["verdict"] == "clean"
    assert out["stored"] is True
    assert persisted["status"] == "completed"
    assert persisted["details"]["type"] == "file"


def test_admin_key_mint_and_revoke_lifecycle(monkeypatch):
    store: dict[str, dict] = {}

    monkeypatch.setattr(api, "API_KEY_STORE_ENABLED", True)
    monkeypatch.setattr(api, "RESULT_BACKEND", "redis")
    monkeypatch.setattr(api, "redis_client", object())
    monkeypatch.setattr(api, "table_client", None)
    monkeypatch.setattr(api, "_mint_api_key_plaintext", lambda: "aca-fixed-test-key")

    async def fake_get_api_key_record_async(
        *,
        backend: str,
        cfg,
        key_hash: str,
        table_client=None,
        redis_client=None,
    ):
        _ = (backend, cfg, table_client, redis_client)
        return store.get(key_hash)

    async def fake_upsert_api_key_record_async(
        *,
        backend: str,
        cfg,
        record: dict,
        table_client=None,
        redis_client=None,
    ):
        _ = (backend, cfg, table_client, redis_client)
        store[str(record.get("key_hash"))] = dict(record)
        return True

    async def fake_revoke_api_key_async(
        *,
        backend: str,
        cfg,
        key_hash: str,
        table_client=None,
        redis_client=None,
    ):
        _ = (backend, cfg, table_client, redis_client)
        rec = store.get(key_hash)
        if not rec:
            return False
        rec["revoked"] = True
        rec["revoked_at"] = "2026-01-01T00:00:00+00:00"
        store[key_hash] = rec
        return True

    monkeypatch.setattr(api, "get_api_key_record_async", fake_get_api_key_record_async)
    monkeypatch.setattr(
        api, "upsert_api_key_record_async", fake_upsert_api_key_record_async
    )
    monkeypatch.setattr(api, "revoke_api_key_async", fake_revoke_api_key_async)

    mint_req = api.ApiKeyMintRequest(
        label="team-a", read_rpm=120, write_rpm=60, ttl_days=7, is_admin=False
    )
    minted = _run(api.admin_mint_api_key(mint_req, admin_api_key_hash="f" * 64))
    minted_hash = minted["key_hash"]

    assert minted["api_key"] == "aca-fixed-test-key"
    assert minted_hash in store
    assert store[minted_hash]["label"] == "team-a"

    revoked = _run(api.admin_revoke_api_key(minted_hash, _="f" * 64))
    assert revoked["revoked"] is True


def test_otel_request_spans_extracts_inbound_trace_context(monkeypatch):
    extracted: dict = {}
    sentinel_ctx = object()
    monkeypatch.setattr(api, "TELEMETRY_ACTIVE", True)
    monkeypatch.setattr(
        api,
        "extract_trace_context",
        lambda *, traceparent, tracestate: extracted.update(
            {"traceparent": traceparent, "tracestate": tracestate}
        )
        or sentinel_ctx,
    )

    class _FakeSpan:
        def __init__(self) -> None:
            self.attributes: dict[str, object] = {}
            self.updated_name = ""

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):  # noqa: ANN001
            return False

        def set_attribute(self, key: str, value):
            self.attributes[key] = value

        def update_name(self, value: str):
            self.updated_name = value

        def set_status(self, *_args, **_kwargs):
            return None

        def record_exception(self, *_args, **_kwargs):
            return None

        def add_event(self, *_args, **_kwargs):
            return None

    class _FakeTracer:
        def __init__(self) -> None:
            self.calls: list[dict] = []

        def start_as_current_span(self, name: str, *, context=None, kind=None):
            span = _FakeSpan()
            self.calls.append(
                {"name": name, "context": context, "kind": kind, "span": span}
            )
            return span

    fake_tracer = _FakeTracer()
    fake_trace_module = types.ModuleType("opentelemetry.trace")
    fake_trace_module.get_tracer = lambda _name: fake_tracer

    class _FakeSpanKind:
        SERVER = "server"

    class _FakeStatusCode:
        ERROR = "error"

    class _FakeStatus:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    fake_trace_module.SpanKind = _FakeSpanKind
    fake_trace_module.StatusCode = _FakeStatusCode
    fake_trace_module.Status = _FakeStatus

    fake_otel_module = types.ModuleType("opentelemetry")
    fake_otel_module.trace = fake_trace_module

    monkeypatch.setitem(sys.modules, "opentelemetry", fake_otel_module)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", fake_trace_module)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/scan/test-job",
        "raw_path": b"/scan/test-job",
        "query_string": b"",
        "headers": [
            (
                b"traceparent",
                b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
            (b"tracestate", b"congo=t61rcWkgMzE"),
            (b"host", b"testserver"),
        ],
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "root_path": "",
    }
    request = Request(scope)

    async def _call_next(_request: Request):
        return JSONResponse({"ok": True}, status_code=200)

    response = _run(api.otel_request_spans(request, _call_next))
    assert response.status_code == 200
    assert extracted["traceparent"] == (
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    )
    assert extracted["tracestate"] == "congo=t61rcWkgMzE"
    assert fake_tracer.calls[0]["context"] is sentinel_ctx
