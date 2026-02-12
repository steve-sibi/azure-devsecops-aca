"""Telemetry behavior tests for app/worker/fetcher.py."""

from __future__ import annotations

import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
WORKER_ROOT = APP_ROOT / "worker"
if str(WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_ROOT))

import fetcher as fetcher  # noqa: E402
from common.logging_config import get_correlation_id  # noqa: E402


class _Persister:
    def __init__(self) -> None:
        self.saved: list[dict] = []

    def save_result(self, **kwargs):
        self.saved.append(kwargs)
        return True


def test_fetcher_process_propagates_trace_and_clears_correlation(monkeypatch, tmp_path):
    persister = _Persister()
    forwarded: dict = {}

    monkeypatch.setattr(fetcher, "result_persister", persister)
    monkeypatch.setattr(fetcher, "download_url", lambda *_a, **_k: (b"abc", 3, {}))
    monkeypatch.setattr(fetcher, "_ensure_artifact_dir", lambda: tmp_path)
    monkeypatch.setattr(fetcher, "get_tracer", lambda *_a, **_k: None)
    monkeypatch.setattr(fetcher, "validate_scan_task_v1", lambda task: task)
    monkeypatch.setattr(fetcher, "validate_scan_artifact_v1", lambda payload: payload)
    monkeypatch.setattr(
        fetcher,
        "inject_trace_context",
        lambda carrier: carrier.update(
            {
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "tracestate": "congo=t61rcWkgMzE",
            }
        ),
    )
    monkeypatch.setattr(
        fetcher,
        "_enqueue_scan",
        lambda payload, message_id: forwarded.update(
            {"payload": payload, "message_id": message_id}
        ),
    )

    fetcher.process(
        {
            "job_id": "job-1",
            "request_id": "req-1",
            "run_id": "run-1",
            "url": "https://example.com",
            "correlation_id": "corr-1",
            "submitted_at": "2026-01-01T00:00:00Z",
            "type": "url",
            "metadata": {},
        }
    )

    assert forwarded["message_id"] == "job-1"
    assert forwarded["payload"]["request_id"] == "req-1"
    assert forwarded["payload"]["run_id"] == "run-1"
    assert (
        forwarded["payload"]["traceparent"]
        == "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    )
    assert forwarded["payload"]["tracestate"] == "congo=t61rcWkgMzE"
    assert any(item.get("status") == "fetching" for item in persister.saved)
    assert any(item.get("status") == "queued_scan" for item in persister.saved)
    assert get_correlation_id() is None
