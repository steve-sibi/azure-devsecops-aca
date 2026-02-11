"""Telemetry behavior tests for app/worker/worker.py."""

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

import worker as worker_mod  # noqa: E402
from common.logging_config import get_correlation_id  # noqa: E402


class _Persister:
    def __init__(self) -> None:
        self.saved: list[dict] = []

    def save_result(self, **kwargs):
        self.saved.append(kwargs)
        return True


def test_worker_process_clears_correlation_between_tasks(monkeypatch):
    persister = _Persister()

    monkeypatch.setattr(worker_mod, "result_persister", persister)
    monkeypatch.setattr(worker_mod, "get_tracer", lambda *_a, **_k: None)
    monkeypatch.setattr(worker_mod, "validate_scan_artifact_v1", lambda task: task)
    monkeypatch.setattr(worker_mod, "download_url", lambda *_a, **_k: (b"abc", 3, {}))
    monkeypatch.setattr(
        worker_mod,
        "_scan_bytes",
        lambda *_a, **_k: {"results": {"web": {"page_information": {}}}},
    )
    monkeypatch.setattr(
        worker_mod,
        "_maybe_capture_and_store_screenshot",
        lambda **_k: {"status": "disabled"},
    )

    task = {
        "job_id": "job-1",
        "url": "https://example.com",
        "correlation_id": "corr-1",
        "submitted_at": "2026-01-01T00:00:00Z",
    }
    worker_mod.process(task)
    assert get_correlation_id() is None

    task2 = {
        "job_id": "job-2",
        "url": "https://example.org",
        "correlation_id": "corr-2",
        "submitted_at": "2026-01-01T00:01:00Z",
    }
    worker_mod.process(task2)
    assert get_correlation_id() is None
    assert len(persister.saved) == 2
    assert persister.saved[0]["job_id"] == "job-1"
    assert persister.saved[1]["job_id"] == "job-2"
