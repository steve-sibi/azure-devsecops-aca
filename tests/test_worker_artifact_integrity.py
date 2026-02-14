from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
WORKER_ROOT = APP_ROOT / "worker"
if str(WORKER_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKER_ROOT))

import worker as worker_mod  # noqa: E402


def test_worker_rejects_artifact_size_mismatch(monkeypatch, tmp_path):
    artifact = tmp_path / "job-1.bin"
    artifact.write_bytes(b"abc")

    monkeypatch.setattr(worker_mod, "ARTIFACT_DIR", str(tmp_path))
    monkeypatch.setattr(worker_mod, "get_tracer", lambda *_a, **_k: None)
    monkeypatch.setattr(worker_mod, "validate_scan_artifact_v1", lambda task: task)

    with pytest.raises(ValueError, match="artifact size mismatch"):
        worker_mod.process(
            {
                "job_id": "job-1",
                "url": "https://example.com",
                "artifact_path": "job-1.bin",
                "artifact_size_bytes": 1,
            }
        )
