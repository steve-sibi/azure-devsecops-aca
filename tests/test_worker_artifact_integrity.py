from __future__ import annotations


import pytest

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
