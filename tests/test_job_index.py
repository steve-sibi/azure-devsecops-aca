from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.job_index import (  # noqa: E402
    api_key_hash,
    build_job_index_record,
    job_index_partition_key,
    job_index_row_key,
)


def test_api_key_hash_is_sha256_hex():
    h = api_key_hash("secret")
    assert isinstance(h, str)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_job_index_row_key_sorts_newest_first():
    now = datetime.now(timezone.utc)
    older = (now - timedelta(minutes=5)).isoformat()
    newer = now.isoformat()

    rk_old = job_index_row_key(submitted_at=older, job_id="a")
    rk_new = job_index_row_key(submitted_at=newer, job_id="b")

    # RowKey sorts ascending in Table; we want newest first.
    assert rk_new < rk_old


def test_build_job_index_record_includes_partition_and_rowkey():
    h = api_key_hash("secret")
    submitted = datetime.now(timezone.utc).isoformat()
    rec = build_job_index_record(
        api_key_hash_value=h,
        job_id="job",
        submitted_at=submitted,
        status="queued",
        url="https://example.com",
    )
    assert rec["PartitionKey"] == job_index_partition_key(api_key_hash_value=h)
    assert rec["RowKey"].endswith(":job")
    assert rec["status"] == "queued"
    assert int(rec["status_rank"]) > 0

