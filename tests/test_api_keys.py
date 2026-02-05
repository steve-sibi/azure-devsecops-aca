from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.api_keys import (  # noqa: E402
    ApiKeyStoreConfig,
    api_key_is_active,
    build_api_key_record,
    normalize_api_key_record,
)


def test_build_api_key_record_sets_expected_defaults():
    cfg = ApiKeyStoreConfig(
        table_partition="apikeys",
        redis_prefix="apikey:",
        redis_index_key="apikeys:index",
    )
    key_hash = "a" * 64
    rec = build_api_key_record(cfg=cfg, key_hash=key_hash, label="team-a")
    assert rec["PartitionKey"] == "apikeys"
    assert rec["RowKey"] == key_hash
    assert rec["key_hash"] == key_hash
    assert rec["label"] == "team-a"
    assert rec["revoked"] is False
    assert rec["read_rpm"] == 0
    assert rec["write_rpm"] == 0
    assert rec["key_id"]


def test_normalize_api_key_record_parses_string_fields():
    raw = {
        "key_hash": "b" * 64,
        "key_id": "kid-1",
        "read_rpm": "25",
        "write_rpm": "10",
        "revoked": "0",
        "is_admin": "1",
    }
    rec = normalize_api_key_record(raw)
    assert rec is not None
    assert rec["key_hash"] == "b" * 64
    assert rec["read_rpm"] == 25
    assert rec["write_rpm"] == 10
    assert rec["revoked"] is False
    assert rec["is_admin"] is True


def test_api_key_is_active_handles_revoked_and_expiration():
    now = datetime.now(timezone.utc)
    active = {
        "key_hash": "c" * 64,
        "revoked": False,
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    expired = {
        "key_hash": "d" * 64,
        "revoked": False,
        "expires_at": (now - timedelta(minutes=1)).isoformat(),
    }
    revoked = {
        "key_hash": "e" * 64,
        "revoked": True,
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    assert api_key_is_active(active, now=now) is True
    assert api_key_is_active(expired, now=now) is False
    assert api_key_is_active(revoked, now=now) is False
