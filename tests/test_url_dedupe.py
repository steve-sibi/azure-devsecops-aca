from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.url_dedupe import (  # noqa: E402
    UrlDedupeConfig,
    build_url_index_record,
    make_url_index_key,
    url_index_entry_is_fresh,
)


def test_url_dedupe_config_defaults_disabled():
    with mock.patch.dict(os.environ, {}, clear=True):
        cfg = UrlDedupeConfig.from_env()
        assert cfg.ttl_seconds == 0
        assert cfg.in_progress_ttl_seconds == 0
        assert cfg.scope == "global"
        assert cfg.enabled is False


def test_make_url_index_key_uses_canonical_url():
    cfg = UrlDedupeConfig(
        ttl_seconds=60,
        in_progress_ttl_seconds=10,
        scope="global",
        index_partition="urlidx",
        redis_prefix="urlidx:",
    )
    key = make_url_index_key(url="HTTPS://ExAmple.COM:443/A/../B#Frag", api_key_hash=None, cfg=cfg)
    assert key.canonical_url == "https://example.com/B"
    assert key.partition_key == "urlidx"
    assert len(key.row_key) == 64  # sha256 hex


def test_make_url_index_key_scopes_by_apikey_when_configured():
    cfg = UrlDedupeConfig(
        ttl_seconds=60,
        in_progress_ttl_seconds=10,
        scope="apikey",
        index_partition="urlidx",
        redis_prefix="urlidx:",
    )
    key = make_url_index_key(url="https://example.com/", api_key_hash="abc", cfg=cfg)
    assert key.partition_key.startswith("urlidx:")


def test_url_index_entry_is_fresh_terminal_vs_in_progress_ttl():
    cfg = UrlDedupeConfig(
        ttl_seconds=60,
        in_progress_ttl_seconds=10,
        scope="global",
        index_partition="urlidx",
        redis_prefix="urlidx:",
    )
    now = datetime.now(timezone.utc)
    key = make_url_index_key(url="https://example.com/", api_key_hash=None, cfg=cfg)

    completed = build_url_index_record(
        key=key,
        job_id="job",
        status="completed",
        submitted_at=now.isoformat(),
        scanned_at=now.isoformat(),
        updated_at=now.isoformat(),
    )
    assert url_index_entry_is_fresh(completed, now=now, cfg=cfg) is True
    assert (
        url_index_entry_is_fresh(
            completed, now=now + timedelta(seconds=61), cfg=cfg
        )
        is False
    )

    queued = dict(completed)
    queued["status"] = "queued"
    queued["updated_at"] = now.isoformat()
    assert url_index_entry_is_fresh(queued, now=now, cfg=cfg) is True
    assert (
        url_index_entry_is_fresh(
            queued, now=now + timedelta(seconds=11), cfg=cfg
        )
        is False
    )
