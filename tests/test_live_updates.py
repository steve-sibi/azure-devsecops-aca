from __future__ import annotations

import json
import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.live_updates import (  # noqa: E402
    RedisStreamsConfig,
    RedisStreamsPublisher,
    redis_stream_key,
    resolve_live_updates_backend,
)
from common.webpubsub import WebPubSubConfig  # noqa: E402


class _FakeRedis:
    def __init__(self):
        self.calls: list[dict] = []

    def xadd(self, key, mapping, **kwargs):
        self.calls.append({"key": key, "mapping": mapping, "kwargs": kwargs})
        return "1700000000000-0"


def _webpubsub_cfg() -> WebPubSubConfig:
    return WebPubSubConfig(
        connection_string="Endpoint=https://example.webpubsub.azure.com;AccessKey=abc;Version=1.0;",
        hub="scans",
        run_group_prefix="run",
        user_group_prefix="apikey",
        token_ttl_minutes=60,
    )


def test_redis_stream_key_normalizes_prefix_and_hash():
    assert redis_stream_key("events:apikey:", "AA11") == "events:apikey:aa11"
    assert redis_stream_key("", "AA11") == "events:apikey:aa11"


def test_resolve_backend_auto_prefers_webpubsub_over_redis():
    state = resolve_live_updates_backend(
        requested="auto",
        webpubsub_cfg=_webpubsub_cfg(),
        redis_available=True,
    )
    assert state.selected == "webpubsub"
    assert state.reason == "auto selected webpubsub"


def test_resolve_backend_auto_uses_redis_when_webpubsub_missing():
    state = resolve_live_updates_backend(
        requested="auto",
        webpubsub_cfg=None,
        redis_available=True,
    )
    assert state.selected == "redis_streams"
    assert state.reason == "auto selected redis_streams"


def test_resolve_backend_respects_explicit_none():
    state = resolve_live_updates_backend(
        requested="none",
        webpubsub_cfg=_webpubsub_cfg(),
        redis_available=True,
    )
    assert state.selected == "none"
    assert state.reason == "disabled by configuration"


def test_resolve_backend_webpubsub_requested_without_config_falls_back_to_none():
    state = resolve_live_updates_backend(
        requested="webpubsub",
        webpubsub_cfg=None,
        redis_available=True,
    )
    assert state.selected == "none"
    assert "WEBPUBSUB_CONNECTION_STRING" in state.reason


def test_resolve_backend_redis_requested_without_redis_falls_back_to_none():
    state = resolve_live_updates_backend(
        requested="redis_streams",
        webpubsub_cfg=None,
        redis_available=False,
    )
    assert state.selected == "none"
    assert "redis is unavailable" in state.reason


def test_resolve_backend_invalid_mode_defaults_to_auto(monkeypatch):
    monkeypatch.setenv("LIVE_UPDATES_BACKEND", "invalid-mode")
    state = resolve_live_updates_backend(
        requested=None,
        webpubsub_cfg=None,
        redis_available=False,
    )
    assert state.requested == "auto"
    assert state.selected == "none"


def test_redis_streams_config_from_env_defaults(monkeypatch):
    monkeypatch.delenv("REDIS_LIVE_UPDATES_STREAM_PREFIX", raising=False)
    monkeypatch.delenv("REDIS_LIVE_UPDATES_MAXLEN", raising=False)
    monkeypatch.delenv("REDIS_LIVE_UPDATES_BLOCK_MS", raising=False)
    cfg = RedisStreamsConfig.from_env()
    assert cfg.stream_prefix == "events:apikey:"
    assert cfg.maxlen == 10000
    assert cfg.block_ms == 30000


def test_redis_streams_publisher_xadd_with_maxlen():
    redis = _FakeRedis()
    cfg = RedisStreamsConfig(stream_prefix="events:apikey:", maxlen=55, block_ms=30000)
    publisher = RedisStreamsPublisher(redis_client=redis, cfg=cfg)

    ok = publisher.publish_job_update(
        run_id="run-123",
        api_key_hash="ABCDEF",
        payload={
            "status": "completed",
            "duration_ms": 12,
            "stage": "worker",
        },
    )

    assert ok is True
    assert len(redis.calls) == 1
    call = redis.calls[0]
    assert call["key"] == "events:apikey:abcdef"
    assert call["kwargs"] == {"maxlen": 55, "approximate": True}
    event = json.loads(call["mapping"]["event"])
    assert event["type"] == "job.update"
    assert event["run_id"] == "run-123"
    assert event["status"] == "completed"
    assert event["stage"] == "worker"


def test_redis_streams_publisher_xadd_without_maxlen_when_zero():
    redis = _FakeRedis()
    cfg = RedisStreamsConfig(stream_prefix="events:apikey:", maxlen=0, block_ms=30000)
    publisher = RedisStreamsPublisher(redis_client=redis, cfg=cfg)

    ok = publisher.publish_job_update(
        run_id="run-123",
        api_key_hash="ABCDEF",
        payload={"status": "queued"},
    )

    assert ok is True
    assert len(redis.calls) == 1
    assert redis.calls[0]["kwargs"] == {}


def test_redis_streams_publisher_requires_run_id_and_api_key_hash():
    redis = _FakeRedis()
    cfg = RedisStreamsConfig(stream_prefix="events:apikey:", maxlen=10, block_ms=30000)
    publisher = RedisStreamsPublisher(redis_client=redis, cfg=cfg)

    assert publisher.publish_job_update(
        run_id="",
        api_key_hash="ABCDEF",
        payload={"status": "queued"},
    ) is False
    assert publisher.publish_job_update(
        run_id="run-1",
        api_key_hash="",
        payload={"status": "queued"},
    ) is False
    assert redis.calls == []
