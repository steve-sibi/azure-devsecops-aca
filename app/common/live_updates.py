from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

from common.webpubsub import WebPubSubConfig, WebPubSubPublisher

logger = logging.getLogger(__name__)

LIVE_UPDATES_BACKENDS = ("auto", "webpubsub", "redis_streams", "none")


@dataclass(frozen=True)
class LiveUpdatesBackendState:
    requested: str
    selected: str
    reason: str


@dataclass(frozen=True)
class RedisStreamsConfig:
    stream_prefix: str
    maxlen: int
    block_ms: int

    @staticmethod
    def from_env() -> "RedisStreamsConfig":
        prefix = (
            os.getenv("REDIS_LIVE_UPDATES_STREAM_PREFIX", "events:apikey:")
            or "events:apikey:"
        ).strip()
        if not prefix:
            prefix = "events:apikey:"
        try:
            maxlen = int(os.getenv("REDIS_LIVE_UPDATES_MAXLEN", "10000"))
        except Exception:
            maxlen = 10000
        try:
            block_ms = int(os.getenv("REDIS_LIVE_UPDATES_BLOCK_MS", "30000"))
        except Exception:
            block_ms = 30000
        return RedisStreamsConfig(
            stream_prefix=prefix,
            maxlen=max(0, maxlen),
            block_ms=max(1000, block_ms),
        )


class RedisStreamsPublisher:
    def __init__(
        self,
        *,
        redis_client,
        cfg: RedisStreamsConfig,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:
        self._redis_client = redis_client
        self._cfg = cfg
        self._logger = logger_obj or logger

    def publish_job_update(
        self, *, run_id: str, api_key_hash: Optional[str], payload: dict
    ) -> bool:
        run_id = (run_id or "").strip()
        api_key_hash_norm = (api_key_hash or "").strip().lower()
        if not run_id or not api_key_hash_norm:
            return False

        event = {"type": "job.update", "run_id": run_id}
        if isinstance(payload, dict):
            event.update(payload)

        key = redis_stream_key(self._cfg.stream_prefix, api_key_hash_norm)
        mapping = {
            "event": json.dumps(event, separators=(",", ":"), ensure_ascii=False),
        }
        try:
            if self._cfg.maxlen > 0:
                self._redis_client.xadd(
                    key,
                    mapping,
                    maxlen=self._cfg.maxlen,
                    approximate=True,
                )
            else:
                self._redis_client.xadd(key, mapping)
            return True
        except Exception as exc:
            self._logger.warning(
                "[live-updates] failed to publish redis stream event (run_id=%s key=%s): %s",
                run_id,
                key,
                exc,
            )
            return False


def redis_stream_key(stream_prefix: str, api_key_hash: str) -> str:
    prefix = (stream_prefix or "events:apikey:").strip() or "events:apikey:"
    return f"{prefix}{str(api_key_hash or '').strip().lower()}"


def resolve_live_updates_backend(
    *,
    requested: Optional[str] = None,
    webpubsub_cfg: Optional[WebPubSubConfig] = None,
    redis_available: bool = False,
) -> LiveUpdatesBackendState:
    raw = requested or os.getenv("LIVE_UPDATES_BACKEND", "auto")
    mode = (str(raw or "auto").strip().lower() or "auto")
    if mode not in LIVE_UPDATES_BACKENDS:
        mode = "auto"

    has_webpubsub = webpubsub_cfg is not None

    if mode == "none":
        return LiveUpdatesBackendState(
            requested=mode,
            selected="none",
            reason="disabled by configuration",
        )

    if mode == "webpubsub":
        if has_webpubsub:
            return LiveUpdatesBackendState(
                requested=mode,
                selected="webpubsub",
                reason="configured",
            )
        return LiveUpdatesBackendState(
            requested=mode,
            selected="none",
            reason="webpubsub requested but WEBPUBSUB_CONNECTION_STRING is not set",
        )

    if mode == "redis_streams":
        if redis_available:
            return LiveUpdatesBackendState(
                requested=mode,
                selected="redis_streams",
                reason="configured",
            )
        return LiveUpdatesBackendState(
            requested=mode,
            selected="none",
            reason="redis_streams requested but redis is unavailable",
        )

    # auto mode
    if has_webpubsub:
        return LiveUpdatesBackendState(
            requested=mode,
            selected="webpubsub",
            reason="auto selected webpubsub",
        )
    if redis_available:
        return LiveUpdatesBackendState(
            requested=mode,
            selected="redis_streams",
            reason="auto selected redis_streams",
        )
    return LiveUpdatesBackendState(
        requested=mode,
        selected="none",
        reason="auto selected none (no supported backend available)",
    )


def create_live_updates_publisher(
    *,
    backend: LiveUpdatesBackendState,
    redis_client=None,
    webpubsub_cfg: Optional[WebPubSubConfig] = None,
    redis_cfg: Optional[RedisStreamsConfig] = None,
    logger_obj: Optional[logging.Logger] = None,
):
    selected = (backend.selected or "none").strip().lower()
    if selected == "webpubsub":
        if not webpubsub_cfg:
            return None
        return WebPubSubPublisher(webpubsub_cfg, logger_obj=logger_obj)
    if selected == "redis_streams":
        if redis_client is None:
            return None
        return RedisStreamsPublisher(
            redis_client=redis_client,
            cfg=redis_cfg or RedisStreamsConfig.from_env(),
            logger_obj=logger_obj,
        )
    return None
