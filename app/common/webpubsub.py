from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WebPubSubConfig:
    connection_string: str
    hub: str
    run_group_prefix: str
    user_group_prefix: str
    token_ttl_minutes: int

    @staticmethod
    def from_env() -> Optional["WebPubSubConfig"]:
        conn = os.getenv("WEBPUBSUB_CONNECTION_STRING") or os.getenv("WEBPUBSUB_CONN")
        if not isinstance(conn, str) or not conn.strip():
            return None
        hub = (os.getenv("WEBPUBSUB_HUB", "scans") or "scans").strip()
        run_group_prefix = (
            os.getenv("WEBPUBSUB_GROUP_PREFIX", "run") or "run"
        ).strip()
        user_group_prefix = (
            os.getenv("WEBPUBSUB_USER_GROUP_PREFIX", "apikey") or "apikey"
        ).strip()
        ttl_raw = os.getenv("WEBPUBSUB_TOKEN_TTL_MINUTES", "60")
        try:
            ttl = max(1, int(ttl_raw))
        except Exception:
            ttl = 60
        return WebPubSubConfig(
            connection_string=conn.strip(),
            hub=hub or "scans",
            run_group_prefix=run_group_prefix or "run",
            user_group_prefix=user_group_prefix or "apikey",
            token_ttl_minutes=ttl,
        )


def group_for_run(cfg: WebPubSubConfig, run_id: str) -> str:
    return f"{cfg.run_group_prefix}:{run_id}"


def group_for_api_key_hash(cfg: WebPubSubConfig, api_key_hash: str) -> str:
    return f"{cfg.user_group_prefix}:{api_key_hash}"


def create_service_client(cfg: WebPubSubConfig):
    try:
        from azure.messaging.webpubsubservice import WebPubSubServiceClient
    except Exception as exc:
        raise RuntimeError(
            "Web PubSub requires azure-messaging-webpubsubservice"
        ) from exc
    return WebPubSubServiceClient.from_connection_string(
        cfg.connection_string, hub=cfg.hub
    )


class WebPubSubPublisher:
    def __init__(self, cfg: WebPubSubConfig, *, logger_obj: Optional[logging.Logger] = None):
        self._cfg = cfg
        self._logger = logger_obj or logger
        self._client = create_service_client(cfg)

    def publish_job_update(
        self, *, run_id: str, api_key_hash: Optional[str], payload: dict
    ) -> bool:
        run_id = (run_id or "").strip()
        api_key_hash = (api_key_hash or "").strip().lower()
        if not run_id:
            return False
        message = {"type": "job.update", "run_id": run_id}
        if isinstance(payload, dict):
            message.update(payload)
        sent = False
        targets = [group_for_run(self._cfg, run_id)]
        if api_key_hash:
            targets.append(group_for_api_key_hash(self._cfg, api_key_hash))
        for group in targets:
            try:
                self._client.send_to_group(
                    group,
                    message,
                    content_type="application/json",
                )
                sent = True
            except Exception as exc:
                self._logger.warning(
                    "[webpubsub] failed to publish update (run_id=%s group=%s): %s",
                    run_id,
                    group,
                    exc,
                )
        return sent
