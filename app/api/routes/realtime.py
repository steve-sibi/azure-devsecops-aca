from __future__ import annotations

import asyncio
import json
import secrets
from typing import Optional

from common.live_updates import redis_stream_key
from common.logging_config import get_logger
from common.webpubsub import group_for_api_key_hash, group_for_run
from fastapi import APIRouter, HTTPException, Query, Request, Security
from fastapi.responses import StreamingResponse

import runtime
import settings
from deps.auth import require_api_key
from deps.store import _get_result_entity
from models import PubSubNegotiateRequest

router = APIRouter()
logger = get_logger(__name__)


def _normalize_stream_cursor(value: Optional[str]) -> str:
    raw = str(value or "$").strip() or "$"
    if raw == "$":
        return "$"
    parts = raw.split("-", 1)
    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
        return raw
    raise HTTPException(
        status_code=400,
        detail="cursor must be '$' or a stream id like '<ms>-<seq>'",
    )


@router.get(
    "/events/stream",
    tags=["Realtime"],
    summary="Stream live job updates (NDJSON)",
)
async def stream_job_updates(
    request: Request,
    cursor: str = Query(
        "$",
        description="Redis stream cursor ('$' for latest, or '<ms>-<seq>' for resume)",
    ),
    run_id: Optional[str] = Query(
        None, description="Optional run_id filter for targeted streams"
    ),
    api_key_hash: Optional[str] = Security(require_api_key),
):
    redis_client = runtime.get_redis_client(request)
    if runtime.get_live_updates_backend(request) != "redis_streams":
        raise HTTPException(status_code=501, detail="Redis stream live updates not enabled")
    if not redis_client:
        raise HTTPException(status_code=503, detail="Live updates store not initialized")
    if not api_key_hash:
        raise HTTPException(status_code=401, detail="Missing API key")

    cursor_norm = _normalize_stream_cursor(cursor)
    run_id_norm = str(run_id or "").strip() or None
    stream_key = redis_stream_key(
        settings.LIVE_UPDATES_REDIS_CFG.stream_prefix,
        str(api_key_hash or "").strip().lower(),
    )
    block_ms = max(1000, int(settings.LIVE_UPDATES_REDIS_CFG.block_ms or 30000))

    async def _iter_updates():
        current = cursor_norm
        while True:
            if await request.is_disconnected():
                break

            try:
                records = await redis_client.xread(
                    {stream_key: current},
                    count=100,
                    block=block_ms,
                )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Live stream read failed (key=%s): %s", stream_key, exc)
                break

            if not records:
                continue

            for _stream, entries in records:
                for entry_id, fields in entries:
                    entry_id_s = str(entry_id or "").strip()
                    if not entry_id_s:
                        continue
                    current = entry_id_s
                    if not isinstance(fields, dict):
                        continue

                    raw = fields.get("event")
                    if isinstance(raw, (bytes, bytearray)):
                        raw = bytes(raw).decode("utf-8", "replace")
                    if not isinstance(raw, str) or not raw.strip():
                        continue
                    try:
                        event = json.loads(raw)
                    except Exception:
                        continue
                    if not isinstance(event, dict):
                        continue

                    if run_id_norm and str(event.get("run_id") or "").strip() != run_id_norm:
                        continue

                    payload = {"id": entry_id_s, "event": event}
                    yield json.dumps(payload, separators=(",", ":")) + "\n"

    return StreamingResponse(
        _iter_updates(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/pubsub/negotiate", tags=["Realtime"], summary="Negotiate Web PubSub access")
async def pubsub_negotiate(
    request: Request,
    req: PubSubNegotiateRequest,
    api_key_hash: Optional[str] = Security(require_api_key),
):
    if not settings.WEBPUBSUB_CFG:
        raise HTTPException(status_code=501, detail="Web PubSub not configured")

    job_id = str(req.job_id or "").strip()
    if not job_id:
        raise HTTPException(status_code=400, detail="job_id is required")

    entity = await _get_result_entity(job_id, request=request)
    if not entity:
        raise HTTPException(status_code=404, detail="Scan result not found")

    owner_hash = str(entity.get("api_key_hash") or "").strip()
    if owner_hash and api_key_hash and not secrets.compare_digest(owner_hash, api_key_hash):
        raise HTTPException(status_code=404, detail="Scan result not found")

    run_id = str(entity.get("run_id") or "").strip() or job_id
    group = group_for_run(settings.WEBPUBSUB_CFG, run_id)
    client = runtime.get_webpubsub_client(request)
    if not client:
        raise HTTPException(status_code=501, detail="Web PubSub not configured")

    token = client.get_client_access_token(
        groups=[group],
        user_id=api_key_hash or None,
        minutes_to_expire=settings.WEBPUBSUB_CFG.token_ttl_minutes,
    )
    return {"url": token.get("url"), "run_id": run_id, "group": group}


@router.post(
    "/pubsub/negotiate-user",
    tags=["Realtime"],
    summary="Negotiate user-scoped Web PubSub access",
)
async def pubsub_negotiate_user(
    request: Request,
    api_key_hash: Optional[str] = Security(require_api_key),
):
    if not settings.WEBPUBSUB_CFG:
        raise HTTPException(status_code=501, detail="Web PubSub not configured")
    if not api_key_hash:
        raise HTTPException(status_code=401, detail="Missing API key")
    client = runtime.get_webpubsub_client(request)
    if not client:
        raise HTTPException(status_code=501, detail="Web PubSub not configured")

    group = group_for_api_key_hash(settings.WEBPUBSUB_CFG, api_key_hash)
    token = client.get_client_access_token(
        groups=[group],
        user_id=api_key_hash,
        minutes_to_expire=settings.WEBPUBSUB_CFG.token_ttl_minutes,
    )
    return {"url": token.get("url"), "group": group}
