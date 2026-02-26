from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping, Optional

from azure.servicebus import ServiceBusMessage
from common.result_store import get_result_async, upsert_result_async
from fastapi import HTTPException, Request

import runtime
import settings


def _coerce_positive_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        value = int(value)
    try:
        out = int(value)
    except Exception:
        try:
            out = int(str(value).strip())
        except Exception:
            return None
    return out if out > 0 else None

async def _upsert_result(
    job_id: str,
    status: str,
    details: Optional[dict] = None,
    verdict: Optional[str] = None,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
    *,
    request: Request | None = None,
):
    """Persist status/verdict to the table for status checks."""
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    await upsert_result_async(
        backend=settings.RESULT_BACKEND,
        partition_key=settings.RESULT_PARTITION,
        job_id=job_id,
        status=status,
        verdict=verdict,
        error=error,
        details=details,
        extra=extra,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=settings.REDIS_RESULT_PREFIX,
        redis_ttl_seconds=settings.REDIS_RESULT_TTL_SECONDS,
    )


async def _get_result_entity(job_id: str, *, request: Request | None = None) -> Optional[dict]:
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    return await get_result_async(
        backend=settings.RESULT_BACKEND,
        partition_key=settings.RESULT_PARTITION,
        job_id=job_id,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=settings.REDIS_RESULT_PREFIX,
    )


async def _enqueue_json(
    payload: dict,
    *,
    schema: str,
    message_id: str,
    application_properties: Optional[Mapping[str, Any]] = None,
    request: Request | None = None,
):
    def _normalize_application_properties(
        raw: Optional[Mapping[str, Any]],
    ) -> dict[str, str]:
        if not raw:
            return {}
        out: dict[str, str] = {}
        for k, v in raw.items():
            if v is None:
                continue
            key = str(k)
            if isinstance(v, str):
                out[key] = v
            elif isinstance(v, (bytes, bytearray)):
                out[key] = bytes(v).decode("utf-8", "replace")
            elif isinstance(v, datetime):
                out[key] = v.isoformat()
            else:
                out[key] = str(v)
        return out

    sb_sender = runtime.get_sb_sender(request)
    redis_client = runtime.get_redis_client(request)

    if settings.QUEUE_BACKEND == "servicebus":
        if not sb_sender:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        props: dict[str | bytes, Any] = {"schema": schema}
        if application_properties:
            props.update(_normalize_application_properties(application_properties))
        msg = ServiceBusMessage(
            json.dumps(payload),
            content_type="application/json",
            message_id=message_id,
            application_properties=props,
        )
        await sb_sender.send_messages(msg)
        return

    if settings.QUEUE_BACKEND == "redis":
        if not redis_client:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        envelope = {
            "schema": schema,
            "message_id": message_id,
            "delivery_count": 1,
            "payload": payload,
        }
        if application_properties:
            envelope["application_properties"] = _normalize_application_properties(
                application_properties
            )
        await redis_client.rpush(settings.REDIS_QUEUE_KEY, json.dumps(envelope))
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {settings.QUEUE_BACKEND}")


def _safe_int(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value))
        except Exception:
            return None


def _coerce_bool(value) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return bool(value)
    if isinstance(value, (int, float)):
        return bool(int(value))
    if isinstance(value, (bytes, bytearray)):
        try:
            value = value.decode("utf-8", "replace")
        except Exception:
            value = str(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "y", "on"):
            return True
        if v in ("0", "false", "no", "n", "off"):
            return False
    return None


def _normalize_visibility(value: Optional[str]) -> str:
    v = (value or "").strip().lower()
    if v in ("shared", "private"):
        return v
    return settings._DEFAULT_URL_VISIBILITY


def _parse_details(raw) -> Optional[dict]:
    if raw is None or raw == "":
        return None
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if not isinstance(raw, str):
        raw = str(raw)
    try:
        doc = json.loads(raw)
    except Exception:
        return {"raw": raw}
    return doc if isinstance(doc, dict) else {"value": doc}


def _build_summary(entity: dict, details: Optional[dict]) -> dict:
    summary: dict = {}

    url = None
    engines = []
    sha256 = None

    if isinstance(details, dict):
        url_val = details.get("url")
        if isinstance(url_val, str) and url_val:
            url = url_val

        engines_val = details.get("engines")
        if isinstance(engines_val, list):
            engines = [str(e) for e in engines_val if e]
        elif isinstance(details.get("engine"), str) and details.get("engine"):
            engines = [str(details.get("engine"))]

        sha_val = details.get("sha256")
        if isinstance(sha_val, str) and sha_val:
            sha256 = sha_val

    size_bytes = _safe_int(entity.get("size_bytes"))
    duration_ms = _safe_int(entity.get("duration_ms"))
    correlation_id = entity.get("correlation_id") or None

    if url:
        summary["url"] = url
    if sha256:
        summary["sha256"] = sha256
    if engines:
        summary["engines"] = engines
    if size_bytes is not None:
        summary["size_bytes"] = size_bytes
    if duration_ms is not None:
        summary["duration_ms"] = duration_ms
    if correlation_id:
        summary["correlation_id"] = correlation_id

    # Download metadata (if present)
    if isinstance(details, dict) and isinstance(details.get("download"), dict):
        d = details["download"]
        download: dict = {}
        for key in ("requested_url", "final_url", "content_type", "content_length"):
            val = d.get(key)
            if isinstance(val, str) and val:
                download[key] = val
        status_code = _safe_int(d.get("status_code"))
        if status_code is not None:
            download["status_code"] = status_code
        redirects = d.get("redirects")
        if isinstance(redirects, list):
            download["redirect_count"] = len(redirects)
        blocked = d.get("blocked")
        if isinstance(blocked, bool):
            download["blocked"] = blocked
        rh = d.get("response_headers")
        if isinstance(rh, list):
            trimmed: list[dict] = []
            for item in rh:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                value = item.get("value")
                if not isinstance(name, str) or not name.strip():
                    continue
                if value is None:
                    continue
                val_s = str(value)
                if len(val_s) > 320:
                    val_s = val_s[:317] + "..."
                trimmed.append({"name": name.strip().lower(), "value": val_s})
                if len(trimmed) >= 25:
                    break
            if trimmed:
                download["response_headers"] = trimmed
        if download:
            summary["download"] = download

    # Engine summaries
    results = details.get("results") if isinstance(details, dict) else None
    if isinstance(results, dict):
        web = results.get("web")
        if isinstance(web, dict) and web:
            summary["web"] = web

    return summary
