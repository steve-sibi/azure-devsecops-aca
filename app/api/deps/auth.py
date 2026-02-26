from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from collections import deque
from typing import Optional

from common.api_keys import (
    api_key_is_active,
    get_api_key_record_async,
    touch_api_key_last_used_async,
)
from common.job_index import api_key_hash as hash_api_key
from common.logging_config import get_logger
from fastapi import HTTPException, Request, Security

import runtime
import settings
from deps.store import _coerce_positive_int

logger = get_logger(__name__)

_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, deque[float]] = {}


def _rate_limit_scope_for_request(request: Request) -> tuple[str, int]:
    method = str(getattr(request, "method", "") or "").upper()
    path = str(getattr(getattr(request, "url", None), "path", "") or "")
    if method in ("GET", "HEAD", "OPTIONS"):
        return ("read", settings.RATE_LIMIT_READ_RPM)
    if method == "POST" and path.startswith("/pubsub/"):
        return ("read", settings.RATE_LIMIT_READ_RPM)
    return ("write", settings.RATE_LIMIT_WRITE_RPM)


async def _enforce_rate_limit(api_key: str, *, scope: str, limit_rpm: int):
    if limit_rpm <= 0:
        return
    window = max(1, settings.RATE_LIMIT_WINDOW_SECONDS)
    now = time.monotonic()
    bucket = (
        hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        + ":"
        + str(scope or "default")
    )
    async with _rate_lock:
        q = _rate_buckets.setdefault(bucket, deque())
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= limit_rpm:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({limit_rpm}/{window}s)",
            )
        q.append(now)


def _configured_keys(primary: Optional[str], csv_value: str) -> list[str]:
    out: list[str] = []
    if isinstance(primary, str) and primary.strip():
        out.append(primary.strip())
    if isinstance(csv_value, str) and csv_value.strip():
        out.extend([p.strip() for p in csv_value.split(",") if p.strip()])
    return out


def _default_admin_keys() -> list[str]:
    admin_keys = _configured_keys(settings.API_ADMIN_KEY, settings.API_ADMIN_KEYS)
    if admin_keys:
        return admin_keys
    if isinstance(settings.API_KEY, str) and settings.API_KEY.strip():
        return [settings.API_KEY.strip()]
    return []


def _api_key_store_ready(*, request: Request | None = None) -> bool:
    if not settings.API_KEY_STORE_ENABLED:
        return False
    if settings.RESULT_BACKEND == "table":
        return bool(runtime.get_table_client(request))
    if settings.RESULT_BACKEND == "redis":
        return bool(runtime.get_redis_client(request))
    return False


def _require_api_key_store_ready(*, request: Request | None = None) -> None:
    if not settings.API_KEY_STORE_ENABLED:
        raise HTTPException(status_code=501, detail="API key store is disabled")
    if settings.RESULT_BACKEND == "table" and not runtime.get_table_client(request):
        raise HTTPException(status_code=503, detail="API key store not initialized")
    if settings.RESULT_BACKEND == "redis" and not runtime.get_redis_client(request):
        raise HTTPException(status_code=503, detail="API key store not initialized")


async def _lookup_api_key_record(
    api_key_hash_value: str, *, request: Request | None = None
) -> Optional[dict]:
    if not _api_key_store_ready(request=request):
        return None
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    try:
        return await get_api_key_record_async(
            backend=settings.RESULT_BACKEND,
            cfg=settings._API_KEY_STORE_CFG,
            key_hash=api_key_hash_value,
            table_client=table_client,
            redis_client=redis_client,
        )
    except Exception as e:
        logger.warning("API key lookup failed: %s", e)
        return None


def _is_match(key: str, configured: list[str]) -> bool:
    return any(secrets.compare_digest(key, k) for k in configured)


def _limit_for_scope(
    *,
    scope: str,
    default_limit: int,
    key_record: Optional[dict],
) -> int:
    if not isinstance(key_record, dict):
        return default_limit
    field = "read_rpm" if scope == "read" else "write_rpm"
    override = _coerce_positive_int(key_record.get(field))
    if override is None:
        return default_limit
    return override


async def _authenticate_api_key(
    request: Request,
    api_key: Optional[str],
    *,
    require_admin: bool = False,
) -> Optional[str]:
    if not settings.REQUIRE_API_KEY and not require_admin:
        return None

    configured_keys = _configured_keys(settings.API_KEY, settings.API_KEYS)
    store_ready = _api_key_store_ready(request=request)
    admin_keys = _default_admin_keys() if require_admin else []

    if require_admin:
        if not admin_keys and not store_ready:
            raise HTTPException(status_code=500, detail="No admin API keys are configured")
    elif not configured_keys and not store_ready:
        raise HTTPException(status_code=500, detail="No API keys are configured")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    api_key_hash_value = hash_api_key(api_key)
    key_record = await _lookup_api_key_record(api_key_hash_value, request=request)
    store_active = api_key_is_active(key_record)
    static_allowed = _is_match(api_key, configured_keys)

    if require_admin:
        is_admin_static = _is_match(api_key, admin_keys)
        is_admin_store = (
            store_active and isinstance(key_record, dict) and bool(key_record.get("is_admin"))
        )
        if not is_admin_static and not is_admin_store:
            raise HTTPException(status_code=403, detail="Admin API key required")
    elif not static_allowed and not store_active:
        raise HTTPException(status_code=403, detail="Invalid API key")

    scope, default_limit = _rate_limit_scope_for_request(request)
    limit_rpm = _limit_for_scope(
        scope=scope,
        default_limit=default_limit,
        key_record=key_record if store_active else None,
    )
    await _enforce_rate_limit(api_key, scope=scope, limit_rpm=limit_rpm)

    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    if store_active:
        try:
            await touch_api_key_last_used_async(
                backend=settings.RESULT_BACKEND,
                cfg=settings._API_KEY_STORE_CFG,
                key_hash=api_key_hash_value,
                table_client=table_client,
                redis_client=redis_client,
            )
        except Exception:
            pass

    return api_key_hash_value


async def require_api_key(
    request: Request, api_key: Optional[str] = Security(settings.api_key_scheme)
):
    return await _authenticate_api_key(request, api_key, require_admin=False)


async def require_admin_api_key(
    request: Request, api_key: Optional[str] = Security(settings.api_key_scheme)
):
    return await _authenticate_api_key(request, api_key, require_admin=True)
