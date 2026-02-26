from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from common.api_keys import (
    api_key_is_active,
    build_api_key_record,
    get_api_key_record_async,
    list_api_key_records_async,
    revoke_api_key_async,
    upsert_api_key_record_async,
)
from common.job_index import api_key_hash as hash_api_key
from fastapi import APIRouter, HTTPException, Query, Request, Security

import runtime
import settings
from deps.auth import _require_api_key_store_ready, require_admin_api_key
from deps.store import _coerce_positive_int
from models import ApiKeyMintRequest

router = APIRouter()


def _mint_api_key_plaintext() -> str:
    token = secrets.token_urlsafe(settings._API_KEY_MINT_BYTES)
    prefix = (settings._API_KEY_MINT_PREFIX or "").strip().strip("_-")
    if not prefix:
        return token
    return f"{prefix}_{token}"


def _expires_at_from_ttl_days(ttl_days: Optional[int]) -> str:
    days = _coerce_positive_int(ttl_days)
    if days is None:
        return ""
    expiry = datetime.now(timezone.utc) + timedelta(days=days)
    return expiry.isoformat()


def _is_sha256_hex(value: str) -> bool:
    raw = str(value or "").strip().lower()
    if len(raw) != 64:
        return False
    return all(c in "0123456789abcdef" for c in raw)


@router.get("/admin/api-keys", tags=["Admin"], summary="List API keys")
async def admin_list_api_keys(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    include_inactive: bool = Query(
        False, description="Include revoked or expired keys"
    ),
    _: Optional[str] = Security(require_admin_api_key),
):
    _require_api_key_store_ready(request=request)
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    prefetch_limit = min(2000, max(int(limit or 0), int(limit or 0) * 3))
    records = await list_api_key_records_async(
        backend=settings.RESULT_BACKEND,
        cfg=settings._API_KEY_STORE_CFG,
        limit=prefetch_limit,
        table_client=table_client,
        redis_client=redis_client,
    )
    keys: list[dict] = []
    for rec in records:
        active = api_key_is_active(rec)
        if not include_inactive and not active:
            continue
        keys.append(
            {
                "key_hash": rec.get("key_hash"),
                "key_id": rec.get("key_id"),
                "label": rec.get("label") or None,
                "created_at": rec.get("created_at"),
                "created_by_hash": rec.get("created_by_hash") or None,
                "last_used_at": rec.get("last_used_at") or None,
                "expires_at": rec.get("expires_at") or None,
                "read_rpm": rec.get("read_rpm"),
                "write_rpm": rec.get("write_rpm"),
                "is_admin": bool(rec.get("is_admin")),
                "revoked": bool(rec.get("revoked")),
                "revoked_at": rec.get("revoked_at") or None,
                "active": active,
            }
        )
        if len(keys) >= int(limit or 0):
            break
    return {
        "keys": keys,
        "count": len(keys),
        "include_inactive": bool(include_inactive),
    }


@router.post("/admin/api-keys", tags=["Admin"], summary="Mint an API key")
async def admin_mint_api_key(
    request: Request,
    req: ApiKeyMintRequest,
    admin_api_key_hash: Optional[str] = Security(require_admin_api_key),
):
    _require_api_key_store_ready(request=request)
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)

    plaintext_key = ""
    key_hash = ""
    for _ in range(10):
        candidate = _mint_api_key_plaintext()
        candidate_hash = hash_api_key(candidate)
        existing = await get_api_key_record_async(
            backend=settings.RESULT_BACKEND,
            cfg=settings._API_KEY_STORE_CFG,
            key_hash=candidate_hash,
            table_client=table_client,
            redis_client=redis_client,
        )
        if not existing:
            plaintext_key = candidate
            key_hash = candidate_hash
            break
    if not plaintext_key or not key_hash:
        raise HTTPException(status_code=500, detail="Unable to mint a unique API key")

    now = datetime.now(timezone.utc).isoformat()
    record = build_api_key_record(
        cfg=settings._API_KEY_STORE_CFG,
        key_hash=key_hash,
        label=(req.label or "").strip(),
        created_at=now,
        created_by_hash=admin_api_key_hash or "",
        read_rpm=req.read_rpm,
        write_rpm=req.write_rpm,
        expires_at=_expires_at_from_ttl_days(req.ttl_days),
        is_admin=bool(req.is_admin),
    )
    ok = await upsert_api_key_record_async(
        backend=settings.RESULT_BACKEND,
        cfg=settings._API_KEY_STORE_CFG,
        record=record,
        table_client=table_client,
        redis_client=redis_client,
    )
    if not ok:
        raise HTTPException(status_code=503, detail="Failed to persist API key")

    return {
        "api_key": plaintext_key,
        "key_hash": key_hash,
        "key_id": record.get("key_id"),
        "label": record.get("label") or None,
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at") or None,
        "read_rpm": _coerce_positive_int(record.get("read_rpm")),
        "write_rpm": _coerce_positive_int(record.get("write_rpm")),
        "is_admin": bool(record.get("is_admin")),
    }


@router.post(
    "/admin/api-keys/{key_hash}/revoke",
    tags=["Admin"],
    summary="Revoke an API key",
)
async def admin_revoke_api_key(
    request: Request,
    key_hash: str,
    _: Optional[str] = Security(require_admin_api_key),
):
    _require_api_key_store_ready(request=request)
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)
    key_hash_norm = str(key_hash or "").strip().lower()
    if not _is_sha256_hex(key_hash_norm):
        raise HTTPException(
            status_code=400, detail="key_hash must be a 64-character sha256 hex digest"
        )

    existing = await get_api_key_record_async(
        backend=settings.RESULT_BACKEND,
        cfg=settings._API_KEY_STORE_CFG,
        key_hash=key_hash_norm,
        table_client=table_client,
        redis_client=redis_client,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="API key not found")

    if bool(existing.get("revoked")):
        return {
            "key_hash": key_hash_norm,
            "revoked": True,
            "revoked_at": existing.get("revoked_at") or None,
            "active": False,
        }

    ok = await revoke_api_key_async(
        backend=settings.RESULT_BACKEND,
        cfg=settings._API_KEY_STORE_CFG,
        key_hash=key_hash_norm,
        table_client=table_client,
        redis_client=redis_client,
    )
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to revoke API key")

    return {
        "key_hash": key_hash_norm,
        "revoked": True,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "active": False,
    }
