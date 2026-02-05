from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from azure.core.exceptions import ResourceNotFoundError


@dataclass(frozen=True)
class ApiKeyStoreConfig:
    table_partition: str
    redis_prefix: str
    redis_index_key: str

    @staticmethod
    def from_env() -> "ApiKeyStoreConfig":
        table_partition = (
            os.getenv("API_KEY_STORE_PARTITION", "apikeys") or "apikeys"
        ).strip()
        redis_prefix = (
            os.getenv("REDIS_API_KEY_PREFIX", "apikey:") or "apikey:"
        ).strip()
        redis_index_key = (
            os.getenv("REDIS_API_KEY_INDEX_KEY", "apikeys:index") or "apikeys:index"
        ).strip()
        return ApiKeyStoreConfig(
            table_partition=table_partition or "apikeys",
            redis_prefix=redis_prefix or "apikey:",
            redis_index_key=redis_index_key or "apikeys:index",
        )


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8", "replace")
        except Exception:
            return str(value)
    return str(value)


def _coerce_bool(value: Any, *, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(int(value))
    s = _as_str(value).strip().lower()
    if s in ("1", "true", "yes", "y", "on"):
        return True
    if s in ("0", "false", "no", "n", "off"):
        return False
    return default


def _coerce_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        out = int(value)
    except Exception:
        try:
            out = int(_as_str(value).strip())
        except Exception:
            return None
    return out


def _parse_iso(value: Any) -> Optional[datetime]:
    raw = _as_str(value).strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_hash(key_hash: str) -> str:
    h = _as_str(key_hash).strip().lower()
    if len(h) != 64:
        return ""
    if any(ch not in "0123456789abcdef" for ch in h):
        return ""
    return h


def build_api_key_record(
    *,
    cfg: ApiKeyStoreConfig,
    key_hash: str,
    label: Optional[str] = None,
    key_id: Optional[str] = None,
    created_at: Optional[str] = None,
    created_by_hash: Optional[str] = None,
    read_rpm: Optional[int] = None,
    write_rpm: Optional[int] = None,
    expires_at: Optional[str] = None,
    is_admin: bool = False,
) -> dict[str, Any]:
    norm_hash = _normalize_hash(key_hash)
    if not norm_hash:
        raise ValueError("key_hash must be a 64-char sha256 hex digest")

    created = _as_str(created_at).strip() or _iso_now()
    read_quota = _coerce_int(read_rpm)
    write_quota = _coerce_int(write_rpm)
    out: dict[str, Any] = {
        "PartitionKey": cfg.table_partition,
        "RowKey": norm_hash,
        "key_hash": norm_hash,
        "key_id": (_as_str(key_id).strip() or str(uuid4())),
        "label": _as_str(label).strip(),
        "created_at": created,
        "created_by_hash": _as_str(created_by_hash).strip().lower(),
        "read_rpm": read_quota if isinstance(read_quota, int) and read_quota > 0 else 0,
        "write_rpm": write_quota
        if isinstance(write_quota, int) and write_quota > 0
        else 0,
        "expires_at": _as_str(expires_at).strip(),
        "revoked": False,
        "revoked_at": "",
        "last_used_at": "",
        "is_admin": bool(is_admin),
    }
    return out


def normalize_api_key_record(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    key_hash = _normalize_hash(raw.get("key_hash") or raw.get("RowKey") or "")
    if not key_hash:
        return None
    read_rpm = _coerce_int(raw.get("read_rpm"))
    write_rpm = _coerce_int(raw.get("write_rpm"))
    out: dict[str, Any] = {
        "key_hash": key_hash,
        "key_id": _as_str(raw.get("key_id")).strip(),
        "label": _as_str(raw.get("label")).strip(),
        "created_at": _as_str(raw.get("created_at")).strip(),
        "created_by_hash": _as_str(raw.get("created_by_hash")).strip().lower(),
        "read_rpm": read_rpm if isinstance(read_rpm, int) and read_rpm > 0 else None,
        "write_rpm": write_rpm
        if isinstance(write_rpm, int) and write_rpm > 0
        else None,
        "expires_at": _as_str(raw.get("expires_at")).strip(),
        "revoked": _coerce_bool(raw.get("revoked"), default=False),
        "revoked_at": _as_str(raw.get("revoked_at")).strip(),
        "last_used_at": _as_str(raw.get("last_used_at")).strip(),
        "is_admin": _coerce_bool(raw.get("is_admin"), default=False),
    }
    if not out["key_id"]:
        out["key_id"] = key_hash[:12]
    if not out["created_at"]:
        out["created_at"] = _iso_now()
    return out


def api_key_is_active(
    record: Optional[dict[str, Any]],
    *,
    now: Optional[datetime] = None,
) -> bool:
    if not isinstance(record, dict):
        return False
    if _coerce_bool(record.get("revoked"), default=False):
        return False
    expires_at = _parse_iso(record.get("expires_at"))
    if expires_at is None:
        return True
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)
    return expires_at > current


def _redis_key(cfg: ApiKeyStoreConfig, key_hash: str) -> str:
    return f"{cfg.redis_prefix}{key_hash}"


async def get_api_key_record_async(
    *,
    backend: str,
    cfg: ApiKeyStoreConfig,
    key_hash: str,
    table_client=None,
    redis_client=None,
) -> Optional[dict[str, Any]]:
    norm_hash = _normalize_hash(key_hash)
    if not norm_hash:
        return None

    if backend == "table":
        if not table_client:
            return None
        try:
            entity = await table_client.get_entity(
                partition_key=cfg.table_partition,
                row_key=norm_hash,
            )
        except ResourceNotFoundError:
            return None
        except Exception:
            return None
        return normalize_api_key_record(entity)

    if backend == "redis":
        if not redis_client:
            return None
        try:
            data = await redis_client.hgetall(_redis_key(cfg, norm_hash))
        except Exception:
            return None
        return normalize_api_key_record(data or None)

    raise RuntimeError(f"Unsupported backend: {backend}")


async def upsert_api_key_record_async(
    *,
    backend: str,
    cfg: ApiKeyStoreConfig,
    record: dict[str, Any],
    table_client=None,
    redis_client=None,
) -> bool:
    normalized = normalize_api_key_record(record)
    if not normalized:
        return False

    if backend == "table":
        if not table_client:
            return False
        entity = dict(record)
        entity.setdefault("PartitionKey", cfg.table_partition)
        entity.setdefault("RowKey", normalized["key_hash"])
        await table_client.upsert_entity(entity=entity)
        return True

    if backend == "redis":
        if not redis_client:
            return False
        mapping = {
            "key_hash": normalized["key_hash"],
            "key_id": normalized["key_id"],
            "label": normalized["label"],
            "created_at": normalized["created_at"],
            "created_by_hash": normalized["created_by_hash"],
            "read_rpm": ""
            if normalized["read_rpm"] is None
            else str(normalized["read_rpm"]),
            "write_rpm": ""
            if normalized["write_rpm"] is None
            else str(normalized["write_rpm"]),
            "expires_at": normalized["expires_at"],
            "revoked": "1" if normalized["revoked"] else "0",
            "revoked_at": normalized["revoked_at"],
            "last_used_at": normalized["last_used_at"],
            "is_admin": "1" if normalized["is_admin"] else "0",
        }
        key = _redis_key(cfg, normalized["key_hash"])
        await redis_client.hset(key, mapping=mapping)
        await redis_client.sadd(cfg.redis_index_key, normalized["key_hash"])
        return True

    raise RuntimeError(f"Unsupported backend: {backend}")


async def list_api_key_records_async(
    *,
    backend: str,
    cfg: ApiKeyStoreConfig,
    limit: int = 200,
    table_client=None,
    redis_client=None,
) -> list[dict[str, Any]]:
    limit_n = max(1, int(limit or 0))
    out: list[dict[str, Any]] = []

    if backend == "table":
        if not table_client:
            return []
        safe_partition = cfg.table_partition.replace("'", "''")
        filt = f"PartitionKey eq '{safe_partition}'"
        try:
            pager = table_client.query_entities(
                query_filter=filt, results_per_page=min(200, limit_n)
            )
            async for entity in pager:
                rec = normalize_api_key_record(entity)
                if rec:
                    out.append(rec)
                if len(out) >= limit_n:
                    break
        except Exception:
            return []
    elif backend == "redis":
        if not redis_client:
            return []
        try:
            key_hashes = await redis_client.smembers(cfg.redis_index_key)
        except Exception:
            key_hashes = []
        key_hashes_norm: list[str] = []
        for item in key_hashes or []:
            h = _normalize_hash(item)
            if h:
                key_hashes_norm.append(h)
        key_hashes_norm = key_hashes_norm[: max(limit_n * 3, limit_n)]
        if key_hashes_norm:
            try:
                pipe = redis_client.pipeline()
                for h in key_hashes_norm:
                    pipe.hgetall(_redis_key(cfg, h))
                rows = await pipe.execute()
            except Exception:
                rows = []
            for row in rows or []:
                rec = normalize_api_key_record(row)
                if rec:
                    out.append(rec)
                if len(out) >= limit_n:
                    break
    else:
        raise RuntimeError(f"Unsupported backend: {backend}")

    out.sort(key=lambda r: _as_str(r.get("created_at")), reverse=True)
    return out[:limit_n]


async def touch_api_key_last_used_async(
    *,
    backend: str,
    cfg: ApiKeyStoreConfig,
    key_hash: str,
    table_client=None,
    redis_client=None,
) -> bool:
    norm_hash = _normalize_hash(key_hash)
    if not norm_hash:
        return False
    ts = _iso_now()

    if backend == "table":
        if not table_client:
            return False
        try:
            await table_client.upsert_entity(
                entity={
                    "PartitionKey": cfg.table_partition,
                    "RowKey": norm_hash,
                    "last_used_at": ts,
                }
            )
            return True
        except Exception:
            return False

    if backend == "redis":
        if not redis_client:
            return False
        try:
            await redis_client.hset(
                _redis_key(cfg, norm_hash), mapping={"last_used_at": ts}
            )
            return True
        except Exception:
            return False

    raise RuntimeError(f"Unsupported backend: {backend}")


async def revoke_api_key_async(
    *,
    backend: str,
    cfg: ApiKeyStoreConfig,
    key_hash: str,
    table_client=None,
    redis_client=None,
) -> bool:
    record = await get_api_key_record_async(
        backend=backend,
        cfg=cfg,
        key_hash=key_hash,
        table_client=table_client,
        redis_client=redis_client,
    )
    if not record:
        return False
    ts = _iso_now()
    record["revoked"] = True
    record["revoked_at"] = ts
    return await upsert_api_key_record_async(
        backend=backend,
        cfg=cfg,
        record=record,
        table_client=table_client,
        redis_client=redis_client,
    )
