"""
URL dedupe cache helpers.

This is a best-effort cache for URL scans: within a configurable TTL window, the API
can reuse results for the same canonical URL instead of re-scanning.

The cache can be global or API-key scoped (see `URL_DEDUPE_SCOPE`). "Private" scans
never populate the shared cache.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from common.url_canonicalization import canonicalize_url

_TERMINAL_STATUSES = {"completed", "error"}


def _sha256_hex(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def canonical_url_for_dedupe(url: str) -> str:
    return canonicalize_url(url).canonical


@dataclass(frozen=True)
class UrlDedupeConfig:
    ttl_seconds: int
    in_progress_ttl_seconds: int
    scope: str
    index_partition: str
    redis_prefix: str

    @property
    def enabled(self) -> bool:
        return self.ttl_seconds > 0 or self.in_progress_ttl_seconds > 0

    @staticmethod
    def from_env() -> "UrlDedupeConfig":
        ttl_seconds = int(os.getenv("URL_DEDUPE_TTL_SECONDS", "0") or "0")
        in_progress_ttl_seconds = int(
            os.getenv("URL_DEDUPE_IN_PROGRESS_TTL_SECONDS", "0") or "0"
        )
        scope = (os.getenv("URL_DEDUPE_SCOPE", "global") or "global").strip().lower()
        if scope not in ("apikey", "global"):
            scope = "global"

        index_partition = (
            os.getenv("URL_DEDUPE_INDEX_PARTITION", "urlidx") or "urlidx"
        ).strip()
        redis_prefix = (os.getenv("REDIS_URL_INDEX_PREFIX", "urlidx:") or "urlidx:").strip()

        return UrlDedupeConfig(
            ttl_seconds=max(0, ttl_seconds),
            in_progress_ttl_seconds=max(0, in_progress_ttl_seconds),
            scope=scope,
            index_partition=index_partition or "urlidx",
            redis_prefix=redis_prefix or "urlidx:",
        )


@dataclass(frozen=True)
class UrlIndexKey:
    partition_key: str
    row_key: str
    canonical_url: str


def make_url_index_key(
    *,
    url: str,
    api_key_hash: Optional[str],
    cfg: UrlDedupeConfig,
) -> UrlIndexKey:
    canonical_url = canonical_url_for_dedupe(url)
    row_key = _sha256_hex(canonical_url)
    partition_key = cfg.index_partition
    if cfg.scope == "apikey" and api_key_hash:
        partition_key = f"{partition_key}:{str(api_key_hash).strip()}"
    return UrlIndexKey(
        partition_key=partition_key,
        row_key=row_key,
        canonical_url=canonical_url,
    )


def _parse_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)
    except Exception:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def url_index_entry_is_fresh(
    entry: Optional[dict[str, Any]],
    *,
    now: Optional[datetime] = None,
    cfg: UrlDedupeConfig,
) -> bool:
    if not isinstance(entry, dict) or not entry:
        return False

    status = str(entry.get("status") or "").strip().lower()
    ts = (
        _parse_dt(entry.get("updated_at"))
        or _parse_dt(entry.get("scanned_at"))
        or _parse_dt(entry.get("submitted_at"))
    )
    if not ts:
        return False

    if now is None:
        now = datetime.now(timezone.utc)

    ttl = cfg.ttl_seconds if status in _TERMINAL_STATUSES else cfg.in_progress_ttl_seconds
    if ttl <= 0:
        return False
    age_seconds = (now - ts).total_seconds()
    return 0 <= age_seconds <= ttl


def build_url_index_record(
    *,
    key: UrlIndexKey,
    job_id: str,
    status: str,
    submitted_at: Optional[str],
    scanned_at: Optional[str],
    updated_at: Optional[str] = None,
) -> dict[str, Any]:
    updated = (updated_at or "").strip() or datetime.now(timezone.utc).isoformat()
    return {
        "PartitionKey": key.partition_key,
        "RowKey": key.row_key,
        "job_id": job_id,
        "status": status,
        "canonical_url": key.canonical_url,
        "submitted_at": (submitted_at or "").strip(),
        "scanned_at": (scanned_at or "").strip(),
        "updated_at": updated,
    }


def redis_url_index_key(*, cfg: UrlDedupeConfig, key: UrlIndexKey) -> str:
    return f"{cfg.redis_prefix}{key.partition_key}:{key.row_key}"


def _is_table_not_found(exc: Exception) -> bool:
    # Avoid importing azure.core at module import time (tests may run without it).
    name = exc.__class__.__name__
    if name == "ResourceNotFoundError":
        return True
    status = getattr(exc, "status_code", None)
    if status == 404:
        return True
    return False


def _extract_etag(entity: Any) -> Optional[str]:
    if isinstance(entity, dict):
        for k in ("etag", "odata.etag", "@odata.etag"):
            v = entity.get(k)
            if isinstance(v, str) and v:
                return v
        meta = entity.get("metadata")
        if isinstance(meta, dict):
            v = meta.get("etag")
            if isinstance(v, str) and v:
                return v

    meta = getattr(entity, "metadata", None)
    if isinstance(meta, dict):
        v = meta.get("etag")
        if isinstance(v, str) and v:
            return v

    etag = getattr(entity, "etag", None)
    if isinstance(etag, str) and etag:
        return etag
    return None


async def get_url_index_entry_async(
    *,
    backend: str,
    cfg: UrlDedupeConfig,
    key: UrlIndexKey,
    table_client=None,
    redis_client=None,
) -> Optional[dict[str, Any]]:
    if backend == "table":
        if not table_client:
            return None
        try:
            return await table_client.get_entity(
                partition_key=key.partition_key, row_key=key.row_key
            )
        except Exception as e:
            if _is_table_not_found(e):
                return None
            return None

    if backend == "redis":
        if not redis_client:
            return None
        k = redis_url_index_key(cfg=cfg, key=key)
        try:
            data = await redis_client.hgetall(k)
        except Exception:
            return None
        return data or None

    raise RuntimeError(f"Unsupported backend: {backend}")

def _redis_ttl_for_status(*, cfg: UrlDedupeConfig, status: str, result_ttl_seconds: int) -> int:
    ttl = cfg.ttl_seconds if status in _TERMINAL_STATUSES else cfg.in_progress_ttl_seconds
    ttl = int(ttl or 0)
    if ttl <= 0:
        return 0
    result_ttl_seconds = int(result_ttl_seconds or 0)
    if result_ttl_seconds > 0:
        return min(ttl, result_ttl_seconds)
    return ttl


async def upsert_url_index_entry_async(
    *,
    backend: str,
    cfg: UrlDedupeConfig,
    key: UrlIndexKey,
    record: dict[str, Any],
    table_client=None,
    redis_client=None,
    result_ttl_seconds: int = 0,
) -> bool:
    if backend == "table":
        if not table_client:
            return False
        try:
            await table_client.upsert_entity(entity=record)
            return True
        except Exception:
            return False

    if backend == "redis":
        if not redis_client:
            return False
        k = redis_url_index_key(cfg=cfg, key=key)
        try:
            await redis_client.hset(k, mapping=record)
            ttl = _redis_ttl_for_status(
                cfg=cfg, status=str(record.get("status") or ""), result_ttl_seconds=result_ttl_seconds
            )
            if ttl > 0:
                await redis_client.expire(k, ttl)
            return True
        except Exception:
            return False

    raise RuntimeError(f"Unsupported backend: {backend}")

_REDIS_CONDITIONAL_UPDATE_LUA = r"""
local key = KEYS[1]
local expected = ARGV[1]
local ttl = tonumber(ARGV[2])

local cur = redis.call('HGET', key, 'job_id')
if (not cur) or cur ~= expected then
  return 0
end

for i = 3, #ARGV, 2 do
  redis.call('HSET', key, ARGV[i], ARGV[i + 1])
end

if ttl and ttl > 0 then
  redis.call('EXPIRE', key, ttl)
end

return 1
"""

def update_url_index_if_job_matches_sync(
    *,
    backend: str,
    cfg: UrlDedupeConfig,
    key: UrlIndexKey,
    expected_job_id: str,
    fields: dict[str, Any],
    table_client=None,
    redis_client=None,
    result_ttl_seconds: int = 0,
) -> bool:
    if backend == "table":
        if not table_client:
            return False
        try:
            existing = table_client.get_entity(
                partition_key=key.partition_key, row_key=key.row_key
            )
        except Exception as e:
            if _is_table_not_found(e):
                return False
            return False

        if str(existing.get("job_id") or "") != str(expected_job_id or ""):
            return False

        etag = _extract_etag(existing)
        if not etag:
            return False

        # Only send the fields we want to merge. The entity returned by get_entity may
        # include metadata keys (e.g., @odata.etag / metadata) that are not valid
        # Table Storage properties and can cause update_entity to fail.
        entity: dict[str, Any] = {"PartitionKey": key.partition_key, "RowKey": key.row_key}
        entity.update({str(k): v for k, v in fields.items()})

        try:
            from azure.core.match_conditions import MatchConditions
            from azure.data.tables import UpdateMode

            table_client.update_entity(
                entity=entity,
                mode=UpdateMode.MERGE,
                etag=etag,
                match_condition=MatchConditions.IfNotModified,
            )
            return True
        except Exception:
            return False

    if backend == "redis":
        if not redis_client:
            return False
        k = redis_url_index_key(cfg=cfg, key=key)
        ttl = _redis_ttl_for_status(
            cfg=cfg, status=str(fields.get("status") or ""), result_ttl_seconds=result_ttl_seconds
        )
        args: list[str] = [str(expected_job_id), str(int(ttl or 0))]
        for fk, fv in fields.items():
            args.append(str(fk))
            args.append("" if fv is None else str(fv))
        try:
            updated = redis_client.eval(_REDIS_CONDITIONAL_UPDATE_LUA, 1, k, *args)
            return int(updated or 0) == 1
        except Exception:
            return False

    raise RuntimeError(f"Unsupported backend: {backend}")
