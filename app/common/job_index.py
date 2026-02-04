from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from common.statuses import ALLOWED_JOB_STATUSES, STATUS_RANKS, TERMINAL_STATUSES


def api_key_hash(api_key: str) -> str:
    return hashlib.sha256((api_key or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class JobIndexConfig:
    partition_prefix: str
    redis_zset_prefix: str
    redis_hash_prefix: str

    @staticmethod
    def from_env() -> "JobIndexConfig":
        partition_prefix = (
            os.getenv("JOB_INDEX_PARTITION_PREFIX", "jobs") or "jobs"
        ).strip()
        redis_zset_prefix = (
            os.getenv("REDIS_JOB_INDEX_ZSET_PREFIX", "jobsidx:") or "jobsidx:"
        ).strip()
        redis_hash_prefix = (
            os.getenv("REDIS_JOB_INDEX_HASH_PREFIX", "jobs:") or "jobs:"
        ).strip()
        return JobIndexConfig(
            partition_prefix=partition_prefix or "jobs",
            redis_zset_prefix=redis_zset_prefix or "jobsidx:",
            redis_hash_prefix=redis_hash_prefix or "jobs:",
        )


_CFG = JobIndexConfig.from_env()

# Year ~2286 in epoch ms; large enough for our sorting trick.
_MAX_EPOCH_MS = 9999999999999


def job_index_partition_key(*, api_key_hash_value: str) -> str:
    return f"{_CFG.partition_prefix}:{api_key_hash_value}"


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


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _invert_epoch_ms(epoch_ms: int) -> int:
    ms = int(epoch_ms or 0)
    if ms < 0:
        ms = 0
    if ms > _MAX_EPOCH_MS:
        ms = _MAX_EPOCH_MS
    return _MAX_EPOCH_MS - ms


def job_index_row_key(*, submitted_at: str, job_id: str) -> str:
    ts = _parse_dt(submitted_at) or datetime.now(timezone.utc)
    inv = _invert_epoch_ms(_epoch_ms(ts))
    return f"{inv:013d}:{job_id}"


def _status_rank(status: Optional[str]) -> int:
    key = (status or "").strip().lower()
    return STATUS_RANKS.get(key, 0)


def _coerce_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _should_skip_regression(
    *, existing: Optional[dict[str, Any]], new_status: str, new_rank: int
) -> bool:
    if not isinstance(existing, dict) or not existing:
        return False
    existing_status = str(existing.get("status") or "").strip().lower()
    existing_rank = _coerce_int(
        existing.get("status_rank"), default=_status_rank(existing_status)
    )

    # Never regress status, and never overwrite a terminal status with a different terminal status.
    if existing_status in TERMINAL_STATUSES and new_status != existing_status:
        return True
    return new_rank < existing_rank


def build_job_index_record(
    *,
    api_key_hash_value: str,
    job_id: str,
    submitted_at: str,
    status: str,
    url: Optional[str] = None,
    scanned_at: Optional[str] = None,
    updated_at: Optional[str] = None,
    correlation_id: Optional[str] = None,
    error: Optional[str] = None,
) -> dict[str, Any]:
    submitted = (submitted_at or "").strip() or datetime.now(timezone.utc).isoformat()
    record: dict[str, Any] = {
        "PartitionKey": job_index_partition_key(api_key_hash_value=api_key_hash_value),
        "RowKey": job_index_row_key(submitted_at=submitted, job_id=job_id),
        "job_id": job_id,
        "status": (status or "").strip().lower(),
        "submitted_at": submitted,
        "scanned_at": (scanned_at or "").strip(),
        "updated_at": (updated_at or "").strip()
        or datetime.now(timezone.utc).isoformat(),
        "url": (url or "").strip(),
        "error": (error or "").strip(),
        "correlation_id": (correlation_id or "").strip(),
    }
    record["status_rank"] = _status_rank(record["status"])
    return record


def _redis_zset_key(*, api_key_hash_value: str) -> str:
    return f"{_CFG.redis_zset_prefix}{api_key_hash_value}"


def _redis_hash_key(*, api_key_hash_value: str, job_id: str) -> str:
    return f"{_CFG.redis_hash_prefix}{api_key_hash_value}:{job_id}"


async def upsert_job_index_record_async(
    *,
    backend: str,
    api_key_hash_value: str,
    record: dict[str, Any],
    table_client=None,
    redis_client=None,
    redis_ttl_seconds: int = 0,
) -> bool:
    if backend == "table":
        if not table_client:
            return False
        new_status = str(record.get("status") or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = await table_client.get_entity(
                partition_key=record["PartitionKey"], row_key=record["RowKey"]
            )
        except Exception:
            existing = None
        if _should_skip_regression(
            existing=existing, new_status=new_status, new_rank=new_rank
        ):
            return True
        try:
            await table_client.upsert_entity(entity=record)
            return True
        except Exception:
            return False

    if backend == "redis":
        if not redis_client:
            return False
        zkey = _redis_zset_key(api_key_hash_value=api_key_hash_value)
        hkey = _redis_hash_key(
            api_key_hash_value=api_key_hash_value,
            job_id=str(record.get("job_id") or ""),
        )

        new_status = str(record.get("status") or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = await redis_client.hgetall(hkey)
        except Exception:
            existing = None
        if _should_skip_regression(
            existing=existing, new_status=new_status, new_rank=new_rank
        ):
            return True
        try:
            await redis_client.hset(
                hkey,
                mapping={k: "" if v is None else str(v) for k, v in record.items()},
            )
            # Use submitted_at (or updated_at) as score (epoch ms) for ordering.
            ts = (
                _parse_dt(record.get("submitted_at"))
                or _parse_dt(record.get("updated_at"))
                or datetime.now(timezone.utc)
            )
            score = _epoch_ms(ts)
            await redis_client.zadd(zkey, {str(record.get("job_id") or ""): score})
            ttl = int(redis_ttl_seconds or 0)
            if ttl > 0:
                await redis_client.expire(hkey, ttl)
                await redis_client.expire(zkey, ttl)
            return True
        except Exception:
            return False

    raise RuntimeError(f"Unsupported backend: {backend}")


def upsert_job_index_record_sync(
    *,
    backend: str,
    api_key_hash_value: str,
    record: dict[str, Any],
    table_client=None,
    redis_client=None,
    redis_ttl_seconds: int = 0,
) -> bool:
    if backend == "table":
        if not table_client:
            return False
        new_status = str(record.get("status") or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = table_client.get_entity(
                partition_key=record["PartitionKey"], row_key=record["RowKey"]
            )
        except Exception:
            existing = None
        if _should_skip_regression(
            existing=existing, new_status=new_status, new_rank=new_rank
        ):
            return True
        try:
            table_client.upsert_entity(entity=record)
            return True
        except Exception:
            return False

    if backend == "redis":
        if not redis_client:
            return False
        zkey = _redis_zset_key(api_key_hash_value=api_key_hash_value)
        hkey = _redis_hash_key(
            api_key_hash_value=api_key_hash_value,
            job_id=str(record.get("job_id") or ""),
        )

        new_status = str(record.get("status") or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = redis_client.hgetall(hkey)
        except Exception:
            existing = None
        if _should_skip_regression(
            existing=existing, new_status=new_status, new_rank=new_rank
        ):
            return True
        try:
            redis_client.hset(
                hkey,
                mapping={k: "" if v is None else str(v) for k, v in record.items()},
            )
            ts = (
                _parse_dt(record.get("submitted_at"))
                or _parse_dt(record.get("updated_at"))
                or datetime.now(timezone.utc)
            )
            score = _epoch_ms(ts)
            redis_client.zadd(zkey, {str(record.get("job_id") or ""): score})
            ttl = int(redis_ttl_seconds or 0)
            if ttl > 0:
                redis_client.expire(hkey, ttl)
                redis_client.expire(zkey, ttl)
            return True
        except Exception:
            return False

    raise RuntimeError(f"Unsupported backend: {backend}")


async def list_jobs_async(
    *,
    backend: str,
    api_key_hash_value: str,
    limit: int,
    statuses: Optional[list[str]] = None,
    table_client=None,
    redis_client=None,
) -> list[dict[str, Any]]:
    statuses_norm = [s.strip().lower() for s in (statuses or []) if s and s.strip()]
    limit_n = max(1, int(limit or 0))

    if backend == "table":
        if not table_client:
            return []
        pk = job_index_partition_key(api_key_hash_value=api_key_hash_value)
        filt = f"PartitionKey eq '{pk}'"
        if statuses_norm:
            clauses = [f"status eq '{s}'" for s in statuses_norm]
            filt = f"({filt}) and ({' or '.join(clauses)})"

        out: list[dict[str, Any]] = []
        try:
            pager = table_client.query_entities(
                query_filter=filt, results_per_page=min(200, limit_n)
            )
            async for entity in pager:
                out.append(entity)
                if len(out) >= limit_n:
                    break
        except Exception:
            return out
        return out

    if backend == "redis":
        if not redis_client:
            return []
        zkey = _redis_zset_key(api_key_hash_value=api_key_hash_value)
        try:
            job_ids = await redis_client.zrevrange(zkey, 0, limit_n - 1)
        except Exception:
            return []
        out: list[dict[str, Any]] = []
        for jid in job_ids:
            hkey = _redis_hash_key(
                api_key_hash_value=api_key_hash_value, job_id=str(jid)
            )
            try:
                data = await redis_client.hgetall(hkey)
            except Exception:
                data = None
            if not data:
                continue
            st = str(data.get("status") or "").strip().lower()
            if statuses_norm and st not in statuses_norm:
                continue
            out.append(data)
        return out

    raise RuntimeError(f"Unsupported backend: {backend}")
