from __future__ import annotations

import json
from typing import Any, Optional

from azure.core.exceptions import ResourceNotFoundError


def _redis_key(prefix: str, job_id: str) -> str:
    return f"{prefix}{job_id}"


def _build_table_entity(
    *,
    partition_key: str,
    job_id: str,
    status: str,
    verdict: Optional[str],
    error: Optional[str],
    details: Optional[dict],
    extra: Optional[dict],
) -> dict[str, Any]:
    entity: dict[str, Any] = {
        "PartitionKey": partition_key,
        "RowKey": job_id,
        "status": status,
        "verdict": verdict or "",
        "error": error or "",
    }
    if details is not None:
        entity["details"] = json.dumps(details)
    if extra:
        entity.update({str(k): v for k, v in extra.items()})
    return entity


def _build_redis_mapping(
    *,
    status: str,
    verdict: Optional[str],
    error: Optional[str],
    details: Optional[dict],
    extra: Optional[dict],
) -> dict[str, Any]:
    mapping: dict[str, Any] = {
        "status": status,
        "verdict": verdict or "",
        "error": error or "",
    }
    if details is not None:
        mapping["details"] = json.dumps(details)
    if extra:
        mapping.update({str(k): v for k, v in extra.items()})
    return mapping


async def upsert_result_async(
    *,
    backend: str,
    partition_key: str,
    job_id: str,
    status: str,
    verdict: Optional[str] = None,
    error: Optional[str] = None,
    details: Optional[dict] = None,
    extra: Optional[dict] = None,
    table_client=None,
    redis_client=None,
    redis_prefix: str = "scan:",
    redis_ttl_seconds: int = 0,
) -> None:
    if backend == "table":
        if not table_client:
            return
        entity = _build_table_entity(
            partition_key=partition_key,
            job_id=job_id,
            status=status,
            verdict=verdict,
            error=error,
            details=details,
            extra=extra,
        )
        await table_client.upsert_entity(entity=entity)
        return

    if backend == "redis":
        if not redis_client:
            return
        key = _redis_key(redis_prefix, job_id)
        mapping = _build_redis_mapping(
            status=status, verdict=verdict, error=error, details=details, extra=extra
        )
        await redis_client.hset(key, mapping=mapping)
        if redis_ttl_seconds > 0:
            await redis_client.expire(key, redis_ttl_seconds)
        return

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {backend}")


async def get_result_async(
    *,
    backend: str,
    partition_key: str,
    job_id: str,
    table_client=None,
    redis_client=None,
    redis_prefix: str = "scan:",
) -> Optional[dict]:
    if backend == "table":
        if not table_client:
            return None
        try:
            return await table_client.get_entity(partition_key=partition_key, row_key=job_id)
        except ResourceNotFoundError:
            return None

    if backend == "redis":
        if not redis_client:
            return None
        key = _redis_key(redis_prefix, job_id)
        data = await redis_client.hgetall(key)
        return data or None

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {backend}")


def upsert_result_sync(
    *,
    backend: str,
    partition_key: str,
    job_id: str,
    status: str,
    verdict: Optional[str] = None,
    error: Optional[str] = None,
    details: Optional[dict] = None,
    extra: Optional[dict] = None,
    table_client=None,
    redis_client=None,
    redis_prefix: str = "scan:",
    redis_ttl_seconds: int = 0,
) -> None:
    if backend == "table":
        if not table_client:
            return
        entity = _build_table_entity(
            partition_key=partition_key,
            job_id=job_id,
            status=status,
            verdict=verdict,
            error=error,
            details=details,
            extra=extra,
        )
        table_client.upsert_entity(entity=entity)
        return

    if backend == "redis":
        if not redis_client:
            return
        key = _redis_key(redis_prefix, job_id)
        mapping = _build_redis_mapping(
            status=status, verdict=verdict, error=error, details=details, extra=extra
        )
        redis_client.hset(key, mapping=mapping)
        if redis_ttl_seconds > 0:
            redis_client.expire(key, redis_ttl_seconds)
        return

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {backend}")


def get_result_sync(
    *,
    backend: str,
    partition_key: str,
    job_id: str,
    table_client=None,
    redis_client=None,
    redis_prefix: str = "scan:",
) -> Optional[dict]:
    if backend == "table":
        if not table_client:
            return None
        try:
            return table_client.get_entity(partition_key=partition_key, row_key=job_id)
        except ResourceNotFoundError:
            return None

    if backend == "redis":
        if not redis_client:
            return None
        key = _redis_key(redis_prefix, job_id)
        data = redis_client.hgetall(key)
        return data or None

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {backend}")

