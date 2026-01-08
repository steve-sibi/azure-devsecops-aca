from __future__ import annotations

import os
import json
from typing import Any, Optional

from azure.core.exceptions import ResourceNotFoundError


def _redis_key(prefix: str, job_id: str) -> str:
    return f"{prefix}{job_id}"


def _json_dumps_compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _truncate_details_for_table(details: dict, *, max_bytes: int) -> dict:
    def _encoded_len(obj: Any) -> int:
        return len(_json_dumps_compact(obj).encode("utf-8"))

    original_size = _encoded_len(details)
    if original_size <= max_bytes:
        return details

    out: dict[str, Any] = {}

    for key in ("url", "canonical_url", "sha256", "length", "engine", "engines"):
        if key in details:
            out[key] = details.get(key)

    decision = details.get("decision")
    if isinstance(decision, dict):
        out["decision"] = decision

    download = details.get("download")
    if isinstance(download, dict):
        dl_out: dict[str, Any] = {}
        for key in (
            "requested_url",
            "final_url",
            "content_type",
            "content_length",
            "blocked",
            "blocked_url",
            "blocked_at_hop",
        ):
            val = download.get(key)
            if val is None or val == "":
                continue
            dl_out[key] = val
        redirects = download.get("redirects")
        if isinstance(redirects, list):
            dl_out["redirect_count"] = len(redirects)
        if dl_out:
            out["download"] = dl_out

    results = details.get("results")
    if isinstance(results, dict):
        out["results"] = results

    signals = details.get("signals")
    if isinstance(signals, list):
        trimmed: list[dict[str, Any]] = []
        for item in signals:
            if not isinstance(item, dict):
                continue
            s_out: dict[str, Any] = {}
            for key in ("source", "verdict", "severity", "weight", "ttl"):
                val = item.get(key)
                if val is None or val == "":
                    continue
                s_out[key] = val
            evidence = item.get("evidence")
            if isinstance(evidence, dict):
                reason = evidence.get("reason")
                if reason is not None and reason != "":
                    s_out["evidence"] = {"reason": str(reason)}
            if s_out:
                trimmed.append(s_out)
            if len(trimmed) >= 20:
                break
        if trimmed:
            out["signals"] = trimmed

    out["_truncated"] = True
    out["_truncated_reason"] = "details_too_large_for_table"
    out["_original_size_bytes"] = original_size

    while _encoded_len(out) > max_bytes:
        sigs = out.get("signals")
        if isinstance(sigs, list) and sigs:
            if len(sigs) > 1:
                out["signals"] = sigs[: max(1, len(sigs) // 2)]
            else:
                out.pop("signals", None)
            continue
        if "results" in out:
            out.pop("results", None)
            continue
        if "download" in out:
            out.pop("download", None)
            continue
        if "decision" in out:
            out.pop("decision", None)
            continue
        out = {k: out[k] for k in ("url", "sha256", "_truncated", "_truncated_reason", "_original_size_bytes") if k in out}
        break

    return out


def _build_table_entity(
    *,
    partition_key: str,
    job_id: str,
    status: str,
    verdict: Optional[str],
    error: Optional[str],
    details: Optional[dict],
    extra: Optional[dict],
    max_details_bytes: Optional[int] = None,
) -> dict[str, Any]:
    entity: dict[str, Any] = {
        "PartitionKey": partition_key,
        "RowKey": job_id,
        "status": status,
        "verdict": verdict or "",
        "error": error or "",
    }
    if details is not None:
        max_bytes = max_details_bytes
        if max_bytes is None:
            max_bytes = int(os.getenv("RESULT_DETAILS_MAX_BYTES", "60000"))
        if max_bytes > 0:
            details = _truncate_details_for_table(details, max_bytes=max_bytes)
        entity["details"] = _json_dumps_compact(details)
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
    max_details_bytes: Optional[int] = None,
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
            max_details_bytes=max_details_bytes,
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
    max_details_bytes: Optional[int] = None,
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
            max_details_bytes=max_details_bytes,
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
