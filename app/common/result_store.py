from __future__ import annotations

import json
from typing import Any, Optional

from azure.core.exceptions import ResourceNotFoundError

from common.limits import get_result_store_limits

def _redis_key(prefix: str, job_id: str) -> str:
    return f"{prefix}{job_id}"


_STATUS_RANKS: dict[str, int] = {
    "queued": 10,
    "fetching": 20,
    "queued_scan": 30,
    "retrying": 40,
    # terminal
    "completed": 100,
    "error": 100,
}

_TERMINAL_STATUSES = {"completed", "error"}


def _status_rank(status: Optional[str]) -> int:
    key = (status or "").strip().lower()
    return _STATUS_RANKS.get(key, 0)


def _coerce_int(value: Any, *, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _should_skip_regression(
    *, existing: Optional[dict], new_status: str, new_rank: int
) -> bool:
    if not isinstance(existing, dict) or not existing:
        return False
    existing_status = str(existing.get("status") or "").strip().lower()
    existing_rank = _coerce_int(existing.get("status_rank"), default=_status_rank(existing_status))

    # Never regress status, and never overwrite a terminal status with a different terminal status.
    if existing_status in _TERMINAL_STATUSES and new_status != existing_status:
        return True
    return new_rank < existing_rank


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
            "status_code",
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
        response_headers = download.get("response_headers")
        if isinstance(response_headers, list):
            trimmed_headers: list[dict[str, Any]] = []
            for item in response_headers:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                value = item.get("value")
                if not isinstance(name, str) or not name.strip():
                    continue
                if value is None:
                    continue
                v = str(value)
                if len(v) > 320:
                    v = v[:317] + "..."
                trimmed_headers.append({"name": name.strip().lower(), "value": v})
                if len(trimmed_headers) >= 25:
                    break
            if trimmed_headers:
                dl_out["response_headers"] = trimmed_headers
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
            max_bytes = get_result_store_limits().details_max_bytes
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
        new_status = str(status or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = await table_client.get_entity(partition_key=partition_key, row_key=job_id)
        except ResourceNotFoundError:
            existing = None
        except Exception:
            existing = None
        if _should_skip_regression(existing=existing, new_status=new_status, new_rank=new_rank):
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
        entity["status_rank"] = new_rank
        await table_client.upsert_entity(entity=entity)
        return

    if backend == "redis":
        if not redis_client:
            return
        key = _redis_key(redis_prefix, job_id)
        new_status = str(status or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = await redis_client.hgetall(key)
        except Exception:
            existing = None
        if _should_skip_regression(existing=existing, new_status=new_status, new_rank=new_rank):
            return
        mapping = _build_redis_mapping(
            status=status, verdict=verdict, error=error, details=details, extra=extra
        )
        mapping["status_rank"] = str(new_rank)
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
        new_status = str(status or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = table_client.get_entity(partition_key=partition_key, row_key=job_id)
        except ResourceNotFoundError:
            existing = None
        except Exception:
            existing = None
        if _should_skip_regression(existing=existing, new_status=new_status, new_rank=new_rank):
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
        entity["status_rank"] = new_rank
        table_client.upsert_entity(entity=entity)
        return

    if backend == "redis":
        if not redis_client:
            return
        key = _redis_key(redis_prefix, job_id)
        new_status = str(status or "").strip().lower()
        new_rank = _status_rank(new_status)
        try:
            existing = redis_client.hgetall(key)
        except Exception:
            existing = None
        if _should_skip_regression(existing=existing, new_status=new_status, new_rank=new_rank):
            return
        mapping = _build_redis_mapping(
            status=status, verdict=verdict, error=error, details=details, extra=extra
        )
        mapping["status_rank"] = str(new_rank)
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
