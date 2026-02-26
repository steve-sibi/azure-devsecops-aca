from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from azure.servicebus.exceptions import ServiceBusError
from common.job_index import ALLOWED_JOB_STATUSES
from common.job_index import build_job_index_record as build_job_record
from common.job_index import job_index_partition_key, list_jobs_async, upsert_job_index_record_async
from common.logging_config import get_logger, log_with_context
from common.scan_messages import ScanMessageValidationError, validate_scan_task_v1
from common.screenshot_store import (
    get_screenshot_blob_async,
    get_screenshot_redis_async,
    redis_screenshot_key,
)
from common.telemetry import inject_trace_context
from common.url_dedupe import (
    build_url_index_record,
    get_url_index_entry_async,
    make_url_index_key,
    upsert_url_index_entry_async,
    url_index_entry_is_fresh,
)
from common.url_validation import UrlValidationError, validate_public_https_url_async
from fastapi import APIRouter, HTTPException, Query, Request, Security
from fastapi.responses import Response

import runtime
from deps.auth import require_api_key
from deps.store import (
    _build_summary,
    _coerce_bool,
    _enqueue_json,
    _get_result_entity,
    _normalize_visibility,
    _parse_details,
    _safe_int,
    _upsert_result,
)
from models import ScanRequest
from settings import (
    BLOCK_PRIVATE_NETWORKS,
    REDIS_JOB_INDEX_HASH_PREFIX,
    REDIS_JOB_INDEX_ZSET_PREFIX,
    REDIS_RESULT_PREFIX,
    REDIS_RESULT_TTL_SECONDS,
    RESULT_BACKEND,
    RESULT_PARTITION,
    SCREENSHOT_CONTAINER,
    SCREENSHOT_FORMAT,
    SCREENSHOT_REDIS_PREFIX,
    _URL_DEDUPE,
)

router = APIRouter()
logger = get_logger(__name__)


async def _validate_scan_url(url: str):
    try:
        await validate_public_https_url_async(
            url, block_private_networks=BLOCK_PRIVATE_NETWORKS
        )
    except UrlValidationError as e:
        error_code = str(e.code or "invalid_url")

        def _bad_url(detail: str):
            raise HTTPException(
                status_code=400,
                detail=detail,
                headers={"X-Error-Code": error_code},
            )

        if e.code == "https_only":
            _bad_url("Only HTTPS URLs are allowed")
        if e.code == "host_required":
            _bad_url("URL host is required")
        if e.code == "userinfo_not_allowed":
            _bad_url("Userinfo in URL is not allowed")
        if e.code == "port_not_allowed":
            _bad_url("Only default HTTPS port 443 is allowed")
        if e.code == "localhost_not_allowed":
            _bad_url("Localhost is not allowed")
        if e.code == "dns_failed":
            _bad_url("DNS resolution failed")
        if e.code == "no_records":
            _bad_url("No A/AAAA records found")
        if e.code == "non_public_ip":
            _bad_url("URL resolves to a non-public IP address (blocked)")
        if e.code == "direct_ip_not_public":
            _bad_url("Direct IP destinations must be publicly routable")
        _bad_url(str(e))

def _annotate_current_span_ids(*, request_id: str, run_id: str) -> None:
    """Attach stable request/run identifiers to the current API span."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        span_ctx = span.get_span_context() if span else None
        if not span_ctx or not span_ctx.is_valid:
            return
        span.set_attribute("app.request_id", str(request_id))
        span.set_attribute("app.run_id", str(run_id))
        # Keep existing tag semantics for compatibility with existing queries.
        span.set_attribute("app.job_id", str(run_id))
    except Exception:
        return

@router.post("/scan", tags=["URL Scanning"], summary="Submit a URL for security analysis")
async def enqueue_scan(
    request: Request,
    req: ScanRequest,
    api_key_hash: Optional[str] = Security(require_api_key),
):
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)

    log_with_context(
        logger,
        logging.INFO,
        "Scan request received",
        url=req.url,
        scan_type=req.type,
        source=req.source,
    )

    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")

    request_id = str(uuid4())
    run_id = str(uuid4())
    correlation_id = getattr(getattr(request, "state", None), "request_id", None)
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        correlation_id = str(uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()
    visibility = _normalize_visibility(getattr(req, "visibility", None))
    if str(getattr(req, "type", "url") or "url").strip().lower() != "url":
        # Never treat non-URL scans as shared/cacheable.
        visibility = "private"

    run_payload = {
        "job_id": run_id,
        "request_id": request_id,
        "run_id": run_id,
        "correlation_id": correlation_id,
        "url": req.url,
        "type": req.type,
        "source": req.source,
        "metadata": req.metadata or {},
        "submitted_at": submitted_at,
        "api_key_hash": api_key_hash or "",
        "visibility": visibility,
    }
    trace_ctx: dict[str, str] = {}
    inject_trace_context(trace_ctx)
    if isinstance(trace_ctx.get("traceparent"), str) and trace_ctx["traceparent"].strip():
        run_payload["traceparent"] = trace_ctx["traceparent"].strip()
    if isinstance(trace_ctx.get("tracestate"), str) and trace_ctx["tracestate"].strip():
        run_payload["tracestate"] = trace_ctx["tracestate"].strip()
    try:
        run_payload = validate_scan_task_v1(run_payload)
    except ScanMessageValidationError as e:
        log_with_context(
            logger, logging.WARNING, "Invalid scan request", url=req.url, error=str(e)
        )
        raise HTTPException(status_code=400, detail=str(e))

    await _validate_scan_url(run_payload["url"])

    url_index_key = None
    if (
        _URL_DEDUPE.enabled
        and visibility == "shared"
        and run_payload.get("type") == "url"
    ):
        try:
            url_index_key = make_url_index_key(
                url=run_payload["url"], api_key_hash=api_key_hash, cfg=_URL_DEDUPE
            )
        except Exception:
            url_index_key = None

    if (
        _URL_DEDUPE.enabled
        and url_index_key
        and not bool(getattr(req, "force", False))
        and run_payload.get("type") == "url"
        and visibility == "shared"
    ):
        existing = await get_url_index_entry_async(
            backend=RESULT_BACKEND,
            cfg=_URL_DEDUPE,
            key=url_index_key,
            table_client=table_client,
            redis_client=redis_client,
        )
        if existing and url_index_entry_is_fresh(existing, cfg=_URL_DEDUPE):
            existing_run_id = str(existing.get("job_id") or "").strip()
            if existing_run_id:
                run_entity = await _get_result_entity(existing_run_id, request=request)
                if run_entity:
                    run_visibility = (
                        str(run_entity.get("visibility") or "").strip().lower()
                    )
                    if run_visibility != "shared":
                        # Do not reuse "private" (or legacy) runs across API keys.
                        run_entity = None
                if run_entity:
                    run_status = str(
                        run_entity.get("status") or existing.get("status") or "unknown"
                    )
                    run_scanned_at = run_entity.get("scanned_at") or None
                    run_error = run_entity.get("error") or None
                    run_correlation_id = (
                        run_entity.get("correlation_id") or correlation_id
                    )

                    # Create a per-request result record that resolves to the cached run.
                    await _upsert_result(
                        request_id,
                        status=run_status,
                        details={
                            "url": run_payload["url"],
                            "type": run_payload.get("type"),
                            "source": run_payload.get("source"),
                            "run_id": existing_run_id,
                            "deduped": True,
                        },
                        extra={
                            "submitted_at": submitted_at,
                            "api_key_hash": api_key_hash or "",
                            "correlation_id": run_correlation_id or "",
                            "run_id": existing_run_id,
                            "deduped": True,
                            "url": run_payload["url"],
                            "visibility": visibility,
                        },
                        request=request,
                    )
                    if api_key_hash:
                        job_record = build_job_record(
                            api_key_hash_value=api_key_hash,
                            job_id=request_id,
                            submitted_at=submitted_at,
                            status=run_status,
                            url=run_payload.get("url"),
                            scanned_at=run_scanned_at,
                            updated_at=submitted_at,
                            correlation_id=run_correlation_id,
                            error=run_error,
                        )
                        job_record["type"] = "url"
                        job_record["run_id"] = existing_run_id
                        job_record["deduped"] = True
                        job_record["visibility"] = visibility
                        await upsert_job_index_record_async(
                            backend=RESULT_BACKEND,
                            api_key_hash_value=api_key_hash,
                            record=job_record,
                            table_client=table_client,
                            redis_client=redis_client,
                            redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
                        )

                    log_with_context(
                        logger,
                        logging.INFO,
                        "Scan deduped (cache hit)",
                        request_id=request_id,
                        run_id=existing_run_id,
                        url=run_payload["url"],
                        canonical_url=url_index_key.canonical_url,
                        status=run_status,
                    )
                    _annotate_current_span_ids(
                        request_id=request_id, run_id=existing_run_id
                    )
                    return {
                        "job_id": request_id,
                        "run_id": existing_run_id,
                        "status": run_status,
                        "deduped": True,
                    }
    try:
        application_properties: dict[str, str] = {"correlation_id": correlation_id}
        if isinstance(run_payload.get("traceparent"), str):
            application_properties["traceparent"] = str(run_payload["traceparent"])
        if isinstance(run_payload.get("tracestate"), str):
            application_properties["tracestate"] = str(run_payload["tracestate"])
        await _enqueue_json(
            run_payload,
            schema="scan-v1",
            message_id=run_id,
            application_properties=application_properties,
            request=request,
        )
        await _upsert_result(
            run_id,
            status="queued",
            details={
                "url": run_payload["url"],
                "type": run_payload.get("type"),
                "source": run_payload.get("source"),
            },
            extra={
                "submitted_at": submitted_at,
                "api_key_hash": api_key_hash or "",
                "correlation_id": correlation_id,
                "visibility": visibility,
            },
            request=request,
        )

        # Create a per-request result record that resolves to this run.
        await _upsert_result(
            request_id,
            status="queued",
            details={
                "url": run_payload["url"],
                "type": run_payload.get("type"),
                "source": run_payload.get("source"),
                "run_id": run_id,
                "deduped": False,
            },
            extra={
                "submitted_at": submitted_at,
                "api_key_hash": api_key_hash or "",
                "correlation_id": correlation_id,
                "run_id": run_id,
                "deduped": False,
                "url": run_payload["url"],
                "visibility": visibility,
            },
            request=request,
        )

        log_with_context(
            logger,
            logging.INFO,
            "Scan queued successfully",
            request_id=request_id,
            run_id=run_id,
            url=req.url,
            scan_type=req.type,
        )
        _annotate_current_span_ids(request_id=request_id, run_id=run_id)
        if api_key_hash:
            job_record = build_job_record(
                api_key_hash_value=api_key_hash,
                job_id=request_id,
                submitted_at=submitted_at,
                status="queued",
                url=run_payload.get("url"),
                scanned_at=None,
                updated_at=submitted_at,
                correlation_id=correlation_id,
                error=None,
            )
            job_record["type"] = "url"
            job_record["run_id"] = run_id
            job_record["deduped"] = False
            job_record["visibility"] = visibility
            await upsert_job_index_record_async(
                backend=RESULT_BACKEND,
                api_key_hash_value=api_key_hash,
                record=job_record,
                table_client=table_client,
                redis_client=redis_client,
                redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
            )
        if (
            _URL_DEDUPE.enabled
            and visibility == "shared"
            and url_index_key
            and run_payload.get("type") == "url"
        ):
            record = build_url_index_record(
                key=url_index_key,
                job_id=run_id,
                status="queued",
                submitted_at=submitted_at,
                scanned_at=None,
                updated_at=submitted_at,
            )
            await upsert_url_index_entry_async(
                backend=RESULT_BACKEND,
                cfg=_URL_DEDUPE,
                key=url_index_key,
                record=record,
                table_client=table_client,
                redis_client=redis_client,
                result_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
            )
        return {
            "job_id": request_id,
            "run_id": run_id,
            "status": "queued",
            "deduped": False,
        }
    except HTTPException:
        raise
    except ServiceBusError as e:
        log_with_context(
            logger,
            logging.ERROR,
            "Queue send failed",
            request_id=request_id,
            run_id=run_id,
            error=str(e),
            error_type=e.__class__.__name__,
        )
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
    except Exception as e:
        log_with_context(
            logger,
            logging.ERROR,
            "Queue send failed",
            request_id=request_id,
            run_id=run_id,
            error=str(e),
            error_type=e.__class__.__name__,
        )
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@router.get("/jobs", tags=["Jobs"], summary="List scan jobs")
async def list_jobs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    scan_type: Optional[str] = Query(
        None,
        alias="type",
        description="Optional scan type filter (url or file)",
        pattern="^(url|file)$",
    ),
    status: Optional[str] = Query(
        None, description="Optional CSV status filter (e.g. queued,fetching,completed)"
    ),
    api_key_hash: Optional[str] = Security(require_api_key),
):
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)

    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if not api_key_hash:
        raise HTTPException(status_code=401, detail="Missing API key")

    statuses = None
    if isinstance(status, str) and status.strip():
        statuses = [s.strip().lower() for s in status.split(",") if s.strip()]
        invalid = [s for s in statuses if s not in ALLOWED_JOB_STATUSES]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status value(s): {', '.join(invalid)}",
            )

    scan_type_norm = None
    if isinstance(scan_type, str) and scan_type.strip():
        scan_type_norm = scan_type.strip().lower()
        if scan_type_norm not in ("url", "file"):
            raise HTTPException(status_code=400, detail="type must be 'url' or 'file'")

    limit_n = max(1, int(limit or 0))
    prefetch_limit = limit_n
    if scan_type_norm or statuses:
        prefetch_limit = min(5000, max(limit_n, limit_n * 10))

    items = await list_jobs_async(
        backend=RESULT_BACKEND,
        api_key_hash_value=api_key_hash,
        limit=prefetch_limit,
        statuses=statuses,
        table_client=table_client,
        redis_client=redis_client,
    )

    base_url = str(request.base_url).rstrip("/")
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        item_type_raw = item.get("type")
        item_type = (
            str(item_type_raw).strip().lower()
            if isinstance(item_type_raw, str) and item_type_raw.strip()
            else "url"
        )
        if scan_type_norm == "file" and item_type != "file":
            continue
        if scan_type_norm == "url" and item_type == "file":
            continue

        job_id = str(item.get("job_id") or "").strip()
        if not job_id:
            continue

        run_id = str(item.get("run_id") or "").strip()
        status_out = item.get("status") or "unknown"
        scanned_at_out = item.get("scanned_at") or None
        error_out = item.get("error") or None
        correlation_id_out = item.get("correlation_id") or None
        deduped_out = _coerce_bool(item.get("deduped"))
        visibility_out = (
            (item.get("visibility") or None)
            if isinstance(item.get("visibility"), str)
            else None
        )
        filename_out = item.get("filename") or None
        content_type_out = item.get("content_type") or None
        input_type_out = item.get("input_type") or None
        sha256_out = item.get("sha256") or None
        verdict_out = item.get("verdict") or None
        signature_out = item.get("signature") or None

        if run_id:
            run_entity = await _get_result_entity(run_id, request=request)
            if isinstance(run_entity, dict) and run_entity:
                status_out = run_entity.get("status") or status_out
                scanned_at_out = run_entity.get("scanned_at") or scanned_at_out
                error_out = run_entity.get("error") or error_out
                correlation_id_out = (
                    run_entity.get("correlation_id") or correlation_id_out
                )

        dashboard_path = "/file" if item_type == "file" else "/"
        out.append(
            {
                "job_id": job_id,
                "run_id": run_id or None,
                "type": item_type,
                "status": status_out,
                "submitted_at": item.get("submitted_at") or None,
                "scanned_at": scanned_at_out,
                "url": item.get("url") or None,
                "filename": filename_out,
                "sha256": sha256_out,
                "verdict": verdict_out,
                "signature": signature_out,
                "input_type": input_type_out,
                "content_type": content_type_out,
                "error": error_out,
                "correlation_id": correlation_id_out,
                "deduped": deduped_out,
                "visibility": visibility_out,
                "dashboard_url": f"{base_url}{dashboard_path}?job={job_id}",
            }
        )
        if len(out) >= limit_n:
            break

    return {"jobs": out}


@router.delete("/jobs", tags=["Jobs"], summary="Clear all scan jobs")
async def clear_jobs(
    request: Request,
    scan_type: Optional[str] = Query(
        None,
        alias="type",
        description="Optional scan type filter (url or file)",
        pattern="^(url|file)$",
    ),
    api_key_hash: Optional[str] = Security(require_api_key),
):
    table_client = runtime.get_table_client(request)
    redis_client = runtime.get_redis_client(request)

    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if not api_key_hash:
        raise HTTPException(status_code=401, detail="Missing API key")

    scan_type_norm = None
    if isinstance(scan_type, str) and scan_type.strip():
        scan_type_norm = scan_type.strip().lower()
        if scan_type_norm not in ("url", "file"):
            raise HTTPException(status_code=400, detail="type must be 'url' or 'file'")

    deleted_job_index = 0
    deleted_request_results = 0

    if RESULT_BACKEND == "redis":
        zkey = f"{REDIS_JOB_INDEX_ZSET_PREFIX}{api_key_hash}"
        try:
            job_ids = await redis_client.zrange(zkey, 0, -1)
        except Exception:
            job_ids = []

        job_ids_norm: list[str] = []
        for jid in job_ids or []:
            s = str(jid or "").strip()
            if s:
                job_ids_norm.append(s)

        if scan_type_norm:
            # Filter ids by stored job type. Treat missing type as "url" for backwards compatibility.
            try:
                pipe = redis_client.pipeline()
                hkeys: list[str] = []
                for jid_s in job_ids_norm:
                    hkey = f"{REDIS_JOB_INDEX_HASH_PREFIX}{api_key_hash}:{jid_s}"
                    hkeys.append(hkey)
                    pipe.hget(hkey, "type")
                raw_types = await pipe.execute()
            except Exception:
                raw_types = []
                hkeys = []

            filtered: list[str] = []
            for jid_s, raw_t in zip(job_ids_norm, raw_types):
                jt = (
                    str(raw_t or "").strip().lower()
                    if isinstance(raw_t, str) and str(raw_t).strip()
                    else "url"
                )
                if scan_type_norm == "file" and jt == "file":
                    filtered.append(jid_s)
                if scan_type_norm == "url" and jt != "file":
                    filtered.append(jid_s)
            job_ids_norm = filtered

        try:
            pipe = redis_client.pipeline()
            for jid_s in job_ids_norm:
                pipe.delete(f"{REDIS_JOB_INDEX_HASH_PREFIX}{api_key_hash}:{jid_s}")
                pipe.delete(f"{REDIS_RESULT_PREFIX}{jid_s}")
                if scan_type_norm:
                    pipe.zrem(zkey, jid_s)
            if not scan_type_norm:
                pipe.delete(zkey)
            results = await pipe.execute()
        except Exception:
            results = []

        # Each DEL returns the number of keys removed (0/1).
        n = len(job_ids_norm)
        if isinstance(results, list) and n > 0:
            try:
                step = 3 if scan_type_norm else 2
                deleted_job_index = sum(
                    int(x or 0) for x in results[0 : step * n : step]
                )
                deleted_request_results = sum(
                    int(x or 0) for x in results[1 : step * n : step]
                )
            except Exception:
                deleted_job_index = 0
                deleted_request_results = 0
        return {
            "backend": "redis",
            "api_key_hash": api_key_hash,
            "type": scan_type_norm,
            "deleted_job_index_records": deleted_job_index,
            "deleted_request_results": deleted_request_results,
        }

    if RESULT_BACKEND == "table":
        if not table_client:
            raise HTTPException(status_code=503, detail="Result store not initialized")
        tc = table_client
        pk = job_index_partition_key(api_key_hash_value=api_key_hash)
        filt = f"PartitionKey eq '{pk}'"
        try:
            pager = tc.query_entities(query_filter=filt, results_per_page=200)
            async for entity in pager:
                if not isinstance(entity, dict):
                    continue

                item_type_raw = entity.get("type")
                item_type = (
                    str(item_type_raw).strip().lower()
                    if isinstance(item_type_raw, str) and item_type_raw.strip()
                    else "url"
                )
                if scan_type_norm == "file" and item_type != "file":
                    continue
                if scan_type_norm == "url" and item_type == "file":
                    continue

                row_key = str(entity.get("RowKey") or "").strip()
                request_id = str(entity.get("job_id") or "").strip()

                if row_key:
                    try:
                        await tc.delete_entity(partition_key=pk, row_key=row_key)
                        deleted_job_index += 1
                    except Exception:
                        pass

                if request_id:
                    try:
                        await tc.delete_entity(
                            partition_key=RESULT_PARTITION, row_key=request_id
                        )
                        deleted_request_results += 1
                    except Exception:
                        pass
        except Exception:
            pass

        return {
            "backend": "table",
            "api_key_hash": api_key_hash,
            "type": scan_type_norm,
            "job_index_partition_key": pk,
            "result_partition_key": RESULT_PARTITION,
            "deleted_job_index_records": deleted_job_index,
            "deleted_request_results": deleted_request_results,
        }

    raise HTTPException(
        status_code=500, detail=f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}"
    )


@router.get("/scan/{job_id}", tags=["Jobs"], summary="Get scan result")
async def get_scan_status(
    job_id: str,
    request: Request,
    view: str = Query("summary", description="Response view: summary or full"),
    api_key_hash: Optional[str] = Security(require_api_key),
):
    log_with_context(
        logger, logging.INFO, "Fetching scan result", job_id=job_id, view=view
    )

    view = (view or "summary").strip().lower()
    if view not in ("summary", "full"):
        raise HTTPException(status_code=400, detail="view must be 'summary' or 'full'")

    entity = await _get_result_entity(job_id, request=request)
    if not entity:
        log_with_context(
            logger,
            logging.INFO,
            "Scan result not found",
            job_id=job_id,
            status="pending",
        )
        return {"job_id": job_id, "status": "pending", "summary": None}

    run_id = str(entity.get("run_id") or "").strip()
    if run_id:
        # This is a per-request record pointing at an underlying scan run.
        owner_hash = str(entity.get("api_key_hash") or "").strip()
        if (
            owner_hash
            and api_key_hash
            and not secrets.compare_digest(owner_hash, api_key_hash)
        ):
            raise HTTPException(status_code=404, detail="Scan result not found")

        run_entity = await _get_result_entity(run_id, request=request)
        if not run_entity:
            return {
                "job_id": job_id,
                "run_id": run_id,
                "status": "pending",
                "summary": (
                    {"url": entity.get("url") or None} if entity.get("url") else None
                ),
                "deduped": _coerce_bool(entity.get("deduped")),
                "visibility": (entity.get("visibility") or None),
            }

        details = _parse_details(run_entity.get("details"))
        summary = _build_summary(run_entity, details)
        scan_type_out = None
        if isinstance(details, dict):
            t = details.get("type")
            if isinstance(t, str) and t.strip().lower() in ("url", "file"):
                scan_type_out = t.strip().lower()
            elif isinstance(details.get("url"), str) and details.get("url"):
                scan_type_out = "url"
            elif isinstance(details.get("filename"), str) and details.get("filename"):
                scan_type_out = "file"
        if not scan_type_out:
            scan_type_out = "url"

        log_with_context(
            logger,
            logging.INFO,
            "Scan result retrieved (request)",
            job_id=job_id,
            run_id=run_id,
            status=run_entity.get("status"),
            duration_ms=_safe_int(run_entity.get("duration_ms")),
        )

        base_url = str(request.base_url).rstrip("/")
        dashboard_path = "/file" if scan_type_out == "file" else "/"
        response = {
            "job_id": job_id,
            "run_id": run_id,
            "status": run_entity.get("status", "unknown"),
            "type": scan_type_out,
            "verdict": run_entity.get("verdict") or None,
            "dashboard_url": f"{base_url}{dashboard_path}?job={job_id}",
            "error": run_entity.get("error") or None,
            "submitted_at": entity.get("submitted_at"),
            "scanned_at": run_entity.get("scanned_at"),
            "size_bytes": _safe_int(run_entity.get("size_bytes")),
            "duration_ms": _safe_int(run_entity.get("duration_ms")),
            "correlation_id": run_entity.get("correlation_id") or None,
            "deduped": _coerce_bool(entity.get("deduped")),
            "visibility": (entity.get("visibility") or None),
            "summary": summary,
        }
        if view == "full":
            response["details"] = details
        return response

    owner_hash = str(entity.get("api_key_hash") or "").strip()
    if (
        owner_hash
        and api_key_hash
        and not secrets.compare_digest(owner_hash, api_key_hash)
    ):
        raise HTTPException(status_code=404, detail="Scan result not found")

    details = _parse_details(entity.get("details"))
    summary = _build_summary(entity, details)
    scan_type_out = None
    if isinstance(details, dict):
        t = details.get("type")
        if isinstance(t, str) and t.strip().lower() in ("url", "file"):
            scan_type_out = t.strip().lower()
        elif isinstance(details.get("url"), str) and details.get("url"):
            scan_type_out = "url"
        elif isinstance(details.get("filename"), str) and details.get("filename"):
            scan_type_out = "file"
    if not scan_type_out:
        scan_type_out = "url"

    log_with_context(
        logger,
        logging.INFO,
        "Scan result retrieved",
        job_id=job_id,
        status=entity.get("status"),
        duration_ms=_safe_int(entity.get("duration_ms")),
    )

    base_url = str(request.base_url).rstrip("/")
    dashboard_path = "/file" if scan_type_out == "file" else "/"
    response = {
        "job_id": job_id,
        "run_id": job_id,
        "status": entity.get("status", "unknown"),
        "type": scan_type_out,
        "verdict": entity.get("verdict") or None,
        "dashboard_url": f"{base_url}{dashboard_path}?job={job_id}",
        "error": entity.get("error") or None,
        "submitted_at": entity.get("submitted_at"),
        "scanned_at": entity.get("scanned_at"),
        "size_bytes": _safe_int(entity.get("size_bytes")),
        "duration_ms": _safe_int(entity.get("duration_ms")),
        "correlation_id": entity.get("correlation_id") or None,
        "summary": summary,
    }
    if view == "full":
        response["details"] = details
    return response


def _screenshot_blob_name(job_id: str) -> str:
    fmt = (SCREENSHOT_FORMAT or "jpeg").strip().lower()
    ext = "png" if fmt == "png" else "jpg"
    return f"{job_id}.{ext}"


@router.get("/scan/{job_id}/screenshot", tags=["Jobs"], summary="Get scan screenshot")
async def get_scan_screenshot(
    request: Request,
    job_id: str,
    api_key_hash: Optional[str] = Security(require_api_key),
):
    redis_client = runtime.get_redis_client(request)
    blob_service = runtime.get_blob_service(request)

    log_with_context(
        logger,
        logging.INFO,
        "Fetching screenshot",
        job_id=job_id,
        backend=RESULT_BACKEND,
    )

    entity = await _get_result_entity(job_id, request=request)
    if not entity:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    target_job_id = job_id
    run_id = str(entity.get("run_id") or "").strip()
    if run_id:
        # Request record: enforce access on the request, then resolve to the run for storage.
        owner_hash = str(entity.get("api_key_hash") or "").strip()
        if (
            owner_hash
            and api_key_hash
            and not secrets.compare_digest(owner_hash, api_key_hash)
        ):
            raise HTTPException(status_code=404, detail="Screenshot not found")
        target_job_id = run_id
    else:
        owner_hash = str(entity.get("api_key_hash") or "").strip()
        if (
            owner_hash
            and api_key_hash
            and not secrets.compare_digest(owner_hash, api_key_hash)
        ):
            raise HTTPException(status_code=404, detail="Screenshot not found")

    if RESULT_BACKEND == "redis":
        if not redis_client:
            raise HTTPException(status_code=503, detail="Result store not initialized")
        key = redis_screenshot_key(SCREENSHOT_REDIS_PREFIX, target_job_id)
        data = await get_screenshot_redis_async(redis_client=redis_client, key=key)
        if not data or not data.bytes:
            log_with_context(
                logger,
                logging.WARNING,
                "Screenshot not found",
                job_id=job_id,
                target_job_id=target_job_id,
                backend="redis",
            )
            raise HTTPException(status_code=404, detail="Screenshot not found")
        log_with_context(
            logger,
            logging.INFO,
            "Screenshot retrieved",
            job_id=job_id,
            target_job_id=target_job_id,
            backend="redis",
            size_bytes=len(data.bytes),
        )
        return Response(content=data.bytes, media_type=data.content_type)

    if RESULT_BACKEND == "table":
        if not blob_service:
            raise HTTPException(
                status_code=503, detail="Screenshot store not initialized"
            )
        data = await get_screenshot_blob_async(
            blob_service_client=blob_service,
            container=SCREENSHOT_CONTAINER,
            blob_name=_screenshot_blob_name(target_job_id),
        )
        if not data or not data.bytes:
            log_with_context(
                logger,
                logging.WARNING,
                "Screenshot not found",
                job_id=job_id,
                target_job_id=target_job_id,
                backend="blob",
            )
            raise HTTPException(status_code=404, detail="Screenshot not found")
        log_with_context(
            logger,
            logging.INFO,
            "Screenshot retrieved",
            job_id=job_id,
            target_job_id=target_job_id,
            backend="blob",
            size_bytes=len(data.bytes),
        )
        return Response(content=data.bytes, media_type=data.content_type)

    raise HTTPException(
        status_code=500, detail=f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}"
    )
