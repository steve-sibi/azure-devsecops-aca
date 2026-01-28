import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Optional
from uuid import uuid4

from azure.data.tables.aio import TableServiceClient
from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError
from common.clamav_client import (
    ClamAVConnectionError,
    ClamAVError,
    ClamAVProtocolError,
    clamd_ping,
    clamd_scan_bytes,
    clamd_version,
)
from common.config import ConsumerConfig
from common.limits import get_api_limits, get_file_scan_limits
from common.logging_config import (
    clear_correlation_id,
    get_logger,
    log_with_context,
    set_correlation_id,
    setup_logging,
)
from common.result_store import get_result_async, upsert_result_async
from common.scan_messages import (
    SCAN_SOURCE_MAX_LENGTH,
    SCAN_URL_MAX_LENGTH,
    ScanMessageValidationError,
    validate_scan_task_v1,
)
from common.screenshot_store import (
    get_screenshot_blob_async,
    get_screenshot_redis_async,
    redis_screenshot_key,
)
from common.job_index import ALLOWED_JOB_STATUSES, api_key_hash as hash_api_key
from common.job_index import job_index_partition_key, list_jobs_async, upsert_job_index_record_async
from common.job_index import build_job_index_record as build_job_record
from common.url_dedupe import (
    UrlDedupeConfig,
    build_url_index_record,
    get_url_index_entry_async,
    make_url_index_key,
    upsert_url_index_entry_async,
    url_index_entry_is_fresh,
)
from common.url_validation import UrlValidationError, validate_public_https_url_async
from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Security,
    UploadFile,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

# ---------- Logging Setup ----------
setup_logging(service_name="api", level=logging.INFO)

# ---------- Settings ----------
# Shared configuration (queues, results, redis)
_CONSUMER_CFG = ConsumerConfig.from_env()
QUEUE_NAME = _CONSUMER_CFG.queue_name
QUEUE_BACKEND = _CONSUMER_CFG.queue_backend
SERVICEBUS_CONN = _CONSUMER_CFG.servicebus_conn
RESULT_BACKEND = _CONSUMER_CFG.result_backend
RESULT_STORE_CONN = _CONSUMER_CFG.result_store_conn
RESULT_TABLE = _CONSUMER_CFG.result_table
RESULT_PARTITION = _CONSUMER_CFG.result_partition
REDIS_URL = _CONSUMER_CFG.redis_url
REDIS_QUEUE_KEY = _CONSUMER_CFG.redis_queue_key
REDIS_RESULT_PREFIX = _CONSUMER_CFG.redis_result_prefix
REDIS_RESULT_TTL_SECONDS = _CONSUMER_CFG.redis_result_ttl_seconds
REDIS_JOB_INDEX_ZSET_PREFIX = (os.getenv("REDIS_JOB_INDEX_ZSET_PREFIX", "jobsidx:") or "jobsidx:").strip()
REDIS_JOB_INDEX_HASH_PREFIX = (os.getenv("REDIS_JOB_INDEX_HASH_PREFIX", "jobs:") or "jobs:").strip()

# API-specific settings
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN") or os.getenv(
    "APPLICATIONINSIGHTS_CONNECTION_STRING"
)  # optional

# Screenshots (optional)
SCREENSHOT_REDIS_PREFIX = os.getenv("SCREENSHOT_REDIS_PREFIX", "screenshot:")
SCREENSHOT_CONTAINER = os.getenv("SCREENSHOT_CONTAINER", "screenshots")
SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "jpeg")

logger = get_logger(__name__)

# API hardening
API_KEY = os.getenv("API_KEY")
API_KEYS = os.getenv("ACA_API_KEYS") or os.getenv("API_KEYS") or ""
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
_API_LIMITS = get_api_limits()
RATE_LIMIT_RPM = _API_LIMITS.rate_limit_rpm
RATE_LIMIT_WINDOW_SECONDS = _API_LIMITS.rate_limit_window_seconds
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)
MAX_DASHBOARD_POLL_SECONDS = _API_LIMITS.max_dashboard_poll_seconds
_URL_DEDUPE = UrlDedupeConfig.from_env()
_DEFAULT_URL_VISIBILITY = (os.getenv("URL_RESULT_VISIBILITY_DEFAULT", "shared") or "shared").strip().lower()
if _DEFAULT_URL_VISIBILITY not in ("shared", "private"):
    _DEFAULT_URL_VISIBILITY = "shared"

# File scanning (ClamAV)
CLAMAV_HOST = (os.getenv("CLAMAV_HOST", "127.0.0.1") or "127.0.0.1").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
_FILE_SCAN_LIMITS = get_file_scan_limits()
CLAMAV_TIMEOUT_SECONDS = _FILE_SCAN_LIMITS.clamav_timeout_seconds
FILE_SCAN_MAX_BYTES = _FILE_SCAN_LIMITS.max_bytes
FILE_SCAN_INCLUDE_VERSION = _FILE_SCAN_LIMITS.include_version

# HTML dashboard template lives alongside this file.
DASHBOARD_TEMPLATE = (
    Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
)
FILE_SCANNER_TEMPLATE = (
    Path(__file__).with_name("file_scanner.html").read_text(encoding="utf-8")
)

# Globals set during app startup
sb_client: Optional[ServiceBusClient] = None
sb_sender: Optional[ServiceBusSender] = None
table_service: Optional[TableServiceClient] = None
table_client = None
redis_client = None
blob_service = None

api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

# Simple in-memory rate limiter (per API key hash); good enough for demos.
_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, deque[float]] = {}


class ScanRequest(BaseModel):
    url: str = Field(
        ..., description="HTTPS URL to scan", max_length=SCAN_URL_MAX_LENGTH
    )
    type: str = Field("url", pattern="^(url|file)$", max_length=16)
    source: Optional[str] = Field(
        None,
        description="Optional source identifier",
        max_length=SCAN_SOURCE_MAX_LENGTH,
    )
    metadata: Optional[dict] = Field(None, description="Optional metadata")
    force: bool = Field(
        False, description="Force a re-scan (ignore URL dedupe cache)"
    )
    visibility: Optional[str] = Field(
        None,
        description="URL scan visibility: 'shared' (cacheable) or 'private' (no cache reuse)",
        max_length=16,
        pattern="^(shared|private)$",
    )


async def _read_upload_bytes_limited(
    upload: UploadFile, *, max_bytes: int
) -> tuple[bytes, str]:
    hasher = hashlib.sha256()
    total = 0
    parts: list[bytes] = []
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File too large (max {max_bytes} bytes)",
            )
        hasher.update(chunk)
        parts.append(chunk)
    return b"".join(parts), hasher.hexdigest()


def _decode_payload_bytes(
    payload: str, *, is_base64: bool, max_bytes: int
) -> tuple[bytes, str]:
    raw = (payload or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="payload cannot be empty")

    if is_base64:
        compact = "".join(raw.split())
        estimated_len = (len(compact) * 3) // 4
        if estimated_len > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"Payload too large (max {max_bytes} bytes after base64 decode)",
            )
        try:
            data = base64.b64decode(compact, validate=True)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="payload_base64=true but payload is not valid base64",
            )
    else:
        data = raw.encode("utf-8")

    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413, detail=f"Payload too large (max {max_bytes} bytes)"
        )

    return data, hashlib.sha256(data).hexdigest()


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


async def _enforce_rate_limit(api_key: str):
    if RATE_LIMIT_RPM <= 0:
        return
    window = max(1, RATE_LIMIT_WINDOW_SECONDS)
    now = time.monotonic()
    bucket = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    async with _rate_lock:
        q = _rate_buckets.setdefault(bucket, deque())
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= RATE_LIMIT_RPM:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({RATE_LIMIT_RPM}/{window}s)",
            )
        q.append(now)


async def require_api_key(
    request: Request, api_key: Optional[str] = Security(api_key_scheme)
):
    if not REQUIRE_API_KEY:
        return None
    configured: list[str] = []
    if isinstance(API_KEY, str) and API_KEY.strip():
        configured.append(API_KEY.strip())
    if isinstance(API_KEYS, str) and API_KEYS.strip():
        configured.extend([p.strip() for p in API_KEYS.split(",") if p.strip()])
    if not configured:
        raise HTTPException(status_code=500, detail="No API keys are configured")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if not any(secrets.compare_digest(api_key, k) for k in configured):
        raise HTTPException(status_code=403, detail="Invalid API key")
    await _enforce_rate_limit(api_key)
    return hash_api_key(api_key)


async def _upsert_result(
    job_id: str,
    status: str,
    details: Optional[dict] = None,
    verdict: Optional[str] = None,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
):
    """Persist status/verdict to the table for status checks."""
    await upsert_result_async(
        backend=RESULT_BACKEND,
        partition_key=RESULT_PARTITION,
        job_id=job_id,
        status=status,
        verdict=verdict,
        error=error,
        details=details,
        extra=extra,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=REDIS_RESULT_PREFIX,
        redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
    )


async def _get_result_entity(job_id: str) -> Optional[dict]:
    return await get_result_async(
        backend=RESULT_BACKEND,
        partition_key=RESULT_PARTITION,
        job_id=job_id,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=REDIS_RESULT_PREFIX,
    )


async def _enqueue_json(
    payload: dict,
    *,
    schema: str,
    message_id: str,
    application_properties: Optional[dict] = None,
):
    if QUEUE_BACKEND == "servicebus":
        if not sb_sender:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        props = {"schema": schema}
        if application_properties:
            props.update(application_properties)
        msg = ServiceBusMessage(
            json.dumps(payload),
            content_type="application/json",
            message_id=message_id,
            application_properties=props,
        )
        await sb_sender.send_messages(msg)
        return

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        envelope = {
            "schema": schema,
            "message_id": message_id,
            "delivery_count": 1,
            "payload": payload,
        }
        if application_properties:
            envelope["application_properties"] = application_properties
        await redis_client.rpush(REDIS_QUEUE_KEY, json.dumps(envelope))
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {QUEUE_BACKEND}")


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
    return _DEFAULT_URL_VISIBILITY


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
    download_blocked = None

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

        if isinstance(details.get("download_blocked"), bool):
            download_blocked = bool(details.get("download_blocked"))

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

    if download_blocked is not None:
        summary["download_blocked"] = download_blocked

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sb_client, sb_sender, table_service, table_client, redis_client, blob_service

    # Validate shared configuration
    _CONSUMER_CFG.validate()

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        try:
            import redis.asyncio as redis_async
        except Exception as e:
            raise RuntimeError(
                "Redis backends require the 'redis' package (pip install redis)"
            ) from e
        redis_client = redis_async.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()

    # --- Queue backend ---
    if QUEUE_BACKEND == "servicebus":
        if not SERVICEBUS_CONN:
            raise RuntimeError("SERVICEBUS_CONN environment variable is required")
        sb_client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN)

        await sb_client.__aenter__()
        sb_sender = sb_client.get_queue_sender(queue_name=QUEUE_NAME)
        await sb_sender.__aenter__()

    # --- Result store backend ---
    if RESULT_BACKEND == "table":
        if not RESULT_STORE_CONN:
            raise RuntimeError("RESULT_STORE_CONN environment variable is required")
        table_service = TableServiceClient.from_connection_string(
            conn_str=RESULT_STORE_CONN
        )
        table_client = table_service.get_table_client(table_name=RESULT_TABLE)
        await table_service.__aenter__()
        await table_service.create_table_if_not_exists(table_name=RESULT_TABLE)

        # Screenshots are stored in Blob Storage when using Table results.
        try:
            from azure.storage.blob.aio import BlobServiceClient as AioBlobServiceClient

            blob_service = AioBlobServiceClient.from_connection_string(
                RESULT_STORE_CONN
            )
            await blob_service.__aenter__()
        except Exception as e:
            blob_service = None
            logger.warning("Blob client not initialized (screenshots disabled): %s", e)

    # --- Optional App Insights logging (only if packages + conn are present) ---
    if APPINSIGHTS_CONN:
        try:
            from opencensus.ext.azure.log_exporter import AzureLogHandler

            if not any(isinstance(h, AzureLogHandler) for h in logger.handlers):
                logger.addHandler(AzureLogHandler(connection_string=APPINSIGHTS_CONN))
                logger.info("App Insights logging enabled.")
        except Exception as e:
            logger.warning(f"App Insights logging not enabled: {e}")

    yield  # ---- App runs ----

    # ---- Cleanup on shutdown ----
    if sb_sender:
        await sb_sender.__aexit__(None, None, None)
    if sb_client:
        await sb_client.__aexit__(None, None, None)
    if table_service:
        await table_service.__aexit__(None, None, None)
    if redis_client:
        try:
            maybe = redis_client.close()
            if asyncio.iscoroutine(maybe):
                await maybe
        finally:
            pool = getattr(redis_client, "connection_pool", None)
            disconnect = getattr(pool, "disconnect", None) if pool else None
            if callable(disconnect):
                maybe = disconnect()
                if asyncio.iscoroutine(maybe):
                    await maybe
    if blob_service:
        await blob_service.__aexit__(None, None, None)


app = FastAPI(title="Azure DevSecOps URL Scanner", lifespan=lifespan)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    # Get or generate correlation ID from headers
    correlation_id = (
        request.headers.get("X-Correlation-ID")
        or request.headers.get("X-Request-ID")
        or str(uuid4())
    )

    # Set in context for structured logging
    set_correlation_id(correlation_id)
    request.state.request_id = correlation_id

    try:
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Request-Id"] = correlation_id
        return response
    finally:
        clear_correlation_id()


def _problem_type(code: str | None) -> str:
    if not code:
        return "about:blank"
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "-" for ch in code)
    return f"urn:aca:problem:{safe}"


def _problem_title(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase
    except Exception:
        return "Error"


def _problem_response(
    *,
    request: Request,
    status_code: int,
    title: str,
    detail: str | None,
    code: str | None = None,
    extra: dict | None = None,
    headers: dict | None = None,
):
    body: dict = {
        "type": _problem_type(code),
        "title": title,
        "status": int(status_code),
    }
    if detail is not None:
        body["detail"] = str(detail)

    request_id = getattr(getattr(request, "state", None), "request_id", None)
    if isinstance(request_id, str) and request_id.strip():
        body["instance"] = f"urn:uuid:{request_id.strip()}"

    if code:
        body["code"] = str(code)
    if isinstance(extra, dict) and extra:
        body.update(extra)

    return JSONResponse(
        content=body,
        status_code=int(status_code),
        headers=headers,
        media_type="application/problem+json",
    )


_STATUS_CODE_TO_CODE: dict[int, str] = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    502: "bad_gateway",
    503: "service_unavailable",
}


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    status = int(getattr(exc, "status_code", 500) or 500)
    headers = getattr(exc, "headers", None)
    code = None
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k or "").lower() == "x-error-code" and v:
                code = str(v)
                break
    if not code:
        code = _STATUS_CODE_TO_CODE.get(status, f"http_{status}")
    detail = getattr(exc, "detail", None)
    if detail is None or detail == "":
        detail = _problem_title(status)
    return _problem_response(
        request=request,
        status_code=status,
        title=_problem_title(status),
        detail=str(detail),
        code=code,
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def request_validation_handler(request: Request, exc: RequestValidationError):
    return _problem_response(
        request=request,
        status_code=422,
        title=_problem_title(422),
        detail="Request validation failed",
        code=_STATUS_CODE_TO_CODE.get(422, "validation_error"),
        extra={"errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(getattr(request, "state", None), "request_id", None)
    logger.exception("Unhandled exception (request_id=%s)", request_id)
    return _problem_response(
        request=request,
        status_code=500,
        title=_problem_title(500),
        detail="Internal server error",
        code=_STATUS_CODE_TO_CODE.get(500, "internal_error"),
    )


@app.middleware("http")
async def otel_request_spans(request: Request, call_next):
    if not APPINSIGHTS_CONN or request.url.path == "/healthz":
        return await call_next(request)

    from opentelemetry import trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    tracer = trace.get_tracer("aca-fastapi-api")
    span_name = f"{request.method} {request.url.path}"

    with tracer.start_as_current_span(span_name, kind=SpanKind.SERVER) as span:
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.target", request.url.path)
        span.set_attribute("http.url", str(request.url))

        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception(
                "Unhandled exception in request: %s %s",
                request.method,
                request.url.path,
            )
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise

        route = request.scope.get("route")
        route_path = getattr(route, "path", None)
        if route_path:
            span.update_name(f"{request.method} {route_path}")
            span.set_attribute("http.route", route_path)

        span.set_attribute("http.status_code", response.status_code)
        if response.status_code >= 500:
            detail = None
            try:
                if (
                    str(response.headers.get("content-type") or "")
                    .lower()
                    .startswith(("application/json", "application/problem+json"))
                ):
                    body = getattr(response, "body", None)
                    if body:
                        parsed = json.loads(body.decode("utf-8"))
                        if (
                            isinstance(parsed, dict)
                            and parsed.get("detail") is not None
                        ):
                            detail = parsed.get("detail")
            except Exception:
                detail = None

            if detail is not None:
                span.set_attribute("app.error_detail", str(detail))
                try:
                    span.add_event("http.error", {"detail": str(detail)})
                except Exception:
                    pass

            logger.error(
                "HTTP %s %s -> %s: %s",
                request.method,
                request.url.path,
                response.status_code,
                str(detail) if detail is not None else "",
            )
            span.set_status(Status(StatusCode.ERROR))
        return response


@app.get("/healthz")
async def healthz():
    return {
        "ok": True,
        "queue_backend": QUEUE_BACKEND,
        "result_backend": RESULT_BACKEND,
        "url_dedupe": {
            "enabled": bool(_URL_DEDUPE.enabled),
            "ttl_seconds": int(_URL_DEDUPE.ttl_seconds or 0),
            "in_progress_ttl_seconds": int(_URL_DEDUPE.in_progress_ttl_seconds or 0),
            "scope": _URL_DEDUPE.scope,
            "index_partition": _URL_DEDUPE.index_partition,
        },
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    template = DASHBOARD_TEMPLATE
    api_key_header_html = html.escape(API_KEY_HEADER or "")
    api_key_header_json = json.dumps(API_KEY_HEADER or "X-API-Key")
    return (
        template.replace("__API_KEY_HEADER__", api_key_header_html)
        .replace("__API_KEY_HEADER_JSON__", api_key_header_json)
        .replace(
            "__MAX_DASHBOARD_POLL_SECONDS__", str(int(MAX_DASHBOARD_POLL_SECONDS or 0))
        )
    )


@app.get("/file", response_class=HTMLResponse)
async def file_scanner():
    template = FILE_SCANNER_TEMPLATE
    api_key_header_html = html.escape(API_KEY_HEADER or "")
    api_key_header_json = json.dumps(API_KEY_HEADER or "X-API-Key")
    return (
        template.replace("__API_KEY_HEADER__", api_key_header_html)
        .replace("__API_KEY_HEADER_JSON__", api_key_header_json)
        .replace("__FILE_SCAN_MAX_BYTES__", str(int(FILE_SCAN_MAX_BYTES or 0)))
    )


@app.post("/file/scan")
async def scan_file(
    file: Optional[UploadFile] = File(None),
    payload: Optional[str] = Form(None),
    payload_base64: bool = Form(False),
    _api_key_hash: Optional[str] = Security(require_api_key),
):
    if file is None and not (isinstance(payload, str) and payload.strip()):
        raise HTTPException(status_code=400, detail="Provide a file or payload")

    input_type = "file" if file is not None else "payload"

    filename = None
    content_type = None
    if file is not None:
        filename = (file.filename or "upload.bin").strip() or "upload.bin"
        content_type = file.content_type or "application/octet-stream"
        data, sha256 = await _read_upload_bytes_limited(
            file, max_bytes=int(FILE_SCAN_MAX_BYTES or 0)
        )
        await file.close()
    else:
        data, sha256 = _decode_payload_bytes(
            payload or "",
            is_base64=bool(payload_base64),
            max_bytes=int(FILE_SCAN_MAX_BYTES or 0),
        )
        filename = "payload.bin" if payload_base64 else "payload.txt"
        content_type = (
            "application/octet-stream"
            if payload_base64
            else "text/plain; charset=utf-8"
        )

    scan_timeout_seconds = float(CLAMAV_TIMEOUT_SECONDS or 0) or 8.0
    warmup_wait_seconds = min(10.0, max(2.0, scan_timeout_seconds))

    async def _ensure_clamd_ready() -> None:
        # clamd can be briefly unavailable on cold start or signature reload; wait a bit
        # so users don't have to click "Scan" twice.
        deadline = time.monotonic() + warmup_wait_seconds
        delay = 0.25
        ping_timeout = min(0.5, scan_timeout_seconds)
        while True:
            if await asyncio.to_thread(
                clamd_ping,
                host=CLAMAV_HOST,
                port=CLAMAV_PORT,
                timeout_seconds=ping_timeout,
            ):
                return
            if time.monotonic() >= deadline:
                raise ClamAVConnectionError("clamd is not ready yet")
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 1.0)

    started = time.monotonic()
    try:
        await _ensure_clamd_ready()
        try:
            result = await asyncio.to_thread(
                clamd_scan_bytes,
                data,
                host=CLAMAV_HOST,
                port=CLAMAV_PORT,
                timeout_seconds=scan_timeout_seconds,
            )
        except (ClamAVConnectionError, ClamAVProtocolError):
            # One retry after a short delay for transient clamd startup/reload issues.
            await asyncio.sleep(0.5)
            await _ensure_clamd_ready()
            result = await asyncio.to_thread(
                clamd_scan_bytes,
                data,
                host=CLAMAV_HOST,
                port=CLAMAV_PORT,
                timeout_seconds=scan_timeout_seconds,
            )
    except ClamAVConnectionError as e:
        logger.warning("ClamAV is unavailable: %s", e)
        raise HTTPException(status_code=503, detail="ClamAV is unavailable")
    except ClamAVError as e:
        logger.warning("ClamAV scan failed: %s", e)
        raise HTTPException(status_code=502, detail="ClamAV scan failed")

    duration_ms = int((time.monotonic() - started) * 1000)

    version = None
    if FILE_SCAN_INCLUDE_VERSION:
        try:
            version = clamd_version(
                host=CLAMAV_HOST,
                port=CLAMAV_PORT,
                timeout_seconds=min(2.0, float(CLAMAV_TIMEOUT_SECONDS or 0) or 2.0),
            )
        except ClamAVError:
            version = None

    response: dict = {
        "scan_id": str(uuid4()),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "input_type": input_type,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(data),
        "sha256": sha256,
        "engine": "clamav",
        "verdict": result.verdict,
        "duration_ms": duration_ms,
        "clamav": {
            "host": CLAMAV_HOST,
            "port": CLAMAV_PORT,
            "response": result.raw,
        },
    }

    if result.signature:
        response["signature"] = result.signature
    if result.error:
        response["clamav"]["error"] = result.error
    if version:
        response["clamav"]["version"] = version

    return response


@app.post("/scan")
async def enqueue_scan(
    req: ScanRequest, api_key_hash: Optional[str] = Security(require_api_key)
):
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
    correlation_id = str(uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()
    visibility = _normalize_visibility(getattr(req, "visibility", None))
    if str(getattr(req, "type", "url") or "url").strip().lower() != "url":
        # Never treat non-URL scans as shared/cacheable.
        visibility = "private"

    run_payload = {
        "job_id": run_id,
        "correlation_id": correlation_id,
        "url": req.url,
        "type": req.type,
        "source": req.source,
        "metadata": req.metadata or {},
        "submitted_at": submitted_at,
        "api_key_hash": api_key_hash or "",
        "visibility": visibility,
    }
    try:
        run_payload = validate_scan_task_v1(run_payload)
    except ScanMessageValidationError as e:
        log_with_context(
            logger, logging.WARNING, "Invalid scan request", url=req.url, error=str(e)
        )
        raise HTTPException(status_code=400, detail=str(e))

    await _validate_scan_url(run_payload["url"])

    url_index_key = None
    if _URL_DEDUPE.enabled and visibility == "shared" and run_payload.get("type") == "url":
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
                run_entity = await _get_result_entity(existing_run_id)
                if run_entity:
                    run_visibility = str(run_entity.get("visibility") or "").strip().lower()
                    if run_visibility != "shared":
                        # Do not reuse "private" (or legacy) runs across API keys.
                        run_entity = None
                if run_entity:
                    run_status = str(
                        run_entity.get("status") or existing.get("status") or "unknown"
                    )
                    run_scanned_at = run_entity.get("scanned_at") or None
                    run_error = run_entity.get("error") or None
                    run_correlation_id = run_entity.get("correlation_id") or correlation_id

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
                    return {
                        "job_id": request_id,
                        "status": run_status,
                        "deduped": True,
                    }
    try:
        await _enqueue_json(
            run_payload,
            schema="scan-v1",
            message_id=run_id,
            application_properties={"correlation_id": correlation_id},
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
        return {"job_id": request_id, "status": "queued", "deduped": False}
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


@app.get("/jobs")
async def list_jobs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = Query(
        None, description="Optional CSV status filter (e.g. queued,fetching,completed)"
    ),
    api_key_hash: Optional[str] = Security(require_api_key),
):
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

    items = await list_jobs_async(
        backend=RESULT_BACKEND,
        api_key_hash_value=api_key_hash,
        limit=int(limit or 0),
        statuses=statuses,
        table_client=table_client,
        redis_client=redis_client,
    )

    base_url = str(request.base_url).rstrip("/")
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
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
        visibility_out = (item.get("visibility") or None) if isinstance(item.get("visibility"), str) else None

        if run_id:
            run_entity = await _get_result_entity(run_id)
            if isinstance(run_entity, dict) and run_entity:
                status_out = run_entity.get("status") or status_out
                scanned_at_out = run_entity.get("scanned_at") or scanned_at_out
                error_out = run_entity.get("error") or error_out
                correlation_id_out = run_entity.get("correlation_id") or correlation_id_out

        out.append(
            {
                "job_id": job_id,
                "status": status_out,
                "submitted_at": item.get("submitted_at") or None,
                "scanned_at": scanned_at_out,
                "url": item.get("url") or None,
                "error": error_out,
                "correlation_id": correlation_id_out,
                "deduped": deduped_out,
                "visibility": visibility_out,
                "dashboard_url": f"{base_url}/?job={job_id}",
            }
        )

    return {"jobs": out}


@app.delete("/jobs")
async def clear_jobs(api_key_hash: Optional[str] = Security(require_api_key)):
    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if not api_key_hash:
        raise HTTPException(status_code=401, detail="Missing API key")

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

        try:
            pipe = redis_client.pipeline()
            for jid_s in job_ids_norm:
                pipe.delete(f"{REDIS_JOB_INDEX_HASH_PREFIX}{api_key_hash}:{jid_s}")
                pipe.delete(f"{REDIS_RESULT_PREFIX}{jid_s}")
            pipe.delete(zkey)
            results = await pipe.execute()
        except Exception:
            results = []

        # Each DEL returns the number of keys removed (0/1).
        n = len(job_ids_norm)
        if isinstance(results, list) and len(results) >= (2 * n):
            try:
                deleted_job_index = sum(int(x or 0) for x in results[0 : 2 * n : 2])
                deleted_request_results = sum(int(x or 0) for x in results[1 : 2 * n : 2])
            except Exception:
                deleted_job_index = 0
                deleted_request_results = 0
        return {
            "backend": "redis",
            "api_key_hash": api_key_hash,
            "deleted_job_index_records": deleted_job_index,
            "deleted_request_results": deleted_request_results,
        }

    if RESULT_BACKEND == "table":
        pk = job_index_partition_key(api_key_hash_value=api_key_hash)
        filt = f"PartitionKey eq '{pk}'"
        try:
            pager = table_client.query_entities(query_filter=filt, results_per_page=200)
            async for entity in pager:
                if not isinstance(entity, dict):
                    continue
                row_key = str(entity.get("RowKey") or "").strip()
                request_id = str(entity.get("job_id") or "").strip()

                if row_key:
                    try:
                        await table_client.delete_entity(partition_key=pk, row_key=row_key)
                        deleted_job_index += 1
                    except Exception:
                        pass

                if request_id:
                    try:
                        await table_client.delete_entity(
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
            "job_index_partition_key": pk,
            "result_partition_key": RESULT_PARTITION,
            "deleted_job_index_records": deleted_job_index,
            "deleted_request_results": deleted_request_results,
        }

    raise HTTPException(status_code=500, detail=f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}")


@app.get("/scan/{job_id}")
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

    entity = await _get_result_entity(job_id)
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
        if owner_hash and api_key_hash and not secrets.compare_digest(owner_hash, api_key_hash):
            raise HTTPException(status_code=404, detail="Scan result not found")

        run_entity = await _get_result_entity(run_id)
        if not run_entity:
            return {
                "job_id": job_id,
                "status": "pending",
                "summary": {"url": entity.get("url") or None} if entity.get("url") else None,
                "deduped": _coerce_bool(entity.get("deduped")),
                "visibility": (entity.get("visibility") or None),
            }

        details = _parse_details(run_entity.get("details"))
        summary = _build_summary(run_entity, details)

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
        response = {
            "job_id": job_id,
            "status": run_entity.get("status", "unknown"),
            "dashboard_url": f"{base_url}/?job={job_id}",
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
    if owner_hash and api_key_hash and not secrets.compare_digest(owner_hash, api_key_hash):
        raise HTTPException(status_code=404, detail="Scan result not found")

    details = _parse_details(entity.get("details"))
    summary = _build_summary(entity, details)

    log_with_context(
        logger,
        logging.INFO,
        "Scan result retrieved",
        job_id=job_id,
        status=entity.get("status"),
        duration_ms=_safe_int(entity.get("duration_ms")),
    )

    base_url = str(request.base_url).rstrip("/")
    response = {
        "job_id": job_id,
        "status": entity.get("status", "unknown"),
        "dashboard_url": f"{base_url}/?job={job_id}",
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


@app.get("/scan/{job_id}/screenshot")
async def get_scan_screenshot(
    job_id: str, api_key_hash: Optional[str] = Security(require_api_key)
):
    log_with_context(
        logger,
        logging.INFO,
        "Fetching screenshot",
        job_id=job_id,
        backend=RESULT_BACKEND,
    )

    entity = await _get_result_entity(job_id)
    if not entity:
        raise HTTPException(status_code=404, detail="Screenshot not found")

    target_job_id = job_id
    run_id = str(entity.get("run_id") or "").strip()
    if run_id:
        # Request record: enforce access on the request, then resolve to the run for storage.
        owner_hash = str(entity.get("api_key_hash") or "").strip()
        if owner_hash and api_key_hash and not secrets.compare_digest(owner_hash, api_key_hash):
            raise HTTPException(status_code=404, detail="Screenshot not found")
        target_job_id = run_id
    else:
        owner_hash = str(entity.get("api_key_hash") or "").strip()
        if owner_hash and api_key_hash and not secrets.compare_digest(owner_hash, api_key_hash):
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
