import base64
from contextlib import asynccontextmanager
from collections import deque
from datetime import datetime, timezone
import asyncio
import hashlib
import html
import json
import logging
import os
from pathlib import Path
import secrets
import time
from typing import Optional
from uuid import uuid4

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError
from azure.data.tables.aio import TableServiceClient
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Security, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

from common.clamav_client import (
    ClamAVConnectionError,
    ClamAVError,
    ClamAVProtocolError,
    clamd_ping,
    clamd_scan_bytes,
    clamd_version,
)
from common.result_store import get_result_async, upsert_result_async
from common.url_validation import UrlValidationError, validate_public_https_url_async

# ---------- Settings ----------
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")  # connection string (current)
SERVICEBUS_FQDN = os.getenv(
    "SERVICEBUS_FQDN"
)  # e.g. "mynamespace.servicebus.windows.net"
USE_MI = os.getenv("USE_MANAGED_IDENTITY", "false").lower() in ("1", "true", "yes")
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN") or os.getenv(
    "APPLICATIONINSIGHTS_CONNECTION_STRING"
)  # optional
RESULT_BACKEND = os.getenv("RESULT_BACKEND", "table").strip().lower()
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")

# Local dev backends (Redis)
REDIS_URL = os.getenv("REDIS_URL")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", f"queue:{QUEUE_NAME}")
REDIS_RESULT_PREFIX = os.getenv("REDIS_RESULT_PREFIX", "scan:")
REDIS_RESULT_TTL_SECONDS = int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0"))

logger = logging.getLogger("aca.api")

# API hardening
API_KEY = os.getenv("API_KEY")
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)
MAX_DASHBOARD_POLL_SECONDS = int(os.getenv("MAX_DASHBOARD_POLL_SECONDS", "180"))

# File scanning (ClamAV)
CLAMAV_HOST = (os.getenv("CLAMAV_HOST", "127.0.0.1") or "127.0.0.1").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT_SECONDS = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "8"))
FILE_SCAN_MAX_BYTES = int(os.getenv("FILE_SCAN_MAX_BYTES", str(10 * 1024 * 1024)))  # 10MB
FILE_SCAN_INCLUDE_VERSION = os.getenv("FILE_SCAN_INCLUDE_VERSION", "true").lower() in (
    "1",
    "true",
    "yes",
)

# HTML dashboard template lives alongside this file.
DASHBOARD_TEMPLATE = Path(__file__).with_name("dashboard.html").read_text(
    encoding="utf-8"
)
FILE_SCANNER_TEMPLATE = Path(__file__).with_name("file_scanner.html").read_text(
    encoding="utf-8"
)

# Globals set during app startup
sb_client: Optional[ServiceBusClient] = None
sb_sender: Optional[ServiceBusSender] = None
table_service: Optional[TableServiceClient] = None
table_client = None
redis_client = None

api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

# Simple in-memory rate limiter (per API key hash); good enough for demos.
_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, deque[float]] = {}


class TaskIn(BaseModel):
    # adjust fields to your real payload
    payload: dict


class ScanRequest(BaseModel):
    url: str = Field(..., description="HTTPS URL to scan")
    type: str = Field("url", pattern="^(url|file)$")
    source: Optional[str] = Field(None, description="Optional source identifier")
    metadata: Optional[dict] = Field(None, description="Optional metadata")


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
                status_code=400, detail="payload_base64=true but payload is not valid base64"
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
        if e.code == "https_only":
            raise HTTPException(status_code=400, detail="Only HTTPS URLs are allowed")
        if e.code == "host_required":
            raise HTTPException(status_code=400, detail="URL host is required")
        if e.code == "userinfo_not_allowed":
            raise HTTPException(
                status_code=400, detail="Userinfo in URL is not allowed"
            )
        if e.code == "port_not_allowed":
            raise HTTPException(
                status_code=400, detail="Only default HTTPS port 443 is allowed"
            )
        if e.code == "localhost_not_allowed":
            raise HTTPException(status_code=400, detail="Localhost is not allowed")
        if e.code == "dns_failed":
            raise HTTPException(status_code=400, detail="DNS resolution failed")
        if e.code == "no_records":
            raise HTTPException(status_code=400, detail="No A/AAAA records found")
        if e.code == "non_public_ip":
            raise HTTPException(
                status_code=400,
                detail="URL resolves to a non-public IP address (blocked)",
            )
        if e.code == "direct_ip_not_public":
            raise HTTPException(
                status_code=400,
                detail="Direct IP destinations must be publicly routable",
            )
        raise HTTPException(status_code=400, detail=str(e))


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
        return
    if not API_KEY:
        raise HTTPException(status_code=500, detail="API_KEY is not configured")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")
    await _enforce_rate_limit(api_key)


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

    # Decision layer (signals → deterministic aggregation)
    if isinstance(details, dict) and isinstance(details.get("decision"), dict):
        d = details["decision"]
        decision_out: dict = {}
        for key in ("final_verdict", "confidence", "action"):
            val = d.get(key)
            if val is None or val == "":
                continue
            decision_out[key] = val
        reasons = d.get("reasons")
        if isinstance(reasons, list):
            decision_out["reasons"] = [str(r) for r in reasons if r][:10]
        if decision_out:
            summary["decision"] = decision_out

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
    global sb_client, sb_sender, table_service, table_client, redis_client

    cred = None  # will hold DefaultAzureCredential if MI is used
    if QUEUE_BACKEND not in ("servicebus", "redis"):
        raise RuntimeError("QUEUE_BACKEND must be 'servicebus' or 'redis'")
    if RESULT_BACKEND not in ("table", "redis"):
        raise RuntimeError("RESULT_BACKEND must be 'table' or 'redis'")

    # --- Optional Redis client (local dev backends) ---
    if (QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis") and not REDIS_URL:
        raise RuntimeError("REDIS_URL is required when using Redis backends")

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
        if USE_MI:
            try:
                from azure.identity.aio import DefaultAzureCredential
            except Exception as e:
                raise RuntimeError(
                    "USE_MANAGED_IDENTITY=true but azure-identity is not installed"
                ) from e
            if not SERVICEBUS_FQDN:
                raise RuntimeError(
                    "SERVICEBUS_FQDN is required when using Managed Identity"
                )
            cred = DefaultAzureCredential()
            sb_client = ServiceBusClient(
                fully_qualified_namespace=SERVICEBUS_FQDN, credential=cred
            )
        else:
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

    # --- Optional App Insights logging (only if packages + conn are present) ---
    if APPINSIGHTS_CONN:
        try:
            from opencensus.ext.azure.log_exporter import AzureLogHandler

            if not any(isinstance(h, AzureLogHandler) for h in logger.handlers):
                logger.addHandler(AzureLogHandler(connection_string=APPINSIGHTS_CONN))
                logger.info("App Insights logging enabled.")
        except Exception as e:
            logger.warning(f"App Insights logging not enabled: {e}")

    # --- Optional OpenTelemetry tracing (only if packages + conn are present) ---
    if APPINSIGHTS_CONN:
        try:
            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
            from opentelemetry import trace
            from opentelemetry.sdk.resources import SERVICE_NAME, Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({SERVICE_NAME: "aca-fastapi-api"})
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
            exporter = AzureMonitorTraceExporter.from_connection_string(
                APPINSIGHTS_CONN
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except Exception as e:
            # Optional; don't fail app startup on telemetry wiring issues
            print("OTel init skipped:", e)

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
    if cred:
        # Properly close the async credential if used
        await cred.close()


app = FastAPI(title="Azure DevSecOps URL Scanner", lifespan=lifespan)


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
                "Unhandled exception in request: %s %s", request.method, request.url.path
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
                    .startswith("application/json")
                ):
                    body = getattr(response, "body", None)
                    if body:
                        parsed = json.loads(body.decode("utf-8"))
                        if isinstance(parsed, dict) and parsed.get("detail") is not None:
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
    return {"ok": True}


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
    _: None = Security(require_api_key),
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
            "application/octet-stream" if payload_base64 else "text/plain; charset=utf-8"
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
        raise HTTPException(
            status_code=503,
            detail=f"ClamAV is unavailable ({CLAMAV_HOST}:{CLAMAV_PORT}): {e}",
        )
    except ClamAVError as e:
        raise HTTPException(status_code=502, detail=f"ClamAV scan failed: {e}")

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


@app.post("/tasks")
async def enqueue_task(task: TaskIn, _: None = Security(require_api_key)):
    try:
        await _enqueue_json(task.payload, schema="task-v1", message_id=str(uuid4()))
        return {"status": "queued", "item": task.payload}
    except HTTPException:
        raise
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.post("/scan")
async def enqueue_scan(req: ScanRequest, _: None = Security(require_api_key)):
    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")

    await _validate_scan_url(req.url)
    job_id = str(uuid4())
    correlation_id = str(uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "job_id": job_id,
        "correlation_id": correlation_id,
        "url": req.url,
        "type": req.type,
        "source": req.source,
        "metadata": req.metadata or {},
        "submitted_at": submitted_at,
    }
    try:
        await _enqueue_json(
            payload,
            schema="scan-v1",
            message_id=job_id,
            application_properties={"correlation_id": correlation_id},
        )
        await _upsert_result(
            job_id,
            status="queued",
            details={"url": req.url, "type": req.type, "source": req.source},
            extra={"submitted_at": submitted_at},
        )
        return {"job_id": job_id, "status": "queued"}
    except HTTPException:
        raise
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.get("/scan/{job_id}")
async def get_scan_status(
    job_id: str,
    view: str = Query("summary", description="Response view: summary or full"),
    _: None = Security(require_api_key),
):
    view = (view or "summary").strip().lower()
    if view not in ("summary", "full"):
        raise HTTPException(status_code=400, detail="view must be 'summary' or 'full'")

    entity = await _get_result_entity(job_id)
    if not entity:
        return {"job_id": job_id, "status": "pending", "summary": None}

    details = _parse_details(entity.get("details"))
    summary = _build_summary(entity, details)

    response = {
        "job_id": job_id,
        "status": entity.get("status", "unknown"),
        "verdict": entity.get("verdict") or None,
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
