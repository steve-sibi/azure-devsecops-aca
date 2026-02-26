"""
FastAPI entrypoint for the URL + file scanning demo.

Responsibilities:
- Authenticate requests with `X-API-Key` (unless `REQUIRE_API_KEY=false`) and enforce
  a simple per-key rate limit.
- Accept scan submissions (`POST /scan`), enqueue jobs (Service Bus or Redis), and
  expose results (`GET /scan/{job_id}`) from the configured result backend.
- Provide a lightweight HTML dashboard (`GET /`) and file-scan UI (`GET /file`).
- Provide optional screenshot retrieval (`GET /scan/{job_id}/screenshot`) when the
  worker is configured to capture screenshots.

Key env vars (see `.env.example` / README):
`QUEUE_BACKEND`, `SERVICEBUS_CONN`, `RESULT_BACKEND`, `RESULT_STORE_CONN`, `REDIS_URL`,
`API_KEY`/`ACA_API_KEYS`, `REQUIRE_API_KEY`, `RATE_LIMIT_RPM`, `BLOCK_PRIVATE_NETWORKS`.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import time
from contextlib import asynccontextmanager
from http import HTTPStatus
from uuid import uuid4

from azure.data.tables.aio import TableServiceClient
from azure.servicebus.aio import ServiceBusClient
from common.logging_config import (
    clear_correlation_id,
    get_logger,
    log_with_context,
    set_correlation_id,
    setup_logging,
)
from common.telemetry import extract_trace_context, setup_telemetry
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

import runtime
import settings

# Re-export commonly used internals for direct unit tests.
import routes.admin as admin_routes
import routes.file_scan as file_scan_routes
import routes.realtime as realtime_routes
import routes.scan as scan_routes
from deps.auth import _rate_buckets, require_admin_api_key, require_api_key
from deps.store import _enqueue_json, _get_result_entity, _upsert_result
from models import ApiKeyMintRequest, PubSubNegotiateRequest, ScanRequest
from routes.admin import admin_list_api_keys, admin_mint_api_key, admin_revoke_api_key
from routes.file_scan import scan_file
from routes.realtime import pubsub_negotiate, pubsub_negotiate_user, stream_job_updates
from routes.scan import clear_jobs, enqueue_scan, get_scan_screenshot, get_scan_status, list_jobs

__all__ = [
    "_enqueue_json",
    "_get_result_entity",
    "_rate_buckets",
    "_upsert_result",
    "ApiKeyMintRequest",
    "PubSubNegotiateRequest",
    "ScanRequest",
    "admin_list_api_keys",
    "admin_mint_api_key",
    "admin_revoke_api_key",
    "app",
    "clear_jobs",
    "enqueue_scan",
    "get_scan_screenshot",
    "get_scan_status",
    "healthz",
    "list_jobs",
    "otel_request_spans",
    "pubsub_negotiate",
    "pubsub_negotiate_user",
    "require_admin_api_key",
    "require_api_key",
    "scan_file",
    "stream_job_updates",
]

# ---------- Logging Setup ----------
setup_logging(service_name="api", level=logging.INFO)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    runtime.init_app_state(app)

    # Validate shared configuration
    settings._CONSUMER_CFG.validate()
    runtime.set_telemetry_active(
        setup_telemetry(service_name="api", logger_obj=logger),
        app,
    )

    if settings.QUEUE_BACKEND == "redis" or settings.RESULT_BACKEND == "redis":
        try:
            import redis.asyncio as redis_async
        except Exception as e:
            raise RuntimeError(
                "Redis backends require the 'redis' package (pip install redis)"
            ) from e
        redis_client = redis_async.from_url(settings.REDIS_URL, decode_responses=True)
        await redis_client.ping()
        runtime.set_redis_client(redis_client, app)

    # --- Queue backend ---
    if settings.QUEUE_BACKEND == "servicebus":
        if not settings.SERVICEBUS_CONN:
            raise RuntimeError("SERVICEBUS_CONN environment variable is required")
        sb_client = ServiceBusClient.from_connection_string(settings.SERVICEBUS_CONN)
        await sb_client.__aenter__()
        runtime.set_sb_client(sb_client, app)

        sb_sender = sb_client.get_queue_sender(queue_name=settings.QUEUE_NAME)
        await sb_sender.__aenter__()
        runtime.set_sb_sender(sb_sender, app)

    # --- Result store backend ---
    if settings.RESULT_BACKEND == "table":
        if not settings.RESULT_STORE_CONN:
            raise RuntimeError("RESULT_STORE_CONN environment variable is required")
        table_service = TableServiceClient.from_connection_string(
            conn_str=settings.RESULT_STORE_CONN
        )
        table_client = table_service.get_table_client(table_name=settings.RESULT_TABLE)
        await table_service.__aenter__()
        await table_service.create_table_if_not_exists(table_name=settings.RESULT_TABLE)
        runtime.set_table_service(table_service, app)
        runtime.set_table_client(table_client, app)

        # Screenshots are stored in Blob Storage when using Table results.
        try:
            from azure.storage.blob.aio import BlobServiceClient as AioBlobServiceClient

            blob_service = AioBlobServiceClient.from_connection_string(
                settings.RESULT_STORE_CONN
            )
            await blob_service.__aenter__()
            runtime.set_blob_service(blob_service, app)
        except Exception as e:
            runtime.set_blob_service(None, app)
            logger.warning("Blob client not initialized (screenshots disabled): %s", e)

    runtime.refresh_live_updates_backend(
        obj=app,
        redis_available=bool(runtime.get_redis_client(app)),
    )

    yield  # ---- App runs ----

    # ---- Cleanup on shutdown ----
    sb_sender = runtime.get_sb_sender(app)
    sb_client = runtime.get_sb_client(app)
    table_service = runtime.get_table_service(app)
    redis_client = runtime.get_redis_client(app)
    blob_service = runtime.get_blob_service(app)

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


# OpenAPI metadata for /docs
API_TAGS_METADATA = [
    {
        "name": "URL Scanning",
        "description": "Submit URLs for comprehensive security analysis including malware detection, phishing indicators, SSL/TLS validation, and content analysis.",
    },
    {
        "name": "File Scanning",
        "description": "Upload files for malware detection using ClamAV antivirus engine.",
    },
    {
        "name": "Jobs",
        "description": "View, manage, and retrieve results for submitted scan jobs.",
    },
    {
        "name": "Health",
        "description": "API health check and status monitoring.",
    },
    {
        "name": "Admin",
        "description": "Admin endpoints for API key lifecycle management.",
    },
]

app = FastAPI(
    title="URL Security Scanner",
    description="""
A cloud-native security scanning API for analyzing URLs and files for potential threats.

## Features

* **URL Security Analysis** - Comprehensive scanning including SSL/TLS validation, security headers, content analysis, and phishing detection
* **Malware Detection** - File scanning powered by ClamAV antivirus engine
* **YARA Rules** - Custom pattern matching for threat detection
* **Async Processing** - Queue-based architecture for scalable scanning
* **Screenshot Capture** - Visual evidence of scanned web pages

## Authentication

All endpoints require an API key passed via the `X-API-Key` header.
""",
    version="1.0.0",
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT",
    },
    openapi_tags=API_TAGS_METADATA,
    lifespan=lifespan,
)
runtime.init_app_state(app)

app.include_router(admin_routes.router)
app.include_router(realtime_routes.router)
app.include_router(file_scan_routes.router)
app.include_router(scan_routes.router)


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

    started = time.perf_counter()
    try:
        response = await call_next(request)
        route = request.scope.get("route")
        route_path = getattr(route, "path", None) or request.url.path
        duration_ms = int((time.perf_counter() - started) * 1000)
        log_with_context(
            logger,
            logging.INFO,
            "HTTP request completed",
            http_method=request.method,
            http_route=route_path,
            http_status_code=response.status_code,
            duration_ms=duration_ms,
            correlation_id=correlation_id,
        )
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Request-ID"] = correlation_id
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
    if not runtime.is_telemetry_active(request) or request.url.path == "/healthz":
        return await call_next(request)

    from opentelemetry import trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    tracer = trace.get_tracer("aca-fastapi-api")
    span_name = f"{request.method} {request.url.path}"
    parent_ctx = extract_trace_context(
        traceparent=request.headers.get("traceparent"),
        tracestate=request.headers.get("tracestate"),
    )

    with tracer.start_as_current_span(
        span_name, context=parent_ctx, kind=SpanKind.SERVER
    ) as span:
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


@app.get("/healthz", tags=["Health"])
async def healthz():
    return {
        "ok": True,
        "queue_backend": settings.QUEUE_BACKEND,
        "result_backend": settings.RESULT_BACKEND,
        "live_updates_backend": runtime.get_live_updates_backend(app),
        "url_dedupe": {
            "enabled": bool(settings._URL_DEDUPE.enabled),
            "ttl_seconds": int(settings._URL_DEDUPE.ttl_seconds or 0),
            "in_progress_ttl_seconds": int(settings._URL_DEDUPE.in_progress_ttl_seconds or 0),
            "scope": settings._URL_DEDUPE.scope,
            "index_partition": settings._URL_DEDUPE.index_partition,
        },
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    template = settings.DASHBOARD_TEMPLATE
    api_key_header_html = html.escape(settings.API_KEY_HEADER or "")
    api_key_header_json = json.dumps(settings.API_KEY_HEADER or "X-API-Key")
    live_updates_backend_json = json.dumps(runtime.get_live_updates_backend(app) or "none")
    return (
        template.replace("__API_KEY_HEADER__", api_key_header_html)
        .replace("__API_KEY_HEADER_JSON__", api_key_header_json)
        .replace("__LIVE_UPDATES_BACKEND_JSON__", live_updates_backend_json)
        .replace(
            "__MAX_DASHBOARD_POLL_SECONDS__",
            str(int(settings.MAX_DASHBOARD_POLL_SECONDS or 0)),
        )
    )


@app.get("/file", response_class=HTMLResponse, include_in_schema=False)
async def file_scanner():
    template = settings.FILE_SCANNER_TEMPLATE
    api_key_header_html = html.escape(settings.API_KEY_HEADER or "")
    api_key_header_json = json.dumps(settings.API_KEY_HEADER or "X-API-Key")
    return (
        template.replace("__API_KEY_HEADER__", api_key_header_html)
        .replace("__API_KEY_HEADER_JSON__", api_key_header_json)
        .replace("__FILE_SCAN_MAX_BYTES__", str(int(settings.FILE_SCAN_MAX_BYTES or 0)))
    )
