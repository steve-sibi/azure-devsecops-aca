"""
Analyzer stage (URL scan pipeline).

Consumes `scan-artifact-v1` messages from the "scan" queue, analyzes the artifact
bytes (web/content heuristics) and persists results for `GET /scan/{job_id}`.

Optional: captures a browser screenshot via Playwright and stores it alongside
results (Redis locally, Blob Storage when using Table results).
"""

import hashlib
import logging
import os
import secrets
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from azure.data.tables import TableClient
from common.config import (
    ConsumerConfig,
    ResultPersister,
    init_redis_client,
    init_table_client,
)
from common.errors import classify_exception
from common.limits import (
    ScreenshotLimits,
    get_web_analysis_limits,
    get_web_fetch_limits,
)
from common.logging_config import (
    clear_correlation_id,
    get_logger,
    log_with_context,
    set_correlation_id,
    setup_logging,
)
from common.message_consumer import ShutdownFlag, install_signal_handlers, run_consumer
from common.scan_messages import validate_scan_artifact_v1
from common.screenshot_store import (
    redis_screenshot_key,
    store_screenshot_blob_sync,
    store_screenshot_redis_sync,
)
from common.telemetry import extract_trace_context, get_tracer, setup_telemetry
from common.webpubsub import WebPubSubConfig, WebPubSubPublisher
from common.url_canonicalization import canonicalize_url
from common.web_analysis import (
    analyze_html,
    find_open_redirects,
    rdap_whois,
    registrable_domain,
    resolve_dns_addresses,
)
from screenshot_capture import capture_website_screenshot
from web_fetch import download_url

# ---- Config via env ----
_CFG = ConsumerConfig.from_env()

QUEUE_BACKEND = _CFG.queue_backend
SERVICEBUS_CONN = _CFG.servicebus_conn
QUEUE_NAME = _CFG.queue_name
BATCH_SIZE = _CFG.batch_size
MAX_WAIT = _CFG.max_wait  # seconds
PREFETCH = _CFG.prefetch
MAX_RETRIES = _CFG.max_retries  # move to DLQ after this many deliveries
RESULT_BACKEND = _CFG.result_backend
RESULT_STORE_CONN = _CFG.result_store_conn
RESULT_TABLE = _CFG.result_table
RESULT_PARTITION = _CFG.result_partition
BLOCK_PRIVATE_NETWORKS = get_web_fetch_limits().block_private_networks

# Local dev backends (Redis)
REDIS_URL = _CFG.redis_url
REDIS_QUEUE_KEY = _CFG.redis_queue_key
REDIS_DLQ_KEY = _CFG.redis_dlq_key
REDIS_RESULT_PREFIX = _CFG.redis_result_prefix
REDIS_RESULT_TTL_SECONDS = _CFG.redis_result_ttl_seconds

# ---- Artifact handoff (fetcher -> analyzer) ----
ARTIFACT_DIR = _CFG.artifact_dir
ARTIFACT_DELETE_ON_SUCCESS = os.getenv(
    "ARTIFACT_DELETE_ON_SUCCESS", "false"
).lower() in (
    "1",
    "true",
    "yes",
)

# Web analysis tuning (UI-focused)
_WEB_LIMITS = get_web_analysis_limits()
WEB_MAX_RESOURCES = _WEB_LIMITS.max_resources
WEB_MAX_INLINE_SCRIPT_CHARS = _WEB_LIMITS.max_inline_script_chars
WEB_MAX_HTML_BYTES = _WEB_LIMITS.max_html_bytes
WEB_WHOIS_TIMEOUT_SECONDS = _WEB_LIMITS.whois_timeout_seconds

# Screenshot capture (optional)
SCREENSHOT_REDIS_PREFIX = os.getenv("SCREENSHOT_REDIS_PREFIX", "screenshot:")
SCREENSHOT_CONTAINER = os.getenv("SCREENSHOT_CONTAINER", "screenshots")
SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "jpeg")
_SCREENSHOT_LIMITS = ScreenshotLimits.from_env(
    default_ttl_seconds=REDIS_RESULT_TTL_SECONDS
)
SCREENSHOT_TIMEOUT_SECONDS = _SCREENSHOT_LIMITS.timeout_seconds
SCREENSHOT_VIEWPORT_WIDTH = _SCREENSHOT_LIMITS.viewport_width
SCREENSHOT_VIEWPORT_HEIGHT = _SCREENSHOT_LIMITS.viewport_height
SCREENSHOT_FULL_PAGE = _SCREENSHOT_LIMITS.full_page
SCREENSHOT_JPEG_QUALITY = _SCREENSHOT_LIMITS.jpeg_quality
SCREENSHOT_TTL_SECONDS = _SCREENSHOT_LIMITS.ttl_seconds

# ---- Logging (console + optional App Insights) ----
setup_logging(service_name="worker", level=logging.INFO)
logger = get_logger(__name__)

shutdown_flag = ShutdownFlag()
install_signal_handlers(shutdown_flag)

table_client: Optional[TableClient] = None
redis_client = None
result_persister: Optional[ResultPersister] = None


def process(task: dict):
    task = validate_scan_artifact_v1(task)
    job_id = task.get("job_id")
    url = task.get("url")
    correlation_id = task.get("correlation_id")
    api_key_hash = task.get("api_key_hash")
    visibility = task.get("visibility")
    traceparent = task.get("traceparent")
    tracestate = task.get("tracestate")

    if correlation_id:
        set_correlation_id(str(correlation_id))
    parent_ctx = extract_trace_context(
        traceparent=str(traceparent) if isinstance(traceparent, str) else None,
        tracestate=str(tracestate) if isinstance(tracestate, str) else None,
    )

    tracer = get_tracer("aca-worker")
    span_cm = (
        tracer.start_as_current_span("worker.process", context=parent_ctx)
        if tracer
        else nullcontext()
    )
    try:
        with span_cm as span:
            if span:
                span.set_attribute("app.component", "worker")
                span.set_attribute("app.job_id", str(job_id))
                span.set_attribute("app.queue_name", str(QUEUE_NAME))
                if isinstance(url, str):
                    span.set_attribute("url.full", url)

            log_with_context(
                logger, logging.INFO, "Processing scan task", job_id=job_id, url=url
            )

            if not url or not job_id:
                raise ValueError("missing url/job_id in task")

            start = time.time()

            read_span_cm = (
                tracer.start_as_current_span("worker.read_artifact")
                if tracer
                else nullcontext()
            )
            with read_span_cm:
                artifact_path = task.get("artifact_path")
                if isinstance(artifact_path, str) and artifact_path.strip():
                    artifact_name = Path(artifact_path).name
                    full_path = Path(ARTIFACT_DIR) / artifact_name
                    content = full_path.read_bytes()
                    size_bytes = len(content)

                    expected_size = task.get("artifact_size_bytes")
                    if expected_size is not None:
                        try:
                            if int(expected_size) != size_bytes:
                                raise ValueError(
                                    f"artifact size mismatch (expected={expected_size} actual={size_bytes})"
                                )
                        except Exception:
                            pass

                    expected_sha = task.get("artifact_sha256")
                    if isinstance(expected_sha, str) and expected_sha:
                        actual_sha = hashlib.sha256(content).hexdigest()
                        if not secrets.compare_digest(actual_sha, expected_sha.lower()):
                            raise ValueError("artifact sha256 mismatch")

                    download = (
                        task.get("download")
                        if isinstance(task.get("download"), dict)
                        else {}
                    )
                else:
                    content, size_bytes, download = download_url(url)

            analyze_span_cm = (
                tracer.start_as_current_span("worker.analyze_content")
                if tracer
                else nullcontext()
            )
            with analyze_span_cm:
                details = _scan_bytes(content, url, download=download)

            screenshot = _maybe_capture_and_store_screenshot(
                job_id=job_id, url=url, download=download
            )
            page_info = None
            results = details.get("results")
            if isinstance(results, dict):
                web = results.get("web")
                if isinstance(web, dict):
                    page_info = web.get("page_information")
            if isinstance(page_info, dict) and isinstance(screenshot, dict) and screenshot:
                url_val = screenshot.get("url")
                if isinstance(url_val, str) and url_val.strip():
                    page_info["screenshot_url"] = url_val.strip()
                page_info["screenshot"] = {
                    k: v for k, v in screenshot.items() if k != "url" and v is not None
                }

            duration_ms = int((time.time() - start) * 1000)
            persist_span_cm = (
                tracer.start_as_current_span("worker.persist_result")
                if tracer
                else nullcontext()
            )
            with persist_span_cm:
                if not result_persister or not result_persister.save_result(
                    job_id=job_id,
                    status="completed",
                    details=details,
                    size_bytes=size_bytes,
                    correlation_id=correlation_id,
                    api_key_hash=api_key_hash,
                    visibility=visibility,
                    duration_ms=duration_ms,
                    submitted_at=task.get("submitted_at"),
                    error=None,
                    url=url,
                    index_job=False,
                ):
                    raise RuntimeError("failed to persist scan result")
            if ARTIFACT_DELETE_ON_SUCCESS:
                artifact_path = task.get("artifact_path")
                if isinstance(artifact_path, str) and artifact_path.strip():
                    try:
                        (Path(ARTIFACT_DIR) / Path(artifact_path).name).unlink(
                            missing_ok=True
                        )
                    except Exception:
                        pass
            log_with_context(
                logger,
                logging.INFO,
                "Scan completed successfully",
                job_id=job_id,
                size_bytes=size_bytes,
                duration_ms=duration_ms,
                url=url,
            )
            return details
    finally:
        clear_correlation_id()


def _screenshot_blob_name(job_id: str) -> str:
    fmt = (SCREENSHOT_FORMAT or "jpeg").strip().lower()
    ext = "png" if fmt == "png" else "jpg"
    return f"{job_id}.{ext}"


def _maybe_capture_and_store_screenshot(
    *, job_id: str, url: str, download: Optional[dict]
) -> dict:
    target_url = url
    if isinstance(download, dict):
        final_url = download.get("final_url")
        if isinstance(final_url, str) and final_url.strip():
            target_url = final_url.strip()

    capture, capture_error = capture_website_screenshot(
        target_url,
        block_private_networks=BLOCK_PRIVATE_NETWORKS,
        timeout_seconds=SCREENSHOT_TIMEOUT_SECONDS,
        viewport_width=SCREENSHOT_VIEWPORT_WIDTH,
        viewport_height=SCREENSHOT_VIEWPORT_HEIGHT,
        full_page=SCREENSHOT_FULL_PAGE,
        image_format=SCREENSHOT_FORMAT,
        jpeg_quality=SCREENSHOT_JPEG_QUALITY,
    )
    if not capture:
        status = "disabled" if capture_error == "disabled" else "failed"
        out = {"status": status}
        if (
            isinstance(capture_error, str)
            and capture_error
            and capture_error != "disabled"
        ):
            out["error"] = capture_error
        return out

    try:
        if RESULT_BACKEND == "redis":
            if not redis_client:
                return {"status": "store_failed", "error": "redis_not_initialized"}
            key = redis_screenshot_key(SCREENSHOT_REDIS_PREFIX, str(job_id))
            store_screenshot_redis_sync(
                redis_client=redis_client,
                key=key,
                image_bytes=capture.image_bytes,
                content_type=capture.content_type,
                ttl_seconds=SCREENSHOT_TTL_SECONDS,
            )
            return {
                "status": "stored",
                "url": f"/scan/{job_id}/screenshot",
                "metrics": capture.metrics,
            }

        if RESULT_BACKEND == "table":
            if not RESULT_STORE_CONN:
                return {"status": "store_failed", "error": "RESULT_STORE_CONN_not_set"}
            store_screenshot_blob_sync(
                conn_str=RESULT_STORE_CONN,
                container=SCREENSHOT_CONTAINER,
                blob_name=_screenshot_blob_name(str(job_id)),
                image_bytes=capture.image_bytes,
                content_type=capture.content_type,
            )
            return {
                "status": "stored",
                "url": f"/scan/{job_id}/screenshot",
                "metrics": capture.metrics,
            }
    except Exception:
        log_with_context(
            logger,
            logging.INFO,
            "Screenshot store failed",
            job_id=job_id,
        )
        return {"status": "store_failed"}

    return {"status": "skipped"}


def _decode_text_sample(content: bytes, *, max_bytes: int) -> str:
    sample = content[: max(0, int(max_bytes))]
    try:
        return sample.decode("utf-8", "replace")
    except Exception:
        try:
            return sample.decode("latin-1", "replace")
        except Exception:
            return ""


def _headers_map_from_download(download: Optional[dict]) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not isinstance(download, dict):
        return headers
    raw = download.get("response_headers")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip().lower()
            if not name:
                continue
            value = str(item.get("value") or "").strip()
            if value:
                headers[name] = value
    elif isinstance(raw, dict):
        for k, v in raw.items():
            name = str(k or "").strip().lower()
            if not name:
                continue
            value = str(v or "").strip()
            if value:
                headers[name] = value
    return headers


def _header_names_from_download(download: Optional[dict]) -> set[str]:
    names: set[str] = set()
    if not isinstance(download, dict):
        return names

    raw = download.get("response_header_names")
    if isinstance(raw, list):
        for item in raw:
            name = str(item or "").strip().lower()
            if name:
                names.add(name)

    # Backward compatibility: older payloads only included the truncated UI list.
    raw = download.get("response_headers")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip().lower()
            if name:
                names.add(name)
    elif isinstance(raw, dict):
        for k in raw.keys():
            name = str(k or "").strip().lower()
            if name:
                names.add(name)

    names.discard("set-cookie")
    return names


def _web_scan(content: bytes, *, url: str, download: Optional[dict] = None) -> dict:
    final_url = url
    content_type = ""
    cookies: list[dict] = []
    if isinstance(download, dict):
        f = download.get("final_url")
        if isinstance(f, str) and f.strip():
            final_url = f.strip()
        ct = download.get("content_type")
        if isinstance(ct, str) and ct:
            content_type = ct.strip()
        ck = download.get("cookies")
        if isinstance(ck, list):
            cookies = [x for x in ck if isinstance(x, dict)]

    header_names = _header_names_from_download(download)
    page_host = (urlparse(final_url).hostname or "").strip().lower().rstrip(".")

    csp_enforced = "content-security-policy" in header_names
    csp_report_only = "content-security-policy-report-only" in header_names
    csp_present = csp_enforced or csp_report_only
    xfo_present = "x-frame-options" in header_names
    x_xss_present = "x-xss-protection" in header_names
    hsts_present = "strict-transport-security" in header_names

    is_html = "html" in (content_type or "").lower()
    if not is_html:
        sniff = content.lstrip()[:50].lower()
        if (
            sniff.startswith(b"<!doctype html")
            or sniff.startswith(b"<html")
            or b"<head" in sniff
        ):
            is_html = True

    parsed = None
    if is_html:
        text = _decode_text_sample(content, max_bytes=WEB_MAX_HTML_BYTES)
        parsed = analyze_html(
            text,
            base_url=final_url,
            max_items=WEB_MAX_RESOURCES,
            max_inline_script_chars=WEB_MAX_INLINE_SCRIPT_CHARS,
        )

    password_fields = parsed.password_fields if parsed else 0
    login_forms = parsed.login_forms if parsed else 0
    csrf_protection = parsed.csrf_protection if parsed else False
    external_scripts = parsed.external_scripts if parsed else 0
    suspicious_scripts = parsed.suspicious_scripts if parsed else 0
    suspicious_api_calls = parsed.suspicious_api_calls if parsed else False
    mixed_content = parsed.mixed_content if parsed else []
    tracking_scripts = parsed.tracking_scripts if parsed else False
    fingerprinting = parsed.fingerprinting if parsed else False
    eval_usage = parsed.eval_usage if parsed else False
    inner_html_usage = parsed.inner_html_usage if parsed else False

    external_script_examples: list[str] = []
    suspicious_ip_script_examples: list[str] = []
    suspicious_inline_indicators: list[str] = []
    suspicious_api_call_examples: list[str] = []
    tracking_resource_examples: list[dict] = []
    tracking_inline_indicators: list[str] = []
    fingerprinting_indicators: list[str] = []
    eval_indicators: list[str] = []
    inner_html_indicators: list[str] = []
    eval_occurrences = 0
    inner_html_occurrences = 0
    if parsed:
        for item in parsed.scripts:
            if not isinstance(item, dict):
                continue
            script_url = item.get("url")
            script_type = item.get("type")
            if script_type == "external" and isinstance(script_url, str) and script_url:
                external_script_examples.append(script_url)
        external_script_examples = external_script_examples[:10]

        suspicious_ip_script_examples = list(
            getattr(parsed, "suspicious_ip_script_examples", []) or []
        )[:5]
        suspicious_inline_indicators = list(
            getattr(parsed, "suspicious_inline_indicators", []) or []
        )[:15]
        suspicious_api_call_examples = list(
            getattr(parsed, "suspicious_api_call_examples", []) or []
        )[:10]
        tracking_resource_examples = list(
            getattr(parsed, "tracking_resource_examples", []) or []
        )[:10]
        tracking_inline_indicators = list(
            getattr(parsed, "tracking_inline_indicators", []) or []
        )[:10]
        fingerprinting_indicators = list(
            getattr(parsed, "fingerprinting_indicators", []) or []
        )[:10]
        eval_indicators = list(getattr(parsed, "eval_indicators", []) or [])[:10]
        inner_html_indicators = list(
            getattr(parsed, "inner_html_indicators", []) or []
        )[:10]
        eval_occurrences = int(getattr(parsed, "eval_occurrences", 0) or 0)
        inner_html_occurrences = int(getattr(parsed, "inner_html_occurrences", 0) or 0)

    open_redirects = {"detected": False, "examples": []}
    if parsed:
        candidate_urls: list[str] = []
        for item in parsed.links:
            if isinstance(item, dict) and isinstance(item.get("url"), str):
                candidate_urls.append(item["url"])
        candidate_urls.extend([u for u in parsed.form_actions if isinstance(u, str)])
        open_redirects = find_open_redirects(candidate_urls, page_host=page_host)

    insecure_cookies = []
    for c in cookies:
        issues = c.get("issues")
        if isinstance(issues, list) and issues:
            insecure_cookies.append(c)

    analysis = {
        "connection_security": {
            "protocol": (urlparse(final_url).scheme or "").upper() or "HTTPS",
            "mixed_content": {
                "detected": bool(mixed_content),
                "count": int(len(mixed_content)),
                "examples": mixed_content[:5],
            },
        },
        "security_headers": {
            "content_security_policy": {
                "present": bool(csp_present),
                "enforced": bool(csp_enforced),
                "report_only": bool(csp_report_only),
            },
            "x_frame_options": {"present": bool(xfo_present)},
            "x_xss_protection": {"present": bool(x_xss_present)},
            "strict_transport_security": {"present": bool(hsts_present)},
        },
        "forms_and_input": {
            "login_forms": int(login_forms),
            "password_fields": int(password_fields),
            "csrf_protection": bool(csrf_protection),
        },
        "suspicious_scripts": {
            "suspicious_scripts": int(suspicious_scripts),
            "external_scripts": int(external_scripts),
            "suspicious_api_calls": bool(suspicious_api_calls),
            "external_script_examples": external_script_examples,
            "suspicious_ip_script_examples": suspicious_ip_script_examples,
            "suspicious_inline_indicators": suspicious_inline_indicators,
            "suspicious_api_call_examples": suspicious_api_call_examples,
        },
        "cookies": {
            "insecure_cookies": int(len(insecure_cookies)),
            "details": insecure_cookies[:20],
        },
        "detectable_vulnerabilities": {
            "open_redirects": bool(open_redirects.get("detected")),
            "open_redirect_examples": open_redirects.get("examples") or [],
            "inner_html_usage": bool(inner_html_usage),
            "inner_html_indicators": inner_html_indicators,
            "inner_html_occurrences": int(inner_html_occurrences),
            "eval_usage": bool(eval_usage),
            "eval_indicators": eval_indicators,
            "eval_occurrences": int(eval_occurrences),
        },
        "tracking_features": {
            "tracking_scripts": bool(tracking_scripts),
            "tracking_resource_examples": tracking_resource_examples,
            "tracking_inline_indicators": tracking_inline_indicators,
            "fingerprinting": bool(fingerprinting),
            "fingerprinting_indicators": fingerprinting_indicators,
        },
    }

    network = {
        "dns_addresses": resolve_dns_addresses(page_host),
        "whois": None,
    }
    whois_domain = registrable_domain(page_host)
    if whois_domain:
        network["whois"] = rdap_whois(
            whois_domain, timeout_seconds=WEB_WHOIS_TIMEOUT_SECONDS
        )

    page = {
        "title": parsed.title if parsed else "",
        "description": parsed.description if parsed else "",
        "screenshot_url": None,
    }

    web = {
        "security_analysis": analysis,
        "page_information": page,
        "network_information": network,
    }

    return {"web": web}


def _scan_bytes(
    content: bytes,
    url: str,
    *,
    download: Optional[dict] = None,
) -> dict:
    """Analyze content and return security analysis details."""
    digest = hashlib.sha256(content).hexdigest()
    engines = ["web"]
    results: dict[str, dict] = {}

    web_results = _web_scan(content, url=url, download=download)
    results.update(web_results)

    canonical_url = None
    try:
        canonical_url = canonicalize_url(url).canonical
    except Exception:
        canonical_url = None

    details = {
        "url": url,
        "sha256": digest,
        "length": len(content),
        "engine": "web",
        "engines": engines,
        "results": results,
    }
    if isinstance(download, dict) and download:
        download_out = dict(download)
        download_out.pop("cookies", None)
        details["download"] = download_out
    if canonical_url:
        details["canonical_url"] = canonical_url
    return details


def main():
    _CFG.validate()

    global table_client, redis_client, result_persister
    setup_telemetry(service_name="worker", logger_obj=logger)

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        if not REDIS_URL:
            raise RuntimeError(
                "REDIS_URL env var is required when using Redis backends"
            )
        redis_client = init_redis_client(redis_url=REDIS_URL)

    if RESULT_BACKEND == "table":
        if not RESULT_STORE_CONN:
            raise RuntimeError(
                "RESULT_STORE_CONN env var is required when RESULT_BACKEND=table"
            )
        table_client = init_table_client(
            conn_str=RESULT_STORE_CONN, table_name=RESULT_TABLE
        )

    pubsub_cfg = WebPubSubConfig.from_env()
    publisher = WebPubSubPublisher(pubsub_cfg, logger_obj=logger) if pubsub_cfg else None

    result_persister = ResultPersister(
        backend=str(RESULT_BACKEND),
        partition_key=RESULT_PARTITION,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=REDIS_RESULT_PREFIX,
        redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        component="worker",
        publisher=publisher,
    )

    log_with_context(logger, logging.INFO, "Worker scan engines configured", engines=["web"])
    log_with_context(logger, logging.INFO, "Worker started; waiting for messages")

    def _on_exception(
        task: Optional[dict], exc: Exception, delivery_count: int, duration_ms: int
    ) -> None:
        info = classify_exception(exc)
        job_id = task.get("job_id") if isinstance(task, dict) else None
        if not job_id:
            return
        correlation_id = task.get("correlation_id") if isinstance(task, dict) else None
        api_key_hash = task.get("api_key_hash") if isinstance(task, dict) else None
        submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

        def _is_http_4xx(code: str) -> bool:
            if not isinstance(code, str):
                return False
            if not code.startswith("http_"):
                return False
            try:
                status = int(code.split("_", 1)[1])
            except Exception:
                return False
            return 400 <= status < 500

        retrying = info.retryable and delivery_count < MAX_RETRIES
        blocked = _is_http_4xx(info.code) and not info.retryable
        status = "blocked" if blocked else ("retrying" if retrying else "error")

        if not result_persister:
            return
        result_persister.save_result(
            job_id=job_id,
            status=status,
            error=info.message,
            details={
                "reason": info.message,
                "error_code": info.code,
                "retryable": bool(info.retryable),
                "delivery_count": delivery_count,
                "max_retries": MAX_RETRIES,
            },
            correlation_id=correlation_id,
            api_key_hash=api_key_hash,
            visibility=(task.get("visibility") if isinstance(task, dict) else None),
            duration_ms=duration_ms,
            submitted_at=submitted_at,
            url=task.get("url") if isinstance(task, dict) else None,
            index_job=False,
        )

    if QUEUE_BACKEND == "redis":
        log_with_context(
            logger,
            logging.INFO,
            "Worker redis queues configured",
            queue_name=REDIS_QUEUE_KEY,
            dlq_name=REDIS_DLQ_KEY,
        )

    run_consumer(
        component="worker",
        shutdown_flag=shutdown_flag,
        queue_backend=QUEUE_BACKEND,
        servicebus_conn=SERVICEBUS_CONN,
        queue_name=QUEUE_NAME,
        batch_size=BATCH_SIZE,
        max_wait=MAX_WAIT,
        prefetch=PREFETCH,
        max_retries=MAX_RETRIES,
        redis_client=redis_client,
        redis_queue_key=REDIS_QUEUE_KEY,
        redis_dlq_key=REDIS_DLQ_KEY,
        process=process,
        on_exception=_on_exception,
    )

    log_with_context(logger, logging.INFO, "Worker shutdown complete")


if __name__ == "__main__":
    main()
