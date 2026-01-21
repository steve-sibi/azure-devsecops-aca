import logging
import os
import time
import hashlib
import secrets
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from azure.data.tables import TableClient

from common.config import ConsumerConfig, ResultPersister, init_redis_client, init_table_client
from common.errors import classify_exception
from common.screenshot_store import (
    redis_screenshot_key,
    store_screenshot_blob_sync,
    store_screenshot_redis_sync,
)
from common.message_consumer import ShutdownFlag, install_signal_handlers, run_consumer
from common.scan_messages import validate_scan_artifact_v1
from common.signals import Signal, aggregate_signals, signal
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
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN") or os.getenv(
    "APPLICATIONINSIGHTS_CONNECTION_STRING"
)  # optional (opencensus)
RESULT_BACKEND = _CFG.result_backend
RESULT_STORE_CONN = _CFG.result_store_conn
RESULT_TABLE = _CFG.result_table
RESULT_PARTITION = _CFG.result_partition
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)

# Local dev backends (Redis)
REDIS_URL = _CFG.redis_url
REDIS_QUEUE_KEY = _CFG.redis_queue_key
REDIS_DLQ_KEY = _CFG.redis_dlq_key
REDIS_RESULT_PREFIX = _CFG.redis_result_prefix
REDIS_RESULT_TTL_SECONDS = _CFG.redis_result_ttl_seconds

# ---- Artifact handoff (fetcher -> analyzer) ----
ARTIFACT_DIR = _CFG.artifact_dir
ARTIFACT_DELETE_ON_SUCCESS = os.getenv("ARTIFACT_DELETE_ON_SUCCESS", "false").lower() in (
    "1",
    "true",
    "yes",
)

# Web analysis tuning (UI-focused)
WEB_MAX_RESOURCES = int(os.getenv("WEB_MAX_RESOURCES", "25"))
WEB_MAX_INLINE_SCRIPT_CHARS = int(os.getenv("WEB_MAX_INLINE_SCRIPT_CHARS", "80000"))
WEB_MAX_HTML_BYTES = int(os.getenv("WEB_MAX_HTML_BYTES", str(300_000)))
WEB_WHOIS_TIMEOUT_SECONDS = float(os.getenv("WEB_WHOIS_TIMEOUT_SECONDS", "3.0"))

# Screenshot capture (optional)
SCREENSHOT_REDIS_PREFIX = os.getenv("SCREENSHOT_REDIS_PREFIX", "screenshot:")
SCREENSHOT_CONTAINER = os.getenv("SCREENSHOT_CONTAINER", "screenshots")
SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "jpeg")
SCREENSHOT_TIMEOUT_SECONDS = float(os.getenv("SCREENSHOT_TIMEOUT_SECONDS", "12"))
SCREENSHOT_VIEWPORT_WIDTH = int(os.getenv("SCREENSHOT_VIEWPORT_WIDTH", "1280"))
SCREENSHOT_VIEWPORT_HEIGHT = int(os.getenv("SCREENSHOT_VIEWPORT_HEIGHT", "720"))
SCREENSHOT_FULL_PAGE = os.getenv("SCREENSHOT_FULL_PAGE", "false").lower() in (
    "1",
    "true",
    "yes",
)
SCREENSHOT_JPEG_QUALITY = int(os.getenv("SCREENSHOT_JPEG_QUALITY", "60"))
SCREENSHOT_TTL_SECONDS = int(
    os.getenv("SCREENSHOT_TTL_SECONDS", str(REDIS_RESULT_TTL_SECONDS))
)

# ---- Logging (console + optional App Insights) ----
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
if APPINSIGHTS_CONN:
    try:
        from opencensus.ext.azure.log_exporter import AzureLogHandler

        logging.getLogger().addHandler(
            AzureLogHandler(connection_string=APPINSIGHTS_CONN)
        )
    except Exception as e:
        logging.warning(f"App Insights logging not enabled: {e}")

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

    if not url or not job_id:
        raise ValueError("missing url/job_id in task")

    start = time.time()

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

        download = task.get("download") if isinstance(task.get("download"), dict) else {}
    else:
        content, size_bytes, download = download_url(url)

    verdict, details = _scan_bytes(content, url, download=download)

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
    if not result_persister or not result_persister.save_result(
        job_id=job_id,
        status="completed",
        verdict=verdict,
        details=details,
        size_bytes=size_bytes,
        correlation_id=correlation_id,
        duration_ms=duration_ms,
        submitted_at=task.get("submitted_at"),
        error=None,
        url=url,
    ):
        raise RuntimeError("failed to persist scan result")
    if ARTIFACT_DELETE_ON_SUCCESS:
        artifact_path = task.get("artifact_path")
        if isinstance(artifact_path, str) and artifact_path.strip():
            try:
                (Path(ARTIFACT_DIR) / Path(artifact_path).name).unlink(missing_ok=True)
            except Exception:
                pass
    logging.info(
        "[worker] job_id=%s verdict=%s size=%sB duration_ms=%s",
        job_id,
        verdict,
        size_bytes,
        duration_ms,
    )
    return verdict, details


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
        if isinstance(capture_error, str) and capture_error and capture_error != "disabled":
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
        logging.info("[worker] screenshot store failed (job_id=%s)", job_id)
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


def _web_scan(
    content: bytes, *, url: str, download: Optional[dict] = None
) -> tuple[dict, list[Signal]]:
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
        if sniff.startswith(b"<!doctype html") or sniff.startswith(b"<html") or b"<head" in sniff:
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
        },
        "cookies": {
            "insecure_cookies": int(len(insecure_cookies)),
            "details": insecure_cookies[:20],
        },
        "detectable_vulnerabilities": {
            "open_redirects": bool(open_redirects.get("detected")),
            "open_redirect_examples": open_redirects.get("examples") or [],
            "inner_html_usage": bool(inner_html_usage),
            "eval_usage": bool(eval_usage),
        },
        "tracking_features": {
            "tracking_scripts": bool(tracking_scripts),
            "fingerprinting": bool(fingerprinting),
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

    signals: list[Signal] = []
    if not csp_enforced:
        signals.append(
            signal(
                source="web.headers.csp_missing",
                verdict="benign",
                severity="low",
                weight=15,
                evidence={
                    "reason": (
                        "Content-Security-Policy header is missing"
                        if not csp_report_only
                        else "Content-Security-Policy is report-only (not enforced)"
                    ),
                    "url": final_url,
                },
            )
        )
    if mixed_content:
        signals.append(
            signal(
                source="web.mixed_content",
                verdict="suspicious",
                severity="high",
                weight=70,
                evidence={
                    "reason": "Mixed content detected (HTTP resources on an HTTPS page)",
                    "count": int(len(mixed_content)),
                    "url": final_url,
                },
            )
        )
    if insecure_cookies:
        likely_sensitive = []
        samesite_none_without_secure = []
        for c in insecure_cookies:
            name = str(c.get("name") or "").strip().lower()
            issues = c.get("issues") if isinstance(c.get("issues"), list) else []
            issues_l = [str(i).lower() for i in issues if i]
            if any("samesite=none without secure" in i for i in issues_l):
                samesite_none_without_secure.append(c)
            if any(
                hint in name
                for hint in (
                    "session",
                    "sess",
                    "sid",
                    "auth",
                    "token",
                    "jwt",
                    "bearer",
                    "access",
                    "refresh",
                    "login",
                    "csrftoken",
                    "xsrf",
                    "csrf",
                )
            ):
                likely_sensitive.append(c)
            elif c.get("httponly") is True and not c.get("expires") and not c.get("max_age"):
                likely_sensitive.append(c)

        if samesite_none_without_secure:
            signals.append(
                signal(
                    source="web.cookies.samesite_none_without_secure",
                    verdict="suspicious",
                    severity="medium",
                    weight=55,
                    evidence={
                        "reason": "Cookies set SameSite=None without Secure",
                        "count": int(len(samesite_none_without_secure)),
                        "url": final_url,
                    },
                )
            )
        elif likely_sensitive or not hsts_present:
            signals.append(
                signal(
                    source="web.cookies.insecure",
                    verdict="suspicious",
                    severity="low",
                    weight=30,
                    evidence={
                        "reason": (
                            "Insecure cookies detected (missing Secure attribute)"
                            if not likely_sensitive
                            else "Insecure cookies detected (missing Secure on likely session/auth cookies)"
                        ),
                        "count": int(len(insecure_cookies)),
                        "url": final_url,
                    },
                )
            )
        else:
            signals.append(
                signal(
                    source="web.cookies.insecure",
                    verdict="benign",
                    severity="low",
                    weight=10,
                    evidence={
                        "reason": "Cookies missing Secure attribute (HSTS present)",
                        "count": int(len(insecure_cookies)),
                        "url": final_url,
                    },
                )
            )
    if login_forms > 0 and not csrf_protection:
        signals.append(
            signal(
                source="web.forms.csrf_missing",
                verdict="suspicious",
                severity="medium",
                weight=55,
                evidence={
                    "reason": "Login form detected without obvious CSRF protection",
                    "url": final_url,
                },
            )
        )
    if eval_usage:
        signals.append(
            signal(
                source="web.vuln.eval_usage",
                verdict="suspicious",
                severity="high",
                weight=70,
                evidence={"reason": "JavaScript eval usage detected", "url": final_url},
            )
        )
    if open_redirects.get("detected"):
        signals.append(
            signal(
                source="web.vuln.open_redirect_patterns",
                verdict="suspicious",
                severity="medium",
                weight=60,
                evidence={
                    "reason": "Open redirect patterns detected in links/forms",
                    "url": final_url,
                },
            )
        )
    if not signals:
        signals.append(
            signal(
                source="web.ok",
                verdict="benign",
                severity="info",
                weight=10,
                evidence={"reason": "No notable web security indicators found", "url": final_url},
            )
        )

    return {"web": web}, signals


def _scan_bytes(
    content: bytes,
    url: str,
    *,
    download: Optional[dict] = None,
) -> tuple[str, dict]:
    digest = hashlib.sha256(content).hexdigest()
    engines = ["web"]
    results: dict[str, dict] = {}
    signals: list[Signal] = []

    web_results, web_signals = _web_scan(content, url=url, download=download)
    results.update(web_results)
    signals.extend(web_signals)

    decision = aggregate_signals(signals)

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
        "decision": decision.as_dict(),
        "signals": [s.as_dict() for s in signals],
    }
    if isinstance(download, dict) and download:
        download_out = dict(download)
        download_out.pop("cookies", None)
        details["download"] = download_out
    if canonical_url:
        details["canonical_url"] = canonical_url
    return decision.final_verdict, details


def main():
    _CFG.validate()

    global table_client, redis_client, result_persister

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        if not REDIS_URL:
            raise RuntimeError("REDIS_URL env var is required when using Redis backends")
        redis_client = init_redis_client(redis_url=REDIS_URL)

    if RESULT_BACKEND == "table":
        if not RESULT_STORE_CONN:
            raise RuntimeError(
                "RESULT_STORE_CONN env var is required when RESULT_BACKEND=table"
            )
        table_client = init_table_client(
            conn_str=RESULT_STORE_CONN, table_name=RESULT_TABLE
        )

    result_persister = ResultPersister(
        backend=RESULT_BACKEND,
        partition_key=RESULT_PARTITION,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=REDIS_RESULT_PREFIX,
        redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        component="worker",
    )

    logging.info("[worker] Scan engines: %s", ["web"])
    logging.info("[worker] started; waiting for messages...")

    def _on_exception(
        task: Optional[dict], exc: Exception, delivery_count: int, duration_ms: int
    ) -> None:
        info = classify_exception(exc)
        job_id = task.get("job_id") if isinstance(task, dict) else None
        if not job_id:
            return
        correlation_id = task.get("correlation_id") if isinstance(task, dict) else None
        submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

        retrying = info.retryable and delivery_count < MAX_RETRIES
        status = "retrying" if retrying else "error"

        if not result_persister:
            return
        result_persister.save_result(
            job_id=job_id,
            status=status,
            verdict="" if retrying else "error",
            error=info.message,
            details={
                "reason": info.message,
                "error_code": info.code,
                "retryable": bool(info.retryable),
                "delivery_count": delivery_count,
                "max_retries": MAX_RETRIES,
            },
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            submitted_at=submitted_at,
            url=task.get("url") if isinstance(task, dict) else None,
        )

    if QUEUE_BACKEND == "redis":
        logging.info("[worker] redis queue=%s dlq=%s", REDIS_QUEUE_KEY, REDIS_DLQ_KEY)

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

    logging.info("[worker] shutdown complete.")


if __name__ == "__main__":
    main()
