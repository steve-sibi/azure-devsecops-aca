import json
import logging
import os
import signal as os_signal
import time
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableClient, TableServiceClient

from common.result_store import upsert_result_sync
from common.signals import Signal, aggregate_signals, signal
from common.url_canonicalization import canonicalize_url
from common.url_validation import UrlValidationError, validate_public_https_url
from common.web_analysis import (
    analyze_html,
    find_open_redirects,
    parse_set_cookie_headers,
    rdap_whois,
    registrable_domain,
    resolve_dns_addresses,
)

# ---- Config via env ----
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_WAIT = int(os.getenv("MAX_WAIT", "5"))  # seconds
PREFETCH = int(os.getenv("PREFETCH", "20"))
MAX_RETRIES = int(
    os.getenv("MAX_RETRIES", "5")
)  # move to DLQ after this many deliveries
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN") or os.getenv(
    "APPLICATIONINSIGHTS_CONNECTION_STRING"
)  # optional (opencensus)
RESULT_BACKEND = os.getenv("RESULT_BACKEND", "table").strip().lower()
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")
MAX_DOWNLOAD_BYTES = int(os.getenv("MAX_DOWNLOAD_BYTES", str(1024 * 1024)))  # 1MB
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))  # seconds
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)

# Local dev backends (Redis)
REDIS_URL = os.getenv("REDIS_URL")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", f"queue:{QUEUE_NAME}")
REDIS_DLQ_KEY = os.getenv("REDIS_DLQ_KEY", f"dlq:{QUEUE_NAME}")
REDIS_RESULT_PREFIX = os.getenv("REDIS_RESULT_PREFIX", "scan:")
REDIS_RESULT_TTL_SECONDS = int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0"))

# ---- Artifact handoff (fetcher -> analyzer) ----
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "/artifacts").strip() or "/artifacts"
ARTIFACT_DELETE_ON_SUCCESS = os.getenv("ARTIFACT_DELETE_ON_SUCCESS", "false").lower() in (
    "1",
    "true",
    "yes",
)

# Web analysis tuning (UI-focused)
WEB_MAX_HEADER_VALUE_LEN = int(os.getenv("WEB_MAX_HEADER_VALUE_LEN", "600"))
WEB_MAX_HEADERS = int(os.getenv("WEB_MAX_HEADERS", "40"))
WEB_MAX_RESOURCES = int(os.getenv("WEB_MAX_RESOURCES", "25"))
WEB_MAX_INLINE_SCRIPT_CHARS = int(os.getenv("WEB_MAX_INLINE_SCRIPT_CHARS", "80000"))
WEB_MAX_HTML_BYTES = int(os.getenv("WEB_MAX_HTML_BYTES", str(300_000)))
WEB_WHOIS_TIMEOUT_SECONDS = float(os.getenv("WEB_WHOIS_TIMEOUT_SECONDS", "3.0"))

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

shutdown = False
table_client: Optional[TableClient] = None
redis_client = None


def _signal_handler(*_):
    global shutdown
    shutdown = True


os_signal.signal(os_signal.SIGTERM, _signal_handler)
os_signal.signal(os_signal.SIGINT, _signal_handler)


def _decode_body(msg) -> dict:
    # msg.body is an iterable of bytes/memoryview sections; join & decode
    body_bytes = b"".join(
        bytes(b) if isinstance(b, memoryview) else b for b in msg.body
    )
    return json.loads(body_bytes.decode("utf-8"))


def process(task: dict):
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
        content, size_bytes, download = _download(url)

    verdict, details = _scan_bytes(content, url, download=download)
    duration_ms = int((time.time() - start) * 1000)
    if not _save_result(
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


def _download(url: str) -> tuple[bytes, int, dict]:
    session = requests.Session()
    current = url
    redirects: list[dict] = []

    try:
        for _hop in range(MAX_REDIRECTS + 1):
            canonical = _validate_url_for_download(current)
            request_url = canonical.canonical

            with session.get(
                request_url,
                timeout=REQUEST_TIMEOUT,
                stream=True,
                allow_redirects=False,
            ) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise ValueError("redirect without Location header")
                    next_url = urljoin(request_url, location)
                    redirects.append(
                        {
                            "from": request_url,
                            "to": next_url,
                            "status_code": resp.status_code,
                        }
                    )
                    current = next_url
                    continue

                resp.raise_for_status()
                buf = bytearray()
                content_type = (resp.headers.get("Content-Type") or "").strip()
                content_length = (resp.headers.get("Content-Length") or "").strip()
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    buf.extend(chunk)
                    if len(buf) > MAX_DOWNLOAD_BYTES:
                        raise ValueError("content too large")

                # Response headers/cookies (sanitized) for UI analysis.
                response_headers: list[dict] = []
                try:
                    for k, v in resp.headers.items():
                        name = str(k or "").strip().lower()
                        if not name or name == "set-cookie":
                            continue
                        val = str(v or "").strip()
                        if val and len(val) > max(0, int(WEB_MAX_HEADER_VALUE_LEN)):
                            val = val[: max(0, int(WEB_MAX_HEADER_VALUE_LEN) - 3)] + "..."
                        response_headers.append({"name": name, "value": val})
                        if len(response_headers) >= max(1, int(WEB_MAX_HEADERS)):
                            break
                except Exception:
                    response_headers = []

                set_cookie_raw: list[str] = []
                try:
                    raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
                    if raw_headers is not None and hasattr(raw_headers, "getlist"):
                        set_cookie_raw = [
                            str(x) for x in raw_headers.getlist("Set-Cookie") if x
                        ]
                    elif raw_headers is not None and hasattr(raw_headers, "get_all"):
                        set_cookie_raw = [
                            str(x) for x in raw_headers.get_all("Set-Cookie") if x
                        ]
                except Exception:
                    set_cookie_raw = []
                if not set_cookie_raw:
                    sc = resp.headers.get("Set-Cookie")
                    if isinstance(sc, str) and sc.strip():
                        set_cookie_raw = [sc.strip()]

                cookies = parse_set_cookie_headers(set_cookie_raw)
                download_info = {
                    "requested_url": url,
                    "final_url": request_url,
                    "redirects": redirects,
                    "status_code": int(resp.status_code),
                }
                if content_type:
                    download_info["content_type"] = content_type
                if content_length:
                    download_info["content_length"] = content_length
                if response_headers:
                    download_info["response_headers"] = response_headers
                if cookies:
                    download_info["cookies"] = cookies
                return bytes(buf), len(buf), download_info

        raise ValueError("too many redirects")
    finally:
        try:
            session.close()
        except Exception:
            pass


def _validate_url_for_download(url: str):
    # Canonicalize first to prevent representation bypasses, then validate.
    canonical = canonicalize_url(url)
    if canonical.has_userinfo:
        raise UrlValidationError(
            code="userinfo_not_allowed", message="userinfo in url is not allowed"
        )
    validate_public_https_url(
        canonical.canonical, block_private_networks=BLOCK_PRIVATE_NETWORKS
    )
    return canonical

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

    headers = _headers_map_from_download(download)
    page_host = (urlparse(final_url).hostname or "").strip().lower().rstrip(".")

    csp_present = "content-security-policy" in headers
    xfo_present = "x-frame-options" in headers
    x_xss_present = "x-xss-protection" in headers

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
            "content_security_policy": {"present": bool(csp_present)},
            "x_frame_options": {"present": bool(xfo_present)},
            "x_xss_protection": {"present": bool(x_xss_present)},
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

    resources = {
        "links": parsed.links[:WEB_MAX_RESOURCES] if parsed else [],
        "images": parsed.images[:WEB_MAX_RESOURCES] if parsed else [],
        "scripts": parsed.scripts[:WEB_MAX_RESOURCES] if parsed else [],
        "styles": parsed.styles[:WEB_MAX_RESOURCES] if parsed else [],
    }

    page = {
        "title": parsed.title if parsed else "",
        "screenshot_url": None,
    }

    web = {
        "security_analysis": analysis,
        "page_information": page,
        "network_information": network,
        "resources": resources,
    }

    signals: list[Signal] = []
    if not csp_present:
        signals.append(
            signal(
                source="web.headers.csp_missing",
                verdict="suspicious",
                severity="medium",
                weight=45,
                evidence={"reason": "Missing Content-Security-Policy header", "url": final_url},
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
        signals.append(
            signal(
                source="web.cookies.insecure",
                verdict="suspicious",
                severity="low",
                weight=30,
                evidence={
                    "reason": "Insecure cookies detected (missing Secure attribute)",
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


def _save_result(
    job_id: str,
    status: str,
    verdict: str,
    details: Optional[dict] = None,
    size_bytes: Optional[int] = None,
    correlation_id: Optional[str] = None,
    duration_ms: Optional[int] = None,
    submitted_at: Optional[str] = None,
    error: Optional[str] = None,
    url: Optional[str] = None,
) -> bool:
    scanned_at = datetime.now(timezone.utc).isoformat()

    extra = {
        "size_bytes": size_bytes or 0,
        "correlation_id": correlation_id or "",
        "duration_ms": duration_ms or 0,
        "scanned_at": scanned_at,
        "submitted_at": submitted_at or "",
    }
    if url:
        extra["url"] = url

    details_out: dict = dict(details or {})
    if url and "url" not in details_out:
        details_out["url"] = url
    try:
        if RESULT_BACKEND == "table" and not table_client:
            raise RuntimeError("Result store not initialized (table_client)")
        if RESULT_BACKEND == "redis" and not redis_client:
            raise RuntimeError("Result store not initialized (redis_client)")
        upsert_result_sync(
            backend=RESULT_BACKEND,
            partition_key=RESULT_PARTITION,
            job_id=job_id,
            status=status,
            verdict=verdict,
            error=error,
            details=details_out,
            extra=extra,
            table_client=table_client,
            redis_client=redis_client,
            redis_prefix=REDIS_RESULT_PREFIX,
            redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        )
        return True
    except Exception:
        logging.exception(
            "[worker] Failed to persist result (job_id=%s status=%s)", job_id, status
        )
        return False


def main():
    if QUEUE_BACKEND not in ("servicebus", "redis"):
        raise RuntimeError("QUEUE_BACKEND must be 'servicebus' or 'redis'")
    if RESULT_BACKEND not in ("table", "redis"):
        raise RuntimeError("RESULT_BACKEND must be 'table' or 'redis'")

    global table_client, redis_client

    if QUEUE_BACKEND == "servicebus" and not SERVICEBUS_CONN:
        raise RuntimeError("SERVICEBUS_CONN env var is required when QUEUE_BACKEND=servicebus")
    if RESULT_BACKEND == "table" and not RESULT_STORE_CONN:
        raise RuntimeError("RESULT_STORE_CONN env var is required when RESULT_BACKEND=table")
    if (QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis") and not REDIS_URL:
        raise RuntimeError("REDIS_URL env var is required when using Redis backends")

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        try:
            import redis
        except Exception as e:
            raise RuntimeError(
                "Redis backends require the 'redis' package (pip install redis)"
            ) from e
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()

    if RESULT_BACKEND == "table":
        table_service = TableServiceClient.from_connection_string(
            conn_str=RESULT_STORE_CONN
        )
        table_service.create_table_if_not_exists(table_name=RESULT_TABLE)
        table_client = table_service.get_table_client(table_name=RESULT_TABLE)

    logging.info("[worker] Scan engines: %s", ["web"])

    logging.info("[worker] started; waiting for messages...")

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        logging.info("[worker] redis queue=%s dlq=%s", REDIS_QUEUE_KEY, REDIS_DLQ_KEY)
        while not shutdown:
            item = redis_client.blpop(REDIS_QUEUE_KEY, timeout=MAX_WAIT)
            if not item:
                continue

            _queue, raw = item
            started_at = time.time()
            task: Optional[dict] = None
            envelope: Optional[dict] = None
            delivery_count = 1
            try:
                decoded = json.loads(raw)
                if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
                    envelope = decoded
                    task = decoded["payload"]
                    delivery_count = int(decoded.get("delivery_count") or 1)
                elif isinstance(decoded, dict):
                    task = decoded
                    envelope = {"schema": "unknown", "delivery_count": 1, "payload": decoded}
                    delivery_count = 1
                else:
                    raise ValueError("invalid message payload (expected JSON object)")

                process(task)
            except Exception as e:
                duration_ms = int((time.time() - started_at) * 1000)
                job_id = task.get("job_id") if isinstance(task, dict) else None
                correlation_id = (
                    task.get("correlation_id") if isinstance(task, dict) else None
                )
                submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

                retrying = delivery_count < MAX_RETRIES
                status = "retrying" if retrying else "error"

                if job_id:
                    _save_result(
                        job_id=job_id,
                        status=status,
                        verdict="" if retrying else "error",
                        error=str(e),
                        details={
                            "reason": str(e),
                            "delivery_count": delivery_count,
                            "max_retries": MAX_RETRIES,
                        },
                        correlation_id=correlation_id,
                        duration_ms=duration_ms,
                        submitted_at=submitted_at,
                        url=task.get("url") if isinstance(task, dict) else None,
                    )

                if retrying:
                    next_envelope = envelope or {"delivery_count": delivery_count, "payload": task or {}}
                    next_envelope["delivery_count"] = delivery_count + 1
                    redis_client.rpush(REDIS_QUEUE_KEY, json.dumps(next_envelope))
                    logging.warning(
                        "[worker] Requeued message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )
                else:
                    dlq_envelope = envelope or {"delivery_count": delivery_count, "payload": task or {}}
                    dlq_envelope["last_error"] = str(e)
                    redis_client.rpush(REDIS_DLQ_KEY, json.dumps(dlq_envelope))
                    logging.error(
                        "[worker] DLQ'd message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )

    else:
        client = ServiceBusClient.from_connection_string(
            SERVICEBUS_CONN, logging_enable=True
        )
        with client:
            receiver = client.get_queue_receiver(
                queue_name=QUEUE_NAME,
                max_wait_time=MAX_WAIT,
                prefetch_count=PREFETCH,
            )
            with receiver:
                while not shutdown:
                    try:
                        messages = receiver.receive_messages(
                            max_message_count=BATCH_SIZE,
                            max_wait_time=MAX_WAIT,
                        )
                        if not messages:
                            continue

                        for msg in messages:
                            task = None
                            started_at = time.time()
                            try:
                                task = _decode_body(msg)
                                process(task)
                                receiver.complete_message(msg)
                            except Exception as e:
                                duration_ms = int((time.time() - started_at) * 1000)
                                job_id = (
                                    task.get("job_id") if isinstance(task, dict) else None
                                )
                                correlation_id = (
                                    task.get("correlation_id")
                                    if isinstance(task, dict)
                                    else None
                                )
                                submitted_at = (
                                    task.get("submitted_at")
                                    if isinstance(task, dict)
                                    else None
                                )

                                if job_id:
                                    retrying = msg.delivery_count < MAX_RETRIES
                                    status = "retrying" if retrying else "error"
                                    _save_result(
                                        job_id=job_id,
                                        status=status,
                                        verdict="" if retrying else "error",
                                        error=str(e),
                                        details={
                                            "reason": str(e),
                                            "delivery_count": msg.delivery_count,
                                            "max_retries": MAX_RETRIES,
                                        },
                                        correlation_id=correlation_id,
                                        duration_ms=duration_ms,
                                        submitted_at=submitted_at,
                                        url=task.get("url") if isinstance(task, dict) else None,
                                    )

                                # DLQ if too many deliveries, else make it available again
                                if msg.delivery_count >= MAX_RETRIES:
                                    receiver.dead_letter_message(
                                        msg,
                                        reason="max-retries-exceeded",
                                        error_description=str(e),
                                    )
                                    logging.error(
                                        "[worker] DLQ'd message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                                else:
                                    receiver.abandon_message(msg)
                                    logging.warning(
                                        "[worker] Abandoned message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                    except OperationTimeoutError:
                        # no messages within wait window
                        continue
                    except ServiceBusError as e:
                        logging.error(f"[worker] ServiceBusError: {e}")
                        time.sleep(2)  # brief backoff

    logging.info("[worker] shutdown complete.")


if __name__ == "__main__":
    main()
