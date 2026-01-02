import json
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
import hashlib
import struct
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urljoin

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableClient, TableServiceClient
from azure.core.exceptions import HttpResponseError

from common.result_store import upsert_result_sync
from common.url_validation import validate_public_https_url

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
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional (opencensus)
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

# ---- Scan engine (ClamAV) ----
CLAMAV_HOST = os.getenv("CLAMAV_HOST")  # e.g. "127.0.0.1" (local clamd sidecar)
CLAMAV_HOSTS = os.getenv(
    "CLAMAV_HOSTS"
)  # optional CSV of fallbacks, tried in order
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT = float(os.getenv("CLAMAV_TIMEOUT", "10"))
CLAMAV_MAX_RETRIES = int(os.getenv("CLAMAV_MAX_RETRIES", "2"))
CLAMAV_RETRY_DEADLINE_SECONDS = float(os.getenv("CLAMAV_RETRY_DEADLINE_SECONDS", "30"))
CLAMAV_CHUNK_SIZE = int(os.getenv("CLAMAV_CHUNK_SIZE", "16384"))
SCAN_ENGINE = os.getenv(
    "SCAN_ENGINE", "clamav" if (CLAMAV_HOSTS or CLAMAV_HOST) else "heuristic"
).strip().lower()

# ---- Scan engine (YARA, bundled in the worker container) ----
YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "yara-rules/default.yar")
YARA_TIMEOUT = float(os.getenv("YARA_TIMEOUT", "5"))
YARA_MAX_MATCHES = int(os.getenv("YARA_MAX_MATCHES", "50"))
YARA_BINARY = os.getenv("YARA_BINARY", "yara")

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


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT, _signal_handler)


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
    content, size_bytes = _download(url)
    verdict, details = _scan_bytes(content, url)
    duration_ms = int((time.time() - start) * 1000)
    _save_result(
        job_id=job_id,
        status="completed",
        verdict=verdict,
        details=details,
        size_bytes=size_bytes,
        correlation_id=correlation_id,
        duration_ms=duration_ms,
        submitted_at=task.get("submitted_at"),
        error=None,
    )
    logging.info(
        "[worker] job_id=%s verdict=%s size=%sB duration_ms=%s",
        job_id,
        verdict,
        size_bytes,
        duration_ms,
    )
    return verdict, details


def _download(url: str) -> tuple[bytes, int]:
    session = requests.Session()
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        _validate_url_for_download(current)
        with session.get(
            current,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            allow_redirects=False,
        ) as resp:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    raise ValueError("redirect without Location header")
                current = urljoin(current, location)
                continue

            resp.raise_for_status()
            buf = bytearray()
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                buf.extend(chunk)
                if len(buf) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("content too large")
            return bytes(buf), len(buf)

    raise ValueError("too many redirects")


def _validate_url_for_download(url: str):
    validate_public_https_url(url, block_private_networks=BLOCK_PRIVATE_NETWORKS)


_SUPPORTED_SCAN_ENGINES = {"clamav", "yara", "heuristic"}


def _parse_scan_engines(spec: str) -> List[str]:
    raw = (spec or "").strip().lower()
    if not raw:
        return []

    parts = [p.strip() for p in re.split(r"[,+]", raw) if p.strip()]
    engines: List[str] = []
    seen: set[str] = set()
    for part in parts:
        if part not in _SUPPORTED_SCAN_ENGINES:
            raise ValueError(
                f"unsupported scan engine '{part}' (supported: {sorted(_SUPPORTED_SCAN_ENGINES)})"
            )
        if part in seen:
            continue
        seen.add(part)
        engines.append(part)
    return engines


def _get_scan_engines() -> List[str]:
    engines = _parse_scan_engines(SCAN_ENGINE)
    return engines if engines else ["heuristic"]


def _heuristic_scan(content: bytes, url: str) -> tuple[str, dict]:
    lowered = content.lower()
    suspicious = any(
        marker in lowered for marker in [b"<script", b"onerror", b"alert(", b"eval("]
    )

    url_marker = "test-malicious" in url.lower()
    verdict = "malicious" if (url_marker or suspicious) else "clean"
    detail: dict = {"suspicious": bool(suspicious or url_marker)}
    if url_marker:
        detail["reason"] = "test-malicious-url"
    elif suspicious:
        detail["reason"] = "suspicious-content"
    return verdict, {"heuristic": detail}


def _yara_scan(content: bytes) -> tuple[str, dict]:
    rules_path = (YARA_RULES_PATH or "").strip()
    if not rules_path:
        raise ValueError("YARA_RULES_PATH is required when SCAN_ENGINE includes 'yara'")
    if not os.path.exists(rules_path):
        raise ValueError(f"YARA_RULES_PATH not found: {rules_path}")

    yara_bin = (YARA_BINARY or "yara").strip()
    if not shutil.which(yara_bin):
        raise ValueError(f"YARA binary not found on PATH: {yara_bin}")

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="scan-", suffix=".bin", delete=False
        ) as f:
            tmp_path = f.name
            f.write(content)

        proc = subprocess.run(
            [yara_bin, rules_path, tmp_path],
            capture_output=True,
            text=True,
            timeout=YARA_TIMEOUT,
        )
        if proc.returncode not in (0, 1):
            stderr = (proc.stderr or proc.stdout or "").strip()
            raise ValueError(
                f"yara scan failed (exit={proc.returncode}): {stderr or 'unknown error'}"
            )

        matches: List[str] = []
        if proc.returncode == 0:
            for line in (proc.stdout or "").splitlines():
                rule = line.strip().split(maxsplit=1)[0]
                if not rule:
                    continue
                matches.append(rule)
                if len(matches) >= max(1, YARA_MAX_MATCHES):
                    break

        verdict = "malicious" if matches else "clean"
        return verdict, {"yara": {"matches": matches, "rules_path": rules_path}}
    except subprocess.TimeoutExpired as e:
        raise ValueError(f"yara scan timed out after {YARA_TIMEOUT}s") from e
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _scan_bytes(content: bytes, url: str) -> tuple[str, dict]:
    digest = hashlib.sha256(content).hexdigest()
    engines = _get_scan_engines()
    results: dict[str, dict] = {}

    final_verdict = "clean"
    for engine in engines:
        if engine == "clamav":
            if not _get_clamav_hosts():
                raise ValueError(
                    "CLAMAV_HOST or CLAMAV_HOSTS is required when SCAN_ENGINE includes 'clamav'"
                )
            verdict, clamav_details = _clamav_instream_scan(content)
            results["clamav"] = clamav_details.get("clamav", clamav_details)
        elif engine == "yara":
            verdict, yara_details = _yara_scan(content)
            results["yara"] = yara_details.get("yara", yara_details)
        elif engine == "heuristic":
            verdict, heuristic_details = _heuristic_scan(content, url)
            results["heuristic"] = heuristic_details.get("heuristic", heuristic_details)
        else:
            raise ValueError(f"unsupported scan engine: {engine}")

        if verdict == "malicious":
            final_verdict = "malicious"

    details = {
        "sha256": digest,
        "length": len(content),
        "engine": engines[0] if len(engines) == 1 else "multi",
        "engines": engines,
        "results": results,
    }
    return final_verdict, details


def _clamav_instream_scan(content: bytes) -> tuple[str, dict]:
    """Scan bytes via clamd INSTREAM protocol."""
    hosts = _get_clamav_hosts()
    if not hosts:
        raise ValueError("clamav scan failed: no CLAMAV_HOST(S) configured")

    last_err: Optional[Exception] = None

    deadline = time.monotonic() + CLAMAV_RETRY_DEADLINE_SECONDS
    for attempt in range(CLAMAV_MAX_RETRIES + 1):
        for host in hosts:
            # clamd can accept INSTREAM as either newline-delimited or null-terminated.
            for cmd in (b"zINSTREAM\0", b"INSTREAM\n"):
                try:
                    with socket.create_connection(
                        (host, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT
                    ) as sock:
                        sock.settimeout(CLAMAV_TIMEOUT)

                        sock.sendall(cmd)
                        view = memoryview(content)
                        for i in range(0, len(content), CLAMAV_CHUNK_SIZE):
                            chunk = view[i : i + CLAMAV_CHUNK_SIZE]
                            sock.sendall(struct.pack("!I", len(chunk)))
                            sock.sendall(chunk)
                        sock.sendall(struct.pack("!I", 0))

                        buf = b""
                        while True:
                            part = sock.recv(4096)
                            if not part:
                                break
                            buf += part
                            if b"\0" in buf or b"\n" in buf:
                                break

                        line = (
                            buf.split(b"\0", 1)[0]
                            .split(b"\n", 1)[0]
                            .decode("utf-8", "replace")
                            .strip()
                        )
                        if not line:
                            raise ValueError("empty clamd response")

                        # Typical responses:
                        #   "stream: OK"
                        #   "stream: Eicar-Test-Signature FOUND"
                        #   "stream: <reason> ERROR"
                        if line.endswith(" OK"):
                            return "clean", {"clamav": {"result": "OK"}}
                        if line.endswith(" FOUND"):
                            signature = line.split(": ", 1)[1].rsplit(" FOUND", 1)[0]
                            return "malicious", {
                                "clamav": {"result": "FOUND", "signature": signature}
                            }
                        if line.endswith(" ERROR") or " ERROR" in line:
                            raise ValueError(f"clamd error: {line}")

                        # Unexpected response; fail closed.
                        raise ValueError(f"unexpected clamd response: {line}")
                except (OSError, ValueError) as e:
                    last_err = RuntimeError(f"{host}:{CLAMAV_PORT}: {e}")

        if attempt >= CLAMAV_MAX_RETRIES or time.monotonic() >= deadline:
            break
        time.sleep(min(0.5 * (2**attempt), 10.0))

    raise ValueError(f"clamav scan failed: {last_err}")


def _get_clamav_hosts() -> List[str]:
    hosts: List[str] = []
    if CLAMAV_HOSTS:
        hosts.extend([h.strip() for h in CLAMAV_HOSTS.split(",") if h.strip()])
    if CLAMAV_HOST:
        hosts.append(CLAMAV_HOST.strip())

    unique_hosts: List[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        unique_hosts.append(host)
    return unique_hosts


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
):
    scanned_at = datetime.now(timezone.utc).isoformat()

    extra = {
        "size_bytes": size_bytes or 0,
        "correlation_id": correlation_id or "",
        "duration_ms": duration_ms or 0,
        "scanned_at": scanned_at,
        "submitted_at": submitted_at or "",
    }
    try:
        upsert_result_sync(
            backend=RESULT_BACKEND,
            partition_key=RESULT_PARTITION,
            job_id=job_id,
            status=status,
            verdict=verdict,
            error=error,
            details=details or {},
            extra=extra,
            table_client=table_client,
            redis_client=redis_client,
            redis_prefix=REDIS_RESULT_PREFIX,
            redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        )
    except HttpResponseError as e:
        logging.error("[worker] Failed to persist result: %s", e)


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

    engines = _get_scan_engines()
    logging.info("[worker] Scan engines: %s", engines)

    if "clamav" in engines:
        hosts = _get_clamav_hosts()
        if not hosts:
            raise RuntimeError(
                "SCAN_ENGINE includes 'clamav' but CLAMAV_HOST/CLAMAV_HOSTS is not set"
            )
        logging.info("[worker] ClamAV configured: hosts=%s port=%s", hosts, CLAMAV_PORT)

    if "yara" in engines:
        rules_path = (YARA_RULES_PATH or "").strip()
        if not rules_path:
            raise RuntimeError(
                "SCAN_ENGINE includes 'yara' but YARA_RULES_PATH is not set"
            )
        if not os.path.exists(rules_path):
            raise RuntimeError(f"YARA_RULES_PATH not found: {rules_path}")
        yara_bin = (YARA_BINARY or "yara").strip()
        if not shutil.which(yara_bin):
            raise RuntimeError(f"YARA binary not found on PATH: {yara_bin}")
        logging.info("[worker] YARA configured: rules=%s", rules_path)

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
