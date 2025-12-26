import json
import logging
import os
import signal
import time
import hashlib
import ipaddress
import struct
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableClient, TableServiceClient
from azure.core.exceptions import HttpResponseError

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
CLAMAV_HOST = os.getenv("CLAMAV_HOST")  # e.g. "<prefix>-clamav.<env>.internal... "
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

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("invalid scheme (https required)")

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
            data = b""
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                data += chunk
                if len(data) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("content too large")
            return data, len(data)

    raise ValueError("too many redirects")


def _validate_url_for_download(url: str):
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("only https is allowed")
    if not parsed.netloc:
        raise ValueError("url host is required")
    if parsed.username or parsed.password:
        raise ValueError("userinfo in url is not allowed")
    if parsed.port and parsed.port != 443:
        raise ValueError("only default https port 443 is allowed")

    host = parsed.hostname
    if not host:
        raise ValueError("url host is required")
    if host.lower() == "localhost":
        raise ValueError("localhost is not allowed")
    if not BLOCK_PRIVATE_NETWORKS:
        return

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ValueError(f"dns resolution failed: {e}") from e
        ips = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not ips:
            raise ValueError("no a/aaaa records found")
        if any(not ip.is_global for ip in ips):
            raise ValueError("destination resolves to a non-public ip address (blocked)")
    else:
        if not ip_literal.is_global:
            raise ValueError("direct ip destinations must be publicly routable")


def _scan_bytes(content: bytes, url: str) -> tuple[str, dict]:
    digest = hashlib.sha256(content).hexdigest()
    details = {"sha256": digest, "length": len(content)}

    if SCAN_ENGINE == "clamav":
        if not _get_clamav_hosts():
            raise ValueError(
                "CLAMAV_HOST or CLAMAV_HOSTS is required when SCAN_ENGINE=clamav"
            )
        verdict, clamav_details = _clamav_instream_scan(content)
        details.update(
            {
                "engine": "clamav",
                **clamav_details,
            }
        )
        return verdict, details

    # Fallback demo-only heuristics (kept for local development).
    lowered = content.lower()
    suspicious = any(
        marker in lowered for marker in [b"<script", b"onerror", b"alert(", b"eval("]
    )
    verdict = "malicious" if ("test-malicious" in url.lower() or suspicious) else "clean"
    details["engine"] = "heuristic"
    if suspicious:
        details["reason"] = "suspicious-content"
    return verdict, details


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

    if RESULT_BACKEND == "table":
        if not table_client:
            return
        entity = {
            "PartitionKey": RESULT_PARTITION,
            "RowKey": job_id,
            "status": status,
            "verdict": verdict or "",
            "error": error or "",
            "details": json.dumps(details or {}),
            "size_bytes": size_bytes or 0,
            "correlation_id": correlation_id or "",
            "duration_ms": duration_ms or 0,
            "scanned_at": scanned_at,
            "submitted_at": submitted_at or "",
        }
        try:
            table_client.upsert_entity(entity=entity)
        except HttpResponseError as e:
            logging.error("[worker] Failed to persist result: %s", e)
        return

    if RESULT_BACKEND == "redis":
        if not redis_client:
            return
        key = f"{REDIS_RESULT_PREFIX}{job_id}"
        entity = {
            "status": status,
            "verdict": verdict or "",
            "error": error or "",
            "details": json.dumps(details or {}),
            "size_bytes": size_bytes or 0,
            "correlation_id": correlation_id or "",
            "duration_ms": duration_ms or 0,
            "scanned_at": scanned_at,
            "submitted_at": submitted_at or "",
        }
        redis_client.hset(key, mapping=entity)
        if REDIS_RESULT_TTL_SECONDS > 0:
            redis_client.expire(key, REDIS_RESULT_TTL_SECONDS)
        return

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}")


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

    if SCAN_ENGINE == "clamav":
        hosts = _get_clamav_hosts()
        if not hosts:
            raise RuntimeError(
                "SCAN_ENGINE=clamav but CLAMAV_HOST/CLAMAV_HOSTS is not set"
            )
        logging.info("[worker] ClamAV configured: hosts=%s port=%s", hosts, CLAMAV_PORT)

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
