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
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_WAIT = int(os.getenv("MAX_WAIT", "5"))  # seconds
PREFETCH = int(os.getenv("PREFETCH", "20"))
MAX_RETRIES = int(
    os.getenv("MAX_RETRIES", "5")
)  # move to DLQ after this many deliveries
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional (opencensus)
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

# ---- Scan engine (ClamAV) ----
CLAMAV_HOST = os.getenv("CLAMAV_HOST")  # e.g. "<prefix>-clamav.<env>.internal... "
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT = float(os.getenv("CLAMAV_TIMEOUT", "10"))
CLAMAV_MAX_RETRIES = int(os.getenv("CLAMAV_MAX_RETRIES", "2"))
CLAMAV_RETRY_DEADLINE_SECONDS = float(os.getenv("CLAMAV_RETRY_DEADLINE_SECONDS", "30"))
CLAMAV_CHUNK_SIZE = int(os.getenv("CLAMAV_CHUNK_SIZE", "16384"))
CLAMAV_READY_TIMEOUT_SECONDS = float(os.getenv("CLAMAV_READY_TIMEOUT_SECONDS", "300"))
CLAMAV_READY_INTERVAL_SECONDS = float(os.getenv("CLAMAV_READY_INTERVAL_SECONDS", "5"))
SCAN_ENGINE = os.getenv(
    "SCAN_ENGINE", "clamav" if CLAMAV_HOST else "heuristic"
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
        if not CLAMAV_HOST:
            raise ValueError("CLAMAV_HOST is required when SCAN_ENGINE=clamav")
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
    last_err: Optional[Exception] = None

    deadline = time.monotonic() + CLAMAV_RETRY_DEADLINE_SECONDS
    for attempt in range(CLAMAV_MAX_RETRIES + 1):
        try:
            with socket.create_connection(
                (CLAMAV_HOST, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT
            ) as sock:
                sock.settimeout(CLAMAV_TIMEOUT)

                # INSTREAM expects: "zINSTREAM\\0" then repeated [len][chunk] and final 0-length.
                sock.sendall(b"zINSTREAM\0")
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
            last_err = e
            if attempt >= CLAMAV_MAX_RETRIES or time.monotonic() >= deadline:
                break
            time.sleep(min(0.5 * (2**attempt), 10.0))

    raise ValueError(f"clamav scan failed: {last_err}")


def _clamav_ping() -> bool:
    if not CLAMAV_HOST:
        return False
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT) as sock:
            sock.settimeout(CLAMAV_TIMEOUT)
            sock.sendall(b"zPING\0")
            data = sock.recv(64)
            return b"PONG" in data
    except OSError:
        return False


def _wait_for_clamav_ready():
    if SCAN_ENGINE != "clamav":
        return
    if not CLAMAV_HOST:
        raise RuntimeError("CLAMAV_HOST is required when SCAN_ENGINE=clamav")

    deadline = time.monotonic() + CLAMAV_READY_TIMEOUT_SECONDS
    while not shutdown and time.monotonic() < deadline:
        if _clamav_ping():
            logging.info("[worker] ClamAV is ready at %s:%s", CLAMAV_HOST, CLAMAV_PORT)
            return
        logging.warning(
            "[worker] Waiting for ClamAV at %s:%s ...", CLAMAV_HOST, CLAMAV_PORT
        )
        time.sleep(max(0.5, CLAMAV_READY_INTERVAL_SECONDS))

    raise RuntimeError(
        f"ClamAV not ready after {CLAMAV_READY_TIMEOUT_SECONDS:.0f}s at {CLAMAV_HOST}:{CLAMAV_PORT}"
    )


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
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "submitted_at": submitted_at or "",
    }
    try:
        table_client.upsert_entity(entity=entity)
    except HttpResponseError as e:
        logging.error("[worker] Failed to persist result: %s", e)


def main():
    if not SERVICEBUS_CONN:
        raise RuntimeError("SERVICEBUS_CONN env var is required")
    if not RESULT_STORE_CONN:
        raise RuntimeError("RESULT_STORE_CONN env var is required")

    client = ServiceBusClient.from_connection_string(
        SERVICEBUS_CONN, logging_enable=True
    )
    global table_client
    table_service = TableServiceClient.from_connection_string(conn_str=RESULT_STORE_CONN)
    table_service.create_table_if_not_exists(table_name=RESULT_TABLE)
    table_client = table_service.get_table_client(table_name=RESULT_TABLE)

    _wait_for_clamav_ready()
    logging.info("[worker] started; waiting for messages...")

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
                        task: Optional[dict] = None
                        started_at = time.time()
                        try:
                            task = _decode_body(msg)
                            process(task)
                            receiver.complete_message(msg)
                        except Exception as e:
                            duration_ms = int((time.time() - started_at) * 1000)
                            job_id = task.get("job_id") if isinstance(task, dict) else None
                            correlation_id = (
                                task.get("correlation_id") if isinstance(task, dict) else None
                            )
                            submitted_at = (
                                task.get("submitted_at") if isinstance(task, dict) else None
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
