import json
import logging
import os
import signal
import time
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableServiceClient
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
table_client: Optional[TableServiceClient] = None


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
        logging.error("[worker] Missing url/job_id in task")
        return "error", {"reason": "invalid-payload"}

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return "error", {"reason": "invalid-scheme"}

    start = time.time()
    try:
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
        )
        logging.info(
            "[worker] job_id=%s verdict=%s size=%sB duration_ms=%s",
            job_id,
            verdict,
            size_bytes,
            duration_ms,
        )
        return verdict, details
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        logging.error("[worker] job_id=%s error=%s", job_id, e)
        _save_result(
            job_id=job_id,
            status="error",
            verdict="error",
            details={"reason": str(e)},
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            submitted_at=task.get("submitted_at"),
        )
        raise


def _download(url: str) -> tuple[bytes, int]:
    with requests.get(
        url, timeout=REQUEST_TIMEOUT, stream=True, allow_redirects=True
    ) as resp:
        resp.raise_for_status()
        final_scheme = urlparse(resp.url).scheme.lower()
        if final_scheme != "https":
            raise ValueError("redirected to non-https")
        data = b""
        for chunk in resp.iter_content(chunk_size=8192):
            if not chunk:
                continue
            data += chunk
            if len(data) > MAX_DOWNLOAD_BYTES:
                raise ValueError("content too large")
        return data, len(data)


def _scan_bytes(content: bytes, url: str) -> tuple[str, dict]:
    """Lightweight placeholder scan; replace with AV engine."""
    digest = hashlib.sha256(content).hexdigest()
    lowered = content.lower()
    # naive heuristics for demo purposes
    suspicious = any(
        marker in lowered for marker in [b"<script", b"onerror", b"alert(", b"eval("]
    )
    if "test-malicious" in url.lower() or suspicious:
        verdict = "malicious"
    else:
        verdict = "clean"
    details = {"sha256": digest, "length": len(content)}
    if suspicious:
        details["reason"] = "suspicious-content"
    return verdict, details


def _save_result(
    job_id: str,
    status: str,
    verdict: str,
    details: Optional[dict] = None,
    size_bytes: Optional[int] = None,
    correlation_id: Optional[str] = None,
    duration_ms: Optional[int] = None,
    submitted_at: Optional[str] = None,
):
    if not table_client:
        return
    entity = {
        "PartitionKey": RESULT_PARTITION,
        "RowKey": job_id,
        "status": status,
        "verdict": verdict,
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
    table_service = TableServiceClient.from_connection_string(
        conn_str=RESULT_STORE_CONN
    )
    table_client = table_service.get_table_client(table_name=RESULT_TABLE)
    table_client.create_table_if_not_exists()

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
                        try:
                            task = _decode_body(msg)
                            process(task)
                            receiver.complete_message(msg)
                        except Exception as e:
                            # DLQ if too many deliveries, else make it available again
                            if msg.delivery_count >= MAX_RETRIES:
                                receiver.dead_letter_message(
                                    msg,
                                    reason="max-retries-exceeded",
                                    error_description=str(e),
                                )
                                logging.error(f"[worker] DLQ'd message: {e}")
                            else:
                                receiver.abandon_message(msg)
                                logging.warning(
                                    f"[worker] Abandoned message (retry {msg.delivery_count}): {e}"
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
