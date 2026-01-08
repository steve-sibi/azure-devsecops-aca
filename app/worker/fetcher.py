import hashlib
import json
import logging
import os
import signal as os_signal
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from azure.data.tables import TableClient, TableServiceClient
from azure.core.exceptions import HttpResponseError
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError

from common.result_store import upsert_result_sync

import worker as scan_worker


# ---- Config via env ----
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")
SERVICEBUS_SCAN_CONN = os.getenv("SERVICEBUS_SCAN_CONN")  # send to SCAN_QUEUE_NAME
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
SCAN_QUEUE_NAME = os.getenv("SCAN_QUEUE_NAME", f"{QUEUE_NAME}-scan")

BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_WAIT = int(os.getenv("MAX_WAIT", "5"))  # seconds
PREFETCH = int(os.getenv("PREFETCH", "20"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))

RESULT_BACKEND = os.getenv("RESULT_BACKEND", "table").strip().lower()
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")

ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "/artifacts").strip() or "/artifacts"

# Local dev backends (Redis)
REDIS_URL = os.getenv("REDIS_URL")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", f"queue:{QUEUE_NAME}")
REDIS_DLQ_KEY = os.getenv("REDIS_DLQ_KEY", f"dlq:{QUEUE_NAME}")
REDIS_SCAN_QUEUE_KEY = os.getenv("REDIS_SCAN_QUEUE_KEY", f"queue:{SCAN_QUEUE_NAME}")


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

shutdown = False
table_client: Optional[TableClient] = None
redis_client = None


def _signal_handler(*_):
    global shutdown
    shutdown = True


os_signal.signal(os_signal.SIGTERM, _signal_handler)
os_signal.signal(os_signal.SIGINT, _signal_handler)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decode_body(msg) -> dict:
    body_bytes = b"".join(
        bytes(b) if isinstance(b, memoryview) else b for b in msg.body
    )
    return json.loads(body_bytes.decode("utf-8"))


def _ensure_artifact_dir() -> Path:
    p = Path(ARTIFACT_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


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
):
    scanned_at = _utc_now_iso()

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
            redis_prefix=os.getenv("REDIS_RESULT_PREFIX", "scan:"),
            redis_ttl_seconds=int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0")),
        )
    except HttpResponseError as e:
        logging.error("[fetcher] Failed to persist result: %s", e)


def _enqueue_scan(payload: dict, *, message_id: str):
    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        envelope = {
            "schema": "scan-artifact-v1",
            "message_id": message_id,
            "delivery_count": 1,
            "payload": payload,
            "application_properties": {
                "schema": "scan-artifact-v1",
                "correlation_id": payload.get("correlation_id"),
            },
        }
        redis_client.rpush(REDIS_SCAN_QUEUE_KEY, json.dumps(envelope))
        return

    if QUEUE_BACKEND == "servicebus":
        if not SERVICEBUS_SCAN_CONN:
            raise RuntimeError("SERVICEBUS_SCAN_CONN is required for fetcher forwarding")
        with ServiceBusClient.from_connection_string(SERVICEBUS_SCAN_CONN) as client:
            with client.get_queue_sender(queue_name=SCAN_QUEUE_NAME) as sender:
                msg = ServiceBusMessage(
                    json.dumps(payload),
                    content_type="application/json",
                    message_id=message_id,
                    application_properties={
                        "schema": "scan-artifact-v1",
                        "correlation_id": payload.get("correlation_id"),
                    },
                )
                sender.send_messages(msg)
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {QUEUE_BACKEND}")


def process(task: dict):
    job_id = task.get("job_id")
    url = task.get("url")
    correlation_id = task.get("correlation_id")
    submitted_at = task.get("submitted_at")

    if not url or not job_id:
        raise ValueError("missing url/job_id in task")

    engines = scan_worker._get_scan_engines()
    start = time.time()
    _save_result(
        job_id=job_id,
        status="fetching",
        verdict="",
        details={"url": url, "stage": "fetching", "engines": engines},
        correlation_id=correlation_id,
        submitted_at=submitted_at,
        url=url,
    )

    try:
        (
            content,
            size_bytes,
            download,
            url_evaluations,
            url_signals,
            reputation_summary,
        ) = scan_worker._download(url, engines=engines)
    except scan_worker.DownloadBlockedError as e:
        duration_ms = int((time.time() - start) * 1000)
        verdict = str(e.decision.get("final_verdict") or "malicious").lower()
        details = dict(e.details or {})
        details.setdefault("engine", engines[0] if len(engines) == 1 else "multi")
        details.setdefault("engines", engines)
        details.setdefault("download_blocked", True)
        details.setdefault("url", url)
        _save_result(
            job_id=job_id,
            status="completed",
            verdict=verdict,
            details=details,
            size_bytes=0,
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            submitted_at=submitted_at,
            error=None,
            url=url,
        )
        logging.info(
            "[fetcher] job_id=%s verdict=%s size=0B duration_ms=%s (blocked)",
            job_id,
            verdict,
            duration_ms,
        )
        return

    artifact_dir = _ensure_artifact_dir()
    artifact_name = f"{job_id}.bin"
    artifact_path = artifact_dir / artifact_name
    _atomic_write(artifact_path, content)

    sha256 = hashlib.sha256(content).hexdigest()
    duration_ms = int((time.time() - start) * 1000)

    forward_payload = {
        "job_id": job_id,
        "correlation_id": correlation_id,
        "url": url,
        "type": task.get("type"),
        "source": task.get("source"),
        "metadata": task.get("metadata") if isinstance(task.get("metadata"), dict) else {},
        "submitted_at": submitted_at,
        "artifact_path": artifact_name,
        "artifact_sha256": sha256,
        "artifact_size_bytes": size_bytes,
        "download": download,
        "url_evaluations": url_evaluations,
        "url_signals": [s.as_dict() for s in url_signals],
        "reputation_summary": reputation_summary,
    }

    _enqueue_scan(forward_payload, message_id=str(job_id))

    _save_result(
        job_id=job_id,
        status="queued_scan",
        verdict="",
        details={
            "url": url,
            "stage": "queued_scan",
            "artifact_path": artifact_name,
            "artifact_sha256": sha256,
            "artifact_size_bytes": size_bytes,
            "download": download,
        },
        size_bytes=size_bytes,
        correlation_id=correlation_id,
        duration_ms=duration_ms,
        submitted_at=submitted_at,
        error=None,
        url=url,
    )

    logging.info(
        "[fetcher] job_id=%s queued scan size=%sB duration_ms=%s",
        job_id,
        size_bytes,
        duration_ms,
    )


def main() -> None:
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
        table_service = TableServiceClient.from_connection_string(conn_str=RESULT_STORE_CONN)
        table_service.create_table_if_not_exists(table_name=RESULT_TABLE)
        table_client = table_service.get_table_client(table_name=RESULT_TABLE)

    logging.info("[fetcher] started; queue=%s scan_queue=%s backend=%s", QUEUE_NAME, SCAN_QUEUE_NAME, QUEUE_BACKEND)

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        logging.info("[fetcher] redis queue=%s dlq=%s", REDIS_QUEUE_KEY, REDIS_DLQ_KEY)
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
                correlation_id = task.get("correlation_id") if isinstance(task, dict) else None
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
                            "stage": "fetcher",
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
                        "[fetcher] Requeued message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )
                else:
                    dlq_envelope = envelope or {"delivery_count": delivery_count, "payload": task or {}}
                    dlq_envelope["last_error"] = str(e)
                    redis_client.rpush(REDIS_DLQ_KEY, json.dumps(dlq_envelope))
                    logging.error(
                        "[fetcher] DLQ'd message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )
    else:
        client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN, logging_enable=True)
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
                                job_id = task.get("job_id") if isinstance(task, dict) else None
                                correlation_id = task.get("correlation_id") if isinstance(task, dict) else None
                                submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

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
                                            "stage": "fetcher",
                                        },
                                        correlation_id=correlation_id,
                                        duration_ms=duration_ms,
                                        submitted_at=submitted_at,
                                        url=task.get("url") if isinstance(task, dict) else None,
                                    )

                                if msg.delivery_count >= MAX_RETRIES:
                                    receiver.dead_letter_message(
                                        msg,
                                        reason="max-retries-exceeded",
                                        error_description=str(e),
                                    )
                                    logging.error(
                                        "[fetcher] DLQ'd message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                                else:
                                    receiver.abandon_message(msg)
                                    logging.warning(
                                        "[fetcher] Abandoned message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                    except OperationTimeoutError:
                        continue
                    except ServiceBusError as e:
                        logging.error("[fetcher] ServiceBusError: %s", e)
                        time.sleep(2)

    logging.info("[fetcher] shutdown complete.")


if __name__ == "__main__":
    main()
