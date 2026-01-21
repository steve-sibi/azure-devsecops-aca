import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from azure.data.tables import TableClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage

from common.config import ConsumerConfig, ResultPersister, init_redis_client, init_table_client
from common.message_consumer import ShutdownFlag, install_signal_handlers, run_consumer
from common.scan_messages import validate_scan_artifact_v1, validate_scan_task_v1

from web_fetch import download_url


# ---- Config via env ----
_CFG = ConsumerConfig.from_env()

QUEUE_BACKEND = _CFG.queue_backend
SERVICEBUS_CONN = _CFG.servicebus_conn
QUEUE_NAME = _CFG.queue_name
BATCH_SIZE = _CFG.batch_size
MAX_WAIT = _CFG.max_wait  # seconds
PREFETCH = _CFG.prefetch
MAX_RETRIES = _CFG.max_retries

RESULT_BACKEND = _CFG.result_backend
RESULT_STORE_CONN = _CFG.result_store_conn
RESULT_TABLE = _CFG.result_table
RESULT_PARTITION = _CFG.result_partition

ARTIFACT_DIR = _CFG.artifact_dir

# Local dev backends (Redis)
REDIS_URL = _CFG.redis_url
REDIS_QUEUE_KEY = _CFG.redis_queue_key
REDIS_DLQ_KEY = _CFG.redis_dlq_key
REDIS_RESULT_PREFIX = _CFG.redis_result_prefix
REDIS_RESULT_TTL_SECONDS = _CFG.redis_result_ttl_seconds

SERVICEBUS_SCAN_CONN = os.getenv("SERVICEBUS_SCAN_CONN")  # send to SCAN_QUEUE_NAME
SCAN_QUEUE_NAME = os.getenv("SCAN_QUEUE_NAME", f"{QUEUE_NAME}-scan")
REDIS_SCAN_QUEUE_KEY = os.getenv("REDIS_SCAN_QUEUE_KEY", f"queue:{SCAN_QUEUE_NAME}")


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

shutdown_flag = ShutdownFlag()
install_signal_handlers(shutdown_flag)

table_client: Optional[TableClient] = None
redis_client = None
result_persister: Optional[ResultPersister] = None


def _ensure_artifact_dir() -> Path:
    p = Path(ARTIFACT_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


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
    task = validate_scan_task_v1(task)
    job_id = task.get("job_id")
    url = task.get("url")
    correlation_id = task.get("correlation_id")
    submitted_at = task.get("submitted_at")

    if not url or not job_id:
        raise ValueError("missing url/job_id in task")

    engines = ["web"]
    start = time.time()
    if not result_persister or not result_persister.save_result(
        job_id=job_id,
        status="fetching",
        verdict="",
        details={"url": url, "stage": "fetching", "engines": engines},
        correlation_id=correlation_id,
        submitted_at=submitted_at,
        url=url,
    ):
        raise RuntimeError("failed to persist fetcher status")

    content, size_bytes, download = download_url(url)

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
    }
    forward_payload = validate_scan_artifact_v1(forward_payload)

    if not result_persister or not result_persister.save_result(
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
    ):
        raise RuntimeError("failed to persist queued_scan status")

    _enqueue_scan(forward_payload, message_id=str(job_id))

    logging.info(
        "[fetcher] job_id=%s queued scan size=%sB duration_ms=%s",
        job_id,
        size_bytes,
        duration_ms,
    )


def main() -> None:
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
        component="fetcher",
    )

    logging.info("[fetcher] started; queue=%s scan_queue=%s backend=%s", QUEUE_NAME, SCAN_QUEUE_NAME, QUEUE_BACKEND)
    def _on_exception(
        task: Optional[dict], exc: Exception, delivery_count: int, duration_ms: int
    ) -> None:
        job_id = task.get("job_id") if isinstance(task, dict) else None
        if not job_id:
            return
        correlation_id = task.get("correlation_id") if isinstance(task, dict) else None
        submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

        retrying = delivery_count < MAX_RETRIES
        status = "retrying" if retrying else "error"

        if not result_persister:
            return
        result_persister.save_result(
            job_id=job_id,
            status=status,
            verdict="" if retrying else "error",
            error=str(exc),
            details={
                "reason": str(exc),
                "delivery_count": delivery_count,
                "max_retries": MAX_RETRIES,
                "stage": "fetcher",
            },
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            submitted_at=submitted_at,
            url=task.get("url") if isinstance(task, dict) else None,
        )

    if QUEUE_BACKEND == "redis":
        logging.info("[fetcher] redis queue=%s dlq=%s", REDIS_QUEUE_KEY, REDIS_DLQ_KEY)

    run_consumer(
        component="fetcher",
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

    logging.info("[fetcher] shutdown complete.")


if __name__ == "__main__":
    main()
