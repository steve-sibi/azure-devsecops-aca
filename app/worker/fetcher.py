"""
Fetcher stage (URL scan pipeline).

Consumes `scan-v1` messages from the "fetch" queue, downloads the URL (with the
same SSRF protections as the rest of the pipeline), writes the bytes to the shared
artifact directory, and forwards a `scan-artifact-v1` message to the "scan" queue.

This stage is intentionally I/O focused: it avoids doing heavy analysis and exists
to demonstrate an async, two-stage pipeline that can scale independently via KEDA.
"""

import hashlib
import json
import logging
import os
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Optional

from azure.data.tables import TableClient
from azure.servicebus import ServiceBusClient, ServiceBusMessage, ServiceBusSender
from azure.servicebus._common.message import PrimitiveTypes
from common.config import (
    ConsumerConfig,
    ResultPersister,
    init_redis_client,
    init_table_client,
)
from common.errors import classify_exception
from common.live_updates import (
    RedisStreamsConfig,
    create_live_updates_publisher,
    resolve_live_updates_backend,
)
from common.logging_config import (
    clear_correlation_id,
    get_logger,
    log_with_context,
    set_correlation_id,
    setup_logging,
)
from common.message_consumer import ShutdownFlag, install_signal_handlers, run_consumer
from common.scan_messages import validate_scan_artifact_v1, validate_scan_task_v1
from common.telemetry import (
    extract_trace_context,
    get_tracer,
    inject_trace_context,
    setup_telemetry,
)
from common.webpubsub import WebPubSubConfig
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

# ---- Logging ----
setup_logging(service_name="fetcher", level=logging.INFO)
logger = get_logger(__name__)

shutdown_flag = ShutdownFlag()
install_signal_handlers(shutdown_flag)

table_client: Optional[TableClient] = None
redis_client = None
result_persister: Optional[ResultPersister] = None
scan_sb_client: Optional[ServiceBusClient] = None
scan_sb_sender: Optional[ServiceBusSender] = None


def _ensure_artifact_dir() -> Path:
    p = Path(ARTIFACT_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


def _ensure_scan_sender() -> ServiceBusSender:
    global scan_sb_client, scan_sb_sender
    if scan_sb_sender is not None:
        return scan_sb_sender
    if not SERVICEBUS_SCAN_CONN:
        raise RuntimeError("SERVICEBUS_SCAN_CONN is required for fetcher forwarding")

    scan_sb_client = ServiceBusClient.from_connection_string(SERVICEBUS_SCAN_CONN)
    scan_sb_client.__enter__()
    scan_sb_sender = scan_sb_client.get_queue_sender(queue_name=SCAN_QUEUE_NAME)
    scan_sb_sender.__enter__()
    return scan_sb_sender


def _close_scan_sender() -> None:
    global scan_sb_client, scan_sb_sender
    if scan_sb_sender is not None:
        try:
            scan_sb_sender.__exit__(None, None, None)
        except Exception:
            pass
        finally:
            scan_sb_sender = None
    if scan_sb_client is not None:
        try:
            scan_sb_client.__exit__(None, None, None)
        except Exception:
            pass
        finally:
            scan_sb_client = None


def _enqueue_scan(payload: dict, *, message_id: str):
    app_props: dict[str | bytes, PrimitiveTypes] = {"schema": "scan-artifact-v1"}
    correlation_id = payload.get("correlation_id")
    if correlation_id is not None:
        app_props["correlation_id"] = str(correlation_id)
    request_id = payload.get("request_id")
    if request_id is not None:
        app_props["request_id"] = str(request_id)
    run_id = payload.get("run_id")
    if run_id is not None:
        app_props["run_id"] = str(run_id)
    traceparent = payload.get("traceparent")
    if traceparent is not None:
        app_props["traceparent"] = str(traceparent)
    tracestate = payload.get("tracestate")
    if tracestate is not None:
        app_props["tracestate"] = str(tracestate)

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        envelope = {
            "schema": "scan-artifact-v1",
            "message_id": message_id,
            "delivery_count": 1,
            "payload": payload,
            "application_properties": app_props,
        }
        redis_client.rpush(REDIS_SCAN_QUEUE_KEY, json.dumps(envelope))
        return

    if QUEUE_BACKEND == "servicebus":
        sender = _ensure_scan_sender()
        msg = ServiceBusMessage(
            json.dumps(payload),
            content_type="application/json",
            message_id=message_id,
            application_properties=app_props,
        )
        sender.send_messages(msg)
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {QUEUE_BACKEND}")


def process(task: dict):
    task = validate_scan_task_v1(task)
    job_id = task.get("job_id")
    request_id = task.get("request_id")
    run_id = task.get("run_id") or job_id
    url = task.get("url")
    correlation_id = task.get("correlation_id")
    api_key_hash = task.get("api_key_hash")
    visibility = task.get("visibility")
    submitted_at = task.get("submitted_at")
    traceparent = task.get("traceparent")
    tracestate = task.get("tracestate")

    if not url or not job_id:
        raise ValueError("missing url/job_id in task")

    if correlation_id:
        set_correlation_id(str(correlation_id))

    parent_ctx = extract_trace_context(
        traceparent=str(traceparent) if isinstance(traceparent, str) else None,
        tracestate=str(tracestate) if isinstance(tracestate, str) else None,
    )

    tracer = get_tracer("aca-fetcher")
    span_cm = (
        tracer.start_as_current_span("fetcher.process", context=parent_ctx)
        if tracer
        else nullcontext()
    )

    try:
        with span_cm as span:
            if span:
                span.set_attribute("app.component", "fetcher")
                span.set_attribute("app.job_id", str(job_id))
                span.set_attribute("app.run_id", str(run_id))
                if request_id:
                    span.set_attribute("app.request_id", str(request_id))
                span.set_attribute("app.queue_name", str(QUEUE_NAME))
                span.set_attribute("app.scan_queue_name", str(SCAN_QUEUE_NAME))
                span.set_attribute("url.full", str(url))

            engines = ["web"]
            start = time.time()
            log_with_context(
                logger,
                logging.INFO,
                "Fetcher processing scan task",
                job_id=job_id,
                url=url,
            )
            if not result_persister or not result_persister.save_result(
                job_id=job_id,
                status="fetching",
                details={"url": url, "stage": "fetching", "engines": engines},
                correlation_id=correlation_id,
                api_key_hash=api_key_hash,
                visibility=visibility,
                submitted_at=submitted_at,
                url=url,
                index_job=False,
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
                "request_id": request_id,
                "run_id": run_id,
                "correlation_id": correlation_id,
                "api_key_hash": api_key_hash,
                "url": url,
                "type": task.get("type"),
                "source": task.get("source"),
                "visibility": task.get("visibility"),
                "metadata": (
                    task.get("metadata")
                    if isinstance(task.get("metadata"), dict)
                    else {}
                ),
                "submitted_at": submitted_at,
                "traceparent": task.get("traceparent"),
                "tracestate": task.get("tracestate"),
                "artifact_path": artifact_name,
                "artifact_sha256": sha256,
                "artifact_size_bytes": size_bytes,
                "download": download,
            }
            trace_carrier: dict[str, str] = {}
            inject_trace_context(trace_carrier)
            if trace_carrier.get("traceparent"):
                forward_payload["traceparent"] = trace_carrier["traceparent"]
            if trace_carrier.get("tracestate"):
                forward_payload["tracestate"] = trace_carrier["tracestate"]

            forward_payload = validate_scan_artifact_v1(forward_payload)

            if not result_persister or not result_persister.save_result(
                job_id=job_id,
                status="queued_scan",
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
                api_key_hash=api_key_hash,
                visibility=visibility,
                duration_ms=duration_ms,
                submitted_at=submitted_at,
                error=None,
                url=url,
                index_job=False,
            ):
                raise RuntimeError("failed to persist queued_scan status")

            _enqueue_scan(forward_payload, message_id=str(job_id))
            log_with_context(
                logger,
                logging.INFO,
                "Fetcher queued scan artifact",
                job_id=job_id,
                size_bytes=size_bytes,
                duration_ms=duration_ms,
            )
    finally:
        clear_correlation_id()


def main() -> None:
    _CFG.validate()

    global table_client, redis_client, result_persister
    setup_telemetry(service_name="fetcher", logger_obj=logger)

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
    live_backend = resolve_live_updates_backend(
        webpubsub_cfg=pubsub_cfg,
        redis_available=redis_client is not None,
    )
    publisher = create_live_updates_publisher(
        backend=live_backend,
        redis_client=redis_client,
        webpubsub_cfg=pubsub_cfg,
        redis_cfg=RedisStreamsConfig.from_env(),
        logger_obj=logger,
    )

    result_persister = ResultPersister(
        backend=RESULT_BACKEND,
        partition_key=RESULT_PARTITION,
        table_client=table_client,
        redis_client=redis_client,
        redis_prefix=REDIS_RESULT_PREFIX,
        redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        component="fetcher",
        publisher=publisher,
    )

    if QUEUE_BACKEND == "servicebus":
        _ensure_scan_sender()

    log_with_context(
        logger,
        logging.INFO,
        "Fetcher started; waiting for messages",
        queue_name=QUEUE_NAME,
        scan_queue_name=SCAN_QUEUE_NAME,
        queue_backend=QUEUE_BACKEND,
    )

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
                "stage": "fetcher",
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
            "Fetcher redis queues configured",
            queue_name=REDIS_QUEUE_KEY,
            dlq_name=REDIS_DLQ_KEY,
        )

    try:
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
    finally:
        _close_scan_sender()

    log_with_context(logger, logging.INFO, "Fetcher shutdown complete")


if __name__ == "__main__":
    main()
