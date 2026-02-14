"""
Queue consumer helpers (Azure Service Bus or Redis).

This module provides a small, dependency-light "consumer loop" used by both the
fetcher and worker:

- Redis backend: uses BLPOP, supports a lightweight JSON envelope, and requeues
  by incrementing `delivery_count` until `max_retries`, then pushes to a DLQ list.
- Service Bus backend: uses receiver abandon/dead-letter semantics.

The processing function is synchronous by design to keep worker entrypoints simple.
"""

from __future__ import annotations

import json
import logging
import signal as os_signal
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from common.errors import classify_exception

logger = logging.getLogger(__name__)


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


def _should_soft_complete(info) -> bool:
    # Treat non-retryable upstream 4xx as terminal-but-expected (avoid DLQ noise).
    return _is_http_4xx(getattr(info, "code", "")) and not bool(
        getattr(info, "retryable", False)
    )


@dataclass
class ShutdownFlag:
    shutdown: bool = False


def install_signal_handlers(flag: ShutdownFlag) -> None:
    def _signal_handler(*_):
        flag.shutdown = True

    os_signal.signal(os_signal.SIGTERM, _signal_handler)
    os_signal.signal(os_signal.SIGINT, _signal_handler)


def decode_servicebus_body(msg) -> dict:
    """Decode an Azure Service Bus message body into a dict."""
    body_bytes = b"".join(
        bytes(b) if isinstance(b, memoryview) else b for b in msg.body
    )
    return json.loads(body_bytes.decode("utf-8"))


def decode_redis_body(
    raw: str,
) -> Tuple[Optional[dict], Optional[dict], int, Optional[Exception]]:
    """
    Decode a Redis queue item into a task dict.

    Supports two formats:
      1) Envelope: {"payload": {...}, "delivery_count": N, ...}
      2) Bare task dict: {...} (treated as delivery_count=1)
    """
    task: Optional[dict] = None
    envelope: Optional[dict] = None
    delivery_count = 1
    try:
        decoded = json.loads(raw)
        if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
            envelope = decoded
            task = decoded["payload"]
            try:
                delivery_count = int(decoded.get("delivery_count") or 1)
            except Exception as e:
                return task, envelope, 1, e
            return task, envelope, delivery_count, None
        if isinstance(decoded, dict):
            task = decoded
            envelope = {"schema": "unknown", "delivery_count": 1, "payload": decoded}
            return task, envelope, 1, None
        return (
            None,
            None,
            1,
            ValueError("invalid message payload (expected JSON object)"),
        )
    except Exception as e:
        return None, None, 1, e


def _safe_delivery_count(msg) -> int:
    """Best-effort conversion for SDK delivery_count (can be None in stubs)."""
    try:
        if msg is None:
            return 0
        value = getattr(msg, "delivery_count", None)
        if value is None:
            return 0
        return int(value)
    except Exception:
        return 0


def _consumer_extra_fields(
    *,
    component: str,
    queue_backend: str,
    job_id: Optional[str],
    correlation_id: Optional[str],
    delivery_count: int,
    error_code: str,
    error_message: str,
    retryable: bool,
    dlq_reason: Optional[str] = None,
) -> dict[str, Any]:
    return {
        "component": component,
        "queue_backend": queue_backend,
        "job_id": job_id,
        "correlation_id": correlation_id,
        "delivery_count": int(delivery_count),
        "error_code": str(error_code or ""),
        "error_message": str(error_message or ""),
        "retryable": bool(retryable),
        "dlq_reason": dlq_reason,
    }


def _log_consumer_event(
    *,
    level: int,
    message: str,
    component: str,
    queue_backend: str,
    job_id: Optional[str],
    correlation_id: Optional[str],
    delivery_count: int,
    error_code: str,
    error_message: str,
    retryable: bool,
    dlq_reason: Optional[str] = None,
    exc_info: bool = False,
) -> None:
    logger.log(
        level,
        message,
        extra={
            "extra_fields": _consumer_extra_fields(
                component=component,
                queue_backend=queue_backend,
                job_id=job_id,
                correlation_id=correlation_id,
                delivery_count=delivery_count,
                error_code=error_code,
                error_message=error_message,
                retryable=retryable,
                dlq_reason=dlq_reason,
            )
        },
        exc_info=exc_info,
    )


def run_consumer(
    *,
    component: str,
    shutdown_flag: ShutdownFlag,
    queue_backend: str,
    queue_name: str,
    batch_size: int,
    max_wait: int,
    prefetch: int,
    max_retries: int,
    process: Callable[[dict], Any],
    on_exception: Optional[
        Callable[[Optional[dict], Exception, int, int], None]
    ] = None,
    servicebus_conn: Optional[str] = None,
    redis_client: Any = None,
    redis_queue_key: Optional[str] = None,
    redis_dlq_key: Optional[str] = None,
) -> None:
    """Run the main consumer loop for the configured queue backend."""
    if queue_backend == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        if not redis_queue_key or not redis_dlq_key:
            raise RuntimeError("Redis queue keys not configured")

        while not shutdown_flag.shutdown:
            item = redis_client.blpop(redis_queue_key, timeout=max_wait)
            if not item:
                continue

            _queue, raw = item
            started_at = time.time()
            task: Optional[dict] = None
            envelope: Optional[dict] = None
            delivery_count = 1
            try:
                task, envelope, delivery_count, decode_error = decode_redis_body(raw)
                if decode_error:
                    raise decode_error
                if not isinstance(task, dict):
                    raise ValueError("invalid message payload (expected JSON object)")
                process(task)
            except Exception as e:
                duration_ms = int((time.time() - started_at) * 1000)
                if on_exception:
                    on_exception(task, e, delivery_count, duration_ms)

                info = classify_exception(e)
                retrying = info.retryable and delivery_count < max_retries
                job_id = task.get("job_id") if isinstance(task, dict) else None
                correlation_id = (
                    task.get("correlation_id") if isinstance(task, dict) else None
                )

                if retrying:
                    next_envelope = envelope or {
                        "delivery_count": delivery_count,
                        "payload": task or {},
                    }
                    next_envelope["delivery_count"] = delivery_count + 1
                    redis_client.rpush(redis_queue_key, json.dumps(next_envelope))
                    _log_consumer_event(
                        level=logging.ERROR if info.log_traceback else logging.WARNING,
                        message=(
                            f"[{component}] Requeued message "
                            f"(delivery_count={delivery_count} code={info.code}): {info.message}"
                        ),
                        component=component,
                        queue_backend="redis",
                        job_id=str(job_id) if job_id is not None else None,
                        correlation_id=(
                            str(correlation_id) if correlation_id is not None else None
                        ),
                        delivery_count=delivery_count,
                        error_code=info.code,
                        error_message=info.message,
                        retryable=info.retryable,
                        exc_info=info.log_traceback,
                    )
                else:
                    if _should_soft_complete(info):
                        _log_consumer_event(
                            level=logging.WARNING,
                            message=(
                                f"[{component}] Soft-failed message "
                                f"(delivery_count={delivery_count} code={info.code}): {info.message}"
                            ),
                            component=component,
                            queue_backend="redis",
                            job_id=str(job_id) if job_id is not None else None,
                            correlation_id=(
                                str(correlation_id)
                                if correlation_id is not None
                                else None
                            ),
                            delivery_count=delivery_count,
                            error_code=info.code,
                            error_message=info.message,
                            retryable=info.retryable,
                        )
                        continue
                    dlq_reason = info.code
                    if info.retryable:
                        dlq_reason = "max-retries-exceeded"
                    dlq_envelope = envelope or {
                        "delivery_count": delivery_count,
                        "payload": task or {},
                    }
                    dlq_envelope["last_error"] = info.message
                    dlq_envelope["last_error_code"] = info.code
                    dlq_envelope["dlq_reason"] = dlq_reason
                    redis_client.rpush(redis_dlq_key, json.dumps(dlq_envelope))
                    _log_consumer_event(
                        level=logging.ERROR,
                        message=(
                            f"[{component}] DLQ'd message "
                            f"(delivery_count={delivery_count} dlq_reason={dlq_reason} "
                            f"code={info.code}): {info.message}"
                        ),
                        component=component,
                        queue_backend="redis",
                        job_id=str(job_id) if job_id is not None else None,
                        correlation_id=(
                            str(correlation_id) if correlation_id is not None else None
                        ),
                        delivery_count=delivery_count,
                        error_code=info.code,
                        error_message=info.message,
                        retryable=info.retryable,
                        dlq_reason=str(dlq_reason),
                        exc_info=info.log_traceback,
                    )
        return

    if queue_backend == "servicebus":
        if not servicebus_conn:
            raise RuntimeError(
                "SERVICEBUS_CONN env var is required when QUEUE_BACKEND=servicebus"
            )

        client = ServiceBusClient.from_connection_string(
            servicebus_conn, logging_enable=True
        )
        with client:
            receiver = client.get_queue_receiver(
                queue_name=queue_name,
                max_wait_time=max_wait,
                prefetch_count=prefetch,
            )
            with receiver:
                while not shutdown_flag.shutdown:
                    try:
                        messages = receiver.receive_messages(
                            max_message_count=batch_size,
                            max_wait_time=max_wait,
                        )
                        if not messages:
                            continue

                        for msg in messages:
                            task = None
                            started_at = time.time()
                            try:
                                task = decode_servicebus_body(msg)
                                process(task)
                                receiver.complete_message(msg)
                            except Exception as e:
                                duration_ms = int((time.time() - started_at) * 1000)
                                delivery_count = _safe_delivery_count(msg)
                                if on_exception:
                                    on_exception(task, e, delivery_count, duration_ms)

                                info = classify_exception(e)
                                retrying = (
                                    info.retryable and delivery_count < max_retries
                                )
                                job_id = (
                                    task.get("job_id")
                                    if isinstance(task, dict)
                                    else None
                                )
                                correlation_id = (
                                    task.get("correlation_id")
                                    if isinstance(task, dict)
                                    else None
                                )

                                if retrying:
                                    receiver.abandon_message(msg)
                                    _log_consumer_event(
                                        level=(
                                            logging.ERROR
                                            if info.log_traceback
                                            else logging.WARNING
                                        ),
                                        message=(
                                            f"[{component}] Abandoned message "
                                            f"(delivery_count={delivery_count} code={info.code}): {info.message}"
                                        ),
                                        component=component,
                                        queue_backend="servicebus",
                                        job_id=(
                                            str(job_id) if job_id is not None else None
                                        ),
                                        correlation_id=(
                                            str(correlation_id)
                                            if correlation_id is not None
                                            else None
                                        ),
                                        delivery_count=delivery_count,
                                        error_code=info.code,
                                        error_message=info.message,
                                        retryable=info.retryable,
                                        exc_info=info.log_traceback,
                                    )
                                else:
                                    if _should_soft_complete(info):
                                        try:
                                            receiver.complete_message(msg)
                                            _log_consumer_event(
                                                level=logging.WARNING,
                                                message=(
                                                    f"[{component}] Soft-completed message "
                                                    f"(delivery_count={delivery_count} code={info.code}): {info.message}"
                                                ),
                                                component=component,
                                                queue_backend="servicebus",
                                                job_id=(
                                                    str(job_id)
                                                    if job_id is not None
                                                    else None
                                                ),
                                                correlation_id=(
                                                    str(correlation_id)
                                                    if correlation_id is not None
                                                    else None
                                                ),
                                                delivery_count=delivery_count,
                                                error_code=info.code,
                                                error_message=info.message,
                                                retryable=info.retryable,
                                            )
                                        except Exception as complete_exc:
                                            _log_consumer_event(
                                                level=logging.ERROR,
                                                message=(
                                                    f"[{component}] Failed to complete soft-failed message "
                                                    f"(delivery_count={delivery_count}): {complete_exc}"
                                                ),
                                                component=component,
                                                queue_backend="servicebus",
                                                job_id=(
                                                    str(job_id)
                                                    if job_id is not None
                                                    else None
                                                ),
                                                correlation_id=(
                                                    str(correlation_id)
                                                    if correlation_id is not None
                                                    else None
                                                ),
                                                delivery_count=delivery_count,
                                                error_code=info.code,
                                                error_message=str(complete_exc),
                                                retryable=False,
                                                dlq_reason="complete-failed",
                                            )
                                        continue
                                    dlq_reason = info.code or "error"
                                    dlq_description = info.message
                                    if info.retryable and delivery_count >= max_retries:
                                        dlq_reason = "max-retries-exceeded"
                                        if info.code and info.message:
                                            dlq_description = (
                                                f"{info.code}: {info.message}"
                                            )

                                    receiver.dead_letter_message(
                                        msg,
                                        reason=dlq_reason,
                                        error_description=dlq_description,
                                    )
                                    _log_consumer_event(
                                        level=logging.ERROR,
                                        message=(
                                            f"[{component}] DLQ'd message "
                                            f"(delivery_count={delivery_count} dlq_reason={dlq_reason} "
                                            f"code={info.code}): {info.message}"
                                        ),
                                        component=component,
                                        queue_backend="servicebus",
                                        job_id=(
                                            str(job_id) if job_id is not None else None
                                        ),
                                        correlation_id=(
                                            str(correlation_id)
                                            if correlation_id is not None
                                            else None
                                        ),
                                        delivery_count=delivery_count,
                                        error_code=info.code,
                                        error_message=info.message,
                                        retryable=info.retryable,
                                        dlq_reason=str(dlq_reason),
                                        exc_info=info.log_traceback,
                                    )
                    except OperationTimeoutError:
                        continue
                    except ServiceBusError as e:
                        logger.error(
                            "[%s] ServiceBusError",
                            component,
                            extra={
                                "extra_fields": {
                                    "component": component,
                                    "queue_backend": "servicebus",
                                    "error_code": "servicebus_error",
                                    "error_message": str(e),
                                }
                            },
                        )
                        time.sleep(2)
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {queue_backend}")
