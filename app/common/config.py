from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from common.job_index import build_job_index_record, upsert_job_index_record_sync
from common.result_store import upsert_result_sync
from common.url_dedupe import (
    UrlDedupeConfig,
    make_url_index_key,
    update_url_index_if_job_matches_sync,
)

_URL_DEDUPE = UrlDedupeConfig.from_env()


@dataclass(frozen=True)
class ConsumerConfig:
    queue_backend: str
    servicebus_conn: Optional[str]
    queue_name: str
    batch_size: int
    max_wait: int
    prefetch: int
    max_retries: int

    result_backend: str
    result_store_conn: Optional[str]
    result_table: str
    result_partition: str

    artifact_dir: str

    redis_url: Optional[str]
    redis_queue_key: str
    redis_dlq_key: str
    redis_result_prefix: str
    redis_result_ttl_seconds: int

    @staticmethod
    def from_env() -> ConsumerConfig:
        queue_backend = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
        servicebus_conn = os.getenv("SERVICEBUS_CONN")
        queue_name = os.getenv("QUEUE_NAME", "tasks")

        batch_size = int(os.getenv("BATCH_SIZE", "10"))
        max_wait = int(os.getenv("MAX_WAIT", "5"))
        prefetch = int(os.getenv("PREFETCH", "20"))
        max_retries = int(os.getenv("MAX_RETRIES", "5"))

        result_backend = os.getenv("RESULT_BACKEND", "table").strip().lower()
        result_store_conn = os.getenv("RESULT_STORE_CONN")
        result_table = os.getenv("RESULT_TABLE", "scanresults")
        result_partition = os.getenv("RESULT_PARTITION", "scan")

        artifact_dir = os.getenv("ARTIFACT_DIR", "/artifacts").strip() or "/artifacts"

        redis_url = os.getenv("REDIS_URL")
        redis_queue_key = os.getenv("REDIS_QUEUE_KEY", f"queue:{queue_name}")
        redis_dlq_key = os.getenv("REDIS_DLQ_KEY", f"dlq:{queue_name}")
        redis_result_prefix = os.getenv("REDIS_RESULT_PREFIX", "scan:")
        redis_result_ttl_seconds = int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0"))

        return ConsumerConfig(
            queue_backend=queue_backend,
            servicebus_conn=servicebus_conn,
            queue_name=queue_name,
            batch_size=batch_size,
            max_wait=max_wait,
            prefetch=prefetch,
            max_retries=max_retries,
            result_backend=result_backend,
            result_store_conn=result_store_conn,
            result_table=result_table,
            result_partition=result_partition,
            artifact_dir=artifact_dir,
            redis_url=redis_url,
            redis_queue_key=redis_queue_key,
            redis_dlq_key=redis_dlq_key,
            redis_result_prefix=redis_result_prefix,
            redis_result_ttl_seconds=redis_result_ttl_seconds,
        )

    def validate(self) -> None:
        if self.queue_backend not in ("servicebus", "redis"):
            raise RuntimeError("QUEUE_BACKEND must be 'servicebus' or 'redis'")
        if self.result_backend not in ("table", "redis"):
            raise RuntimeError("RESULT_BACKEND must be 'table' or 'redis'")

        if self.queue_backend == "servicebus" and not self.servicebus_conn:
            raise RuntimeError(
                "SERVICEBUS_CONN env var is required when QUEUE_BACKEND=servicebus"
            )
        if self.result_backend == "table" and not self.result_store_conn:
            raise RuntimeError(
                "RESULT_STORE_CONN env var is required when RESULT_BACKEND=table"
            )
        if (
            self.queue_backend == "redis" or self.result_backend == "redis"
        ) and not self.redis_url:
            raise RuntimeError(
                "REDIS_URL env var is required when using Redis backends"
            )


def init_redis_client(*, redis_url: str):
    try:
        import redis
    except Exception as e:
        raise RuntimeError(
            "Redis backends require the 'redis' package (pip install redis)"
        ) from e
    client = redis.Redis.from_url(redis_url, decode_responses=True)
    client.ping()
    return client


def init_table_client(*, conn_str: str, table_name: str):
    from azure.data.tables import TableServiceClient

    table_service = TableServiceClient.from_connection_string(conn_str=conn_str)
    table_service.create_table_if_not_exists(table_name=table_name)
    return table_service.get_table_client(table_name=table_name)


class ResultPersister:
    def __init__(
        self,
        *,
        backend: str,
        partition_key: str,
        table_client=None,
        redis_client=None,
        redis_prefix: str = "scan:",
        redis_ttl_seconds: int = 0,
        component: str = "worker",
    ) -> None:
        self._backend = backend
        self._partition_key = partition_key
        self._table_client = table_client
        self._redis_client = redis_client
        self._redis_prefix = redis_prefix
        self._redis_ttl_seconds = int(redis_ttl_seconds or 0)
        self._component = component

    def save_result(
        self,
        *,
        job_id: str,
        status: str,
        details: Optional[dict] = None,
        size_bytes: Optional[int] = None,
        correlation_id: Optional[str] = None,
        api_key_hash: Optional[str] = None,
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
        if api_key_hash:
            extra["api_key_hash"] = api_key_hash

        details_out: dict = dict(details or {})
        if url and "url" not in details_out:
            details_out["url"] = url

        try:
            if self._backend == "table" and not self._table_client:
                raise RuntimeError("Result store not initialized (table_client)")
            if self._backend == "redis" and not self._redis_client:
                raise RuntimeError("Result store not initialized (redis_client)")
            upsert_result_sync(
                backend=self._backend,
                partition_key=self._partition_key,
                job_id=job_id,
                status=status,
                error=error,
                details=details_out,
                extra=extra,
                table_client=self._table_client,
                redis_client=self._redis_client,
                redis_prefix=self._redis_prefix,
                redis_ttl_seconds=self._redis_ttl_seconds,
            )
            if api_key_hash and submitted_at:
                try:
                    job_record = build_job_index_record(
                        api_key_hash_value=api_key_hash,
                        job_id=job_id,
                        submitted_at=submitted_at,
                        status=status,
                        url=url,
                        scanned_at=scanned_at,
                        updated_at=scanned_at,
                        correlation_id=correlation_id,
                        error=error,
                    )
                    upsert_job_index_record_sync(
                        backend=self._backend,
                        api_key_hash_value=api_key_hash,
                        record=job_record,
                        table_client=self._table_client,
                        redis_client=self._redis_client,
                        redis_ttl_seconds=self._redis_ttl_seconds,
                    )
                except Exception:
                    pass

            if _URL_DEDUPE.enabled and url:
                dedupe_key_hash = api_key_hash if _URL_DEDUPE.scope == "apikey" else None
                if _URL_DEDUPE.scope != "apikey" or dedupe_key_hash:
                    try:
                        key = make_url_index_key(
                            url=url, api_key_hash=dedupe_key_hash, cfg=_URL_DEDUPE
                        )
                        update_url_index_if_job_matches_sync(
                            backend=self._backend,
                            cfg=_URL_DEDUPE,
                            key=key,
                            expected_job_id=job_id,
                            fields={
                                "status": status,
                                "updated_at": scanned_at,
                                "scanned_at": scanned_at,
                            },
                            table_client=self._table_client,
                            redis_client=self._redis_client,
                            result_ttl_seconds=self._redis_ttl_seconds,
                        )
                    except Exception:
                        # Never fail the scan pipeline on best-effort cache maintenance.
                        pass
            return True
        except Exception:
            logging.exception(
                "[%s] Failed to persist result (job_id=%s status=%s)",
                self._component,
                job_id,
                status,
            )
            return False
