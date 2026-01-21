"""Tests for common/config.py - consumer configuration and result persistence."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.config import ConsumerConfig  # noqa: E402


class TestConsumerConfig:
    def test_from_env_with_defaults(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            config = ConsumerConfig.from_env()
            assert config.queue_backend == "servicebus"
            assert config.queue_name == "tasks"
            assert config.batch_size == 10
            assert config.max_wait == 5
            assert config.prefetch == 20
            assert config.max_retries == 5
            assert config.result_backend == "table"
            assert config.result_table == "scanresults"
            assert config.result_partition == "scan"
            assert config.artifact_dir == "/artifacts"
            assert config.redis_queue_key == "queue:tasks"
            assert config.redis_dlq_key == "dlq:tasks"
            assert config.redis_result_prefix == "scan:"
            assert config.redis_result_ttl_seconds == 0

    def test_from_env_with_custom_values(self):
        with mock.patch.dict(
            os.environ,
            {
                "QUEUE_BACKEND": "redis",
                "QUEUE_NAME": "myqueue",
                "BATCH_SIZE": "20",
                "MAX_WAIT": "10",
                "PREFETCH": "50",
                "MAX_RETRIES": "3",
                "RESULT_BACKEND": "redis",
                "RESULT_TABLE": "mytable",
                "RESULT_PARTITION": "mypartition",
                "ARTIFACT_DIR": "/data/artifacts",
                "REDIS_URL": "redis://localhost:6379/0",
                "REDIS_QUEUE_KEY": "q:custom",
                "REDIS_DLQ_KEY": "dlq:custom",
                "REDIS_RESULT_PREFIX": "result:",
                "REDIS_RESULT_TTL_SECONDS": "3600",
            },
        ):
            config = ConsumerConfig.from_env()
            assert config.queue_backend == "redis"
            assert config.queue_name == "myqueue"
            assert config.batch_size == 20
            assert config.max_wait == 10
            assert config.prefetch == 50
            assert config.max_retries == 3
            assert config.result_backend == "redis"
            assert config.result_table == "mytable"
            assert config.result_partition == "mypartition"
            assert config.artifact_dir == "/data/artifacts"
            assert config.redis_url == "redis://localhost:6379/0"
            assert config.redis_queue_key == "q:custom"
            assert config.redis_dlq_key == "dlq:custom"
            assert config.redis_result_prefix == "result:"
            assert config.redis_result_ttl_seconds == 3600

    def test_validate_rejects_invalid_queue_backend(self):
        config = ConsumerConfig(
            queue_backend="invalid",
            servicebus_conn=None,
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="table",
            result_store_conn="conn",
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url=None,
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "QUEUE_BACKEND" in str(exc.value)

    def test_validate_rejects_invalid_result_backend(self):
        config = ConsumerConfig(
            queue_backend="servicebus",
            servicebus_conn="conn",
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="invalid",
            result_store_conn=None,
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url=None,
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "RESULT_BACKEND" in str(exc.value)

    def test_validate_requires_servicebus_conn_for_servicebus(self):
        config = ConsumerConfig(
            queue_backend="servicebus",
            servicebus_conn=None,
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="redis",
            result_store_conn=None,
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url="redis://localhost",
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "SERVICEBUS_CONN" in str(exc.value)

    def test_validate_requires_result_store_conn_for_table(self):
        config = ConsumerConfig(
            queue_backend="redis",
            servicebus_conn=None,
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="table",
            result_store_conn=None,
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url="redis://localhost",
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "RESULT_STORE_CONN" in str(exc.value)

    def test_validate_requires_redis_url_for_redis_queue(self):
        config = ConsumerConfig(
            queue_backend="redis",
            servicebus_conn=None,
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="table",
            result_store_conn="conn",
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url=None,
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "REDIS_URL" in str(exc.value)

    def test_validate_requires_redis_url_for_redis_result(self):
        config = ConsumerConfig(
            queue_backend="servicebus",
            servicebus_conn="conn",
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="redis",
            result_store_conn=None,
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url=None,
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        with pytest.raises(RuntimeError) as exc:
            config.validate()
        assert "REDIS_URL" in str(exc.value)

    def test_validate_passes_with_valid_servicebus_config(self):
        config = ConsumerConfig(
            queue_backend="servicebus",
            servicebus_conn="Endpoint=sb://...",
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="table",
            result_store_conn="DefaultEndpointsProtocol=...",
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url=None,
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        config.validate()  # Should not raise

    def test_validate_passes_with_valid_redis_config(self):
        config = ConsumerConfig(
            queue_backend="redis",
            servicebus_conn=None,
            queue_name="tasks",
            batch_size=10,
            max_wait=5,
            prefetch=20,
            max_retries=5,
            result_backend="redis",
            result_store_conn=None,
            result_table="scanresults",
            result_partition="scan",
            artifact_dir="/artifacts",
            redis_url="redis://localhost:6379/0",
            redis_queue_key="queue:tasks",
            redis_dlq_key="dlq:tasks",
            redis_result_prefix="scan:",
            redis_result_ttl_seconds=0,
        )
        config.validate()  # Should not raise
