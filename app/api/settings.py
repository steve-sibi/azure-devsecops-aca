from __future__ import annotations

import os
from pathlib import Path

from common.api_keys import ApiKeyStoreConfig
from common.config import ConsumerConfig
from common.live_updates import RedisStreamsConfig
from common.limits import get_api_limits, get_file_scan_limits
from common.url_dedupe import UrlDedupeConfig
from common.webpubsub import WebPubSubConfig
from fastapi.security.api_key import APIKeyHeader

# Shared configuration (queues, results, redis)
_CONSUMER_CFG = ConsumerConfig.from_env()
QUEUE_NAME = _CONSUMER_CFG.queue_name
QUEUE_BACKEND = _CONSUMER_CFG.queue_backend
SERVICEBUS_CONN = _CONSUMER_CFG.servicebus_conn
RESULT_BACKEND = _CONSUMER_CFG.result_backend
RESULT_STORE_CONN = _CONSUMER_CFG.result_store_conn
RESULT_TABLE = _CONSUMER_CFG.result_table
RESULT_PARTITION = _CONSUMER_CFG.result_partition
REDIS_URL = _CONSUMER_CFG.redis_url
REDIS_QUEUE_KEY = _CONSUMER_CFG.redis_queue_key
REDIS_RESULT_PREFIX = _CONSUMER_CFG.redis_result_prefix
REDIS_RESULT_TTL_SECONDS = _CONSUMER_CFG.redis_result_ttl_seconds
REDIS_JOB_INDEX_ZSET_PREFIX = (
    os.getenv("REDIS_JOB_INDEX_ZSET_PREFIX", "jobsidx:") or "jobsidx:"
).strip()
REDIS_JOB_INDEX_HASH_PREFIX = (
    os.getenv("REDIS_JOB_INDEX_HASH_PREFIX", "jobs:") or "jobs:"
).strip()

# Screenshots (optional)
SCREENSHOT_REDIS_PREFIX = os.getenv("SCREENSHOT_REDIS_PREFIX", "screenshot:")
SCREENSHOT_CONTAINER = os.getenv("SCREENSHOT_CONTAINER", "screenshots")
SCREENSHOT_FORMAT = os.getenv("SCREENSHOT_FORMAT", "jpeg")

# Web PubSub (optional)
WEBPUBSUB_CFG = WebPubSubConfig.from_env()
LIVE_UPDATES_REDIS_CFG = RedisStreamsConfig.from_env()

# API hardening
API_KEY = os.getenv("API_KEY")
API_KEYS = os.getenv("ACA_API_KEYS") or os.getenv("API_KEYS") or ""
API_ADMIN_KEY = os.getenv("API_ADMIN_KEY")
API_ADMIN_KEYS = os.getenv("API_ADMIN_KEYS") or ""
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
API_KEY_STORE_ENABLED = os.getenv("API_KEY_STORE_ENABLED", "true").lower() in (
    "1",
    "true",
    "yes",
)
_API_KEY_STORE_CFG = ApiKeyStoreConfig.from_env()
_API_LIMITS = get_api_limits()
RATE_LIMIT_RPM = _API_LIMITS.rate_limit_rpm
RATE_LIMIT_WRITE_RPM = _API_LIMITS.rate_limit_write_rpm
RATE_LIMIT_READ_RPM = _API_LIMITS.rate_limit_read_rpm
RATE_LIMIT_WINDOW_SECONDS = _API_LIMITS.rate_limit_window_seconds
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)
MAX_DASHBOARD_POLL_SECONDS = _API_LIMITS.max_dashboard_poll_seconds
_URL_DEDUPE = UrlDedupeConfig.from_env()
_DEFAULT_URL_VISIBILITY = (
    (os.getenv("URL_RESULT_VISIBILITY_DEFAULT", "shared") or "shared").strip().lower()
)
if _DEFAULT_URL_VISIBILITY not in ("shared", "private"):
    _DEFAULT_URL_VISIBILITY = "shared"

# File scanning (ClamAV)
CLAMAV_HOST = (os.getenv("CLAMAV_HOST", "127.0.0.1") or "127.0.0.1").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
_FILE_SCAN_LIMITS = get_file_scan_limits()
CLAMAV_TIMEOUT_SECONDS = _FILE_SCAN_LIMITS.clamav_timeout_seconds
FILE_SCAN_MAX_BYTES = _FILE_SCAN_LIMITS.max_bytes
FILE_SCAN_INCLUDE_VERSION = _FILE_SCAN_LIMITS.include_version

# HTML dashboard templates live alongside this file.
DASHBOARD_TEMPLATE = (
    Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
)
FILE_SCANNER_TEMPLATE = (
    Path(__file__).with_name("file_scanner.html").read_text(encoding="utf-8")
)

_API_KEY_MINT_PREFIX = (os.getenv("API_KEY_MINT_PREFIX", "aca") or "aca").strip() or "aca"
try:
    _API_KEY_MINT_BYTES = max(16, int(os.getenv("API_KEY_MINT_BYTES", "32")))
except Exception:
    _API_KEY_MINT_BYTES = 32

api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)
