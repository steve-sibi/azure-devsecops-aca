from contextlib import asynccontextmanager
from collections import deque
from datetime import datetime, timezone
import asyncio
import hashlib
import html
import ipaddress
import json
import os
import secrets
import socket
import time
from typing import Any, Optional
from uuid import uuid4
from urllib.parse import urlsplit

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError
from azure.data.tables.aio import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.responses import HTMLResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

# ---------- Settings ----------
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")  # connection string (current)
SERVICEBUS_FQDN = os.getenv(
    "SERVICEBUS_FQDN"
)  # e.g. "mynamespace.servicebus.windows.net"
USE_MI = os.getenv("USE_MANAGED_IDENTITY", "false").lower() in ("1", "true", "yes")
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional
RESULT_BACKEND = os.getenv("RESULT_BACKEND", "table").strip().lower()
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")

# Local dev backends (Redis)
REDIS_URL = os.getenv("REDIS_URL")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", f"queue:{QUEUE_NAME}")
REDIS_RESULT_PREFIX = os.getenv("REDIS_RESULT_PREFIX", "scan:")
REDIS_RESULT_TTL_SECONDS = int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0"))

# API hardening
API_KEY = os.getenv("API_KEY")
API_KEY_HEADER = os.getenv("API_KEY_HEADER", "X-API-Key")
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
RATE_LIMIT_RPM = int(os.getenv("RATE_LIMIT_RPM", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)
MAX_DASHBOARD_POLL_SECONDS = int(os.getenv("MAX_DASHBOARD_POLL_SECONDS", "180"))

# Globals set during app startup
sb_client: Optional[ServiceBusClient] = None
sb_sender: Optional[ServiceBusSender] = None
table_service: Optional[TableServiceClient] = None
table_client = None
redis_client = None

api_key_scheme = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

# Simple in-memory rate limiter (per API key hash); good enough for demos.
_rate_lock = asyncio.Lock()
_rate_buckets: dict[str, deque[float]] = {}


class TaskIn(BaseModel):
    # adjust fields to your real payload
    payload: dict


class ScanRequest(BaseModel):
    url: str = Field(..., description="HTTPS URL to scan")
    type: str = Field("url", pattern="^(url|file)$")
    source: Optional[str] = Field(None, description="Optional source identifier")
    metadata: Optional[dict] = Field(None, description="Optional metadata")


def _require_https(url: str):
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Only HTTPS URLs are allowed")


async def _validate_public_destination(url: str):
    if not BLOCK_PRIVATE_NETWORKS:
        return

    parsed = urlsplit(url)
    host = parsed.hostname
    if not host:
        raise HTTPException(status_code=400, detail="URL host is required")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Userinfo in URL is not allowed")
    if parsed.port and parsed.port != 443:
        raise HTTPException(
            status_code=400, detail="Only default HTTPS port 443 is allowed"
        )
    if host.lower() in ("localhost",):
        raise HTTPException(status_code=400, detail="Localhost is not allowed")

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except socket.gaierror:
            raise HTTPException(status_code=400, detail="DNS resolution failed")
        ips = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not ips:
            raise HTTPException(status_code=400, detail="No A/AAAA records found")
        if any(not ip.is_global for ip in ips):
            raise HTTPException(
                status_code=400,
                detail="URL resolves to a non-public IP address (blocked)",
            )
    else:
        if not ip_literal.is_global:
            raise HTTPException(
                status_code=400,
                detail="Direct IP destinations must be publicly routable",
            )


async def _enforce_rate_limit(api_key: str):
    if RATE_LIMIT_RPM <= 0:
        return
    window = max(1, RATE_LIMIT_WINDOW_SECONDS)
    now = time.monotonic()
    bucket = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    async with _rate_lock:
        q = _rate_buckets.setdefault(bucket, deque())
        cutoff = now - window
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= RATE_LIMIT_RPM:
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({RATE_LIMIT_RPM}/{window}s)",
            )
        q.append(now)


async def require_api_key(
    request: Request, api_key: Optional[str] = Security(api_key_scheme)
):
    if not REQUIRE_API_KEY:
        return
    if not API_KEY:
        raise HTTPException(status_code=500, detail="API_KEY is not configured")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")
    if not secrets.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key")
    await _enforce_rate_limit(api_key)


async def _upsert_result(
    job_id: str,
    status: str,
    details: Optional[dict] = None,
    verdict: Optional[str] = None,
    error: Optional[str] = None,
    extra: Optional[dict] = None,
):
    """Persist status/verdict to the table for status checks."""
    if RESULT_BACKEND == "table":
        if not table_client:
            return
        entity: dict[str, Any] = {
            "PartitionKey": RESULT_PARTITION,
            "RowKey": job_id,
            "status": status,
            "verdict": verdict or "",
            "error": error or "",
        }
        if details:
            entity["details"] = json.dumps(details)
        if extra:
            for k, v in extra.items():
                entity[k] = v
        await table_client.upsert_entity(entity=entity)
        return

    if RESULT_BACKEND == "redis":
        if not redis_client:
            return
        key = f"{REDIS_RESULT_PREFIX}{job_id}"
        entity = {
            "status": status,
            "verdict": verdict or "",
            "error": error or "",
        }
        if details is not None:
            entity["details"] = json.dumps(details)
        if extra:
            entity.update({str(k): v for k, v in extra.items()})
        await redis_client.hset(key, mapping=entity)
        if REDIS_RESULT_TTL_SECONDS > 0:
            await redis_client.expire(key, REDIS_RESULT_TTL_SECONDS)
        return

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}")


async def _get_result_entity(job_id: str) -> Optional[dict]:
    if RESULT_BACKEND == "table":
        if not table_client:
            return None
        try:
            return await table_client.get_entity(
                partition_key=RESULT_PARTITION, row_key=job_id
            )
        except ResourceNotFoundError:
            return None

    if RESULT_BACKEND == "redis":
        if not redis_client:
            return None
        key = f"{REDIS_RESULT_PREFIX}{job_id}"
        data = await redis_client.hgetall(key)
        return data or None

    raise RuntimeError(f"Unsupported RESULT_BACKEND: {RESULT_BACKEND}")


async def _enqueue_json(
    payload: dict,
    *,
    schema: str,
    message_id: str,
    application_properties: Optional[dict] = None,
):
    if QUEUE_BACKEND == "servicebus":
        if not sb_sender:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        props = {"schema": schema}
        if application_properties:
            props.update(application_properties)
        msg = ServiceBusMessage(
            json.dumps(payload),
            content_type="application/json",
            message_id=message_id,
            application_properties=props,
        )
        await sb_sender.send_messages(msg)
        return

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise HTTPException(status_code=503, detail="Queue not initialized")
        envelope = {
            "schema": schema,
            "message_id": message_id,
            "delivery_count": 1,
            "payload": payload,
        }
        if application_properties:
            envelope["application_properties"] = application_properties
        await redis_client.rpush(REDIS_QUEUE_KEY, json.dumps(envelope))
        return

    raise RuntimeError(f"Unsupported QUEUE_BACKEND: {QUEUE_BACKEND}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sb_client, sb_sender, table_service, table_client, redis_client

    cred = None  # will hold DefaultAzureCredential if MI is used
    if QUEUE_BACKEND not in ("servicebus", "redis"):
        raise RuntimeError("QUEUE_BACKEND must be 'servicebus' or 'redis'")
    if RESULT_BACKEND not in ("table", "redis"):
        raise RuntimeError("RESULT_BACKEND must be 'table' or 'redis'")

    # --- Optional Redis client (local dev backends) ---
    if (QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis") and not REDIS_URL:
        raise RuntimeError("REDIS_URL is required when using Redis backends")

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        try:
            import redis.asyncio as redis_async
        except Exception as e:
            raise RuntimeError(
                "Redis backends require the 'redis' package (pip install redis)"
            ) from e
        redis_client = redis_async.from_url(REDIS_URL, decode_responses=True)
        await redis_client.ping()

    # --- Queue backend ---
    if QUEUE_BACKEND == "servicebus":
        if USE_MI:
            try:
                from azure.identity.aio import DefaultAzureCredential
            except Exception as e:
                raise RuntimeError(
                    "USE_MANAGED_IDENTITY=true but azure-identity is not installed"
                ) from e
            if not SERVICEBUS_FQDN:
                raise RuntimeError(
                    "SERVICEBUS_FQDN is required when using Managed Identity"
                )
            cred = DefaultAzureCredential()
            sb_client = ServiceBusClient(
                fully_qualified_namespace=SERVICEBUS_FQDN, credential=cred
            )
        else:
            if not SERVICEBUS_CONN:
                raise RuntimeError("SERVICEBUS_CONN environment variable is required")
            sb_client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN)

        await sb_client.__aenter__()
        sb_sender = sb_client.get_queue_sender(queue_name=QUEUE_NAME)
        await sb_sender.__aenter__()

    # --- Result store backend ---
    if RESULT_BACKEND == "table":
        if not RESULT_STORE_CONN:
            raise RuntimeError("RESULT_STORE_CONN environment variable is required")
        table_service = TableServiceClient.from_connection_string(
            conn_str=RESULT_STORE_CONN
        )
        table_client = table_service.get_table_client(table_name=RESULT_TABLE)
        await table_service.__aenter__()
        await table_service.create_table_if_not_exists(table_name=RESULT_TABLE)

    # --- Optional OpenTelemetry tracing (only if packages + conn are present) ---
    if APPINSIGHTS_CONN:
        try:
            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter
            from opentelemetry import trace
            from opentelemetry.sdk.resources import SERVICE_NAME, Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create({SERVICE_NAME: "aca-fastapi-api"})
            provider = TracerProvider(resource=resource)
            trace.set_tracer_provider(provider)
            exporter = AzureMonitorTraceExporter.from_connection_string(
                APPINSIGHTS_CONN
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except Exception as e:
            # Optional; don't fail app startup on telemetry wiring issues
            print("OTel init skipped:", e)

    yield  # ---- App runs ----

    # ---- Cleanup on shutdown ----
    if sb_sender:
        await sb_sender.__aexit__(None, None, None)
    if sb_client:
        await sb_client.__aexit__(None, None, None)
    if table_service:
        await table_service.__aexit__(None, None, None)
    if redis_client:
        try:
            maybe = redis_client.close()
            if asyncio.iscoroutine(maybe):
                await maybe
        finally:
            pool = getattr(redis_client, "connection_pool", None)
            disconnect = getattr(pool, "disconnect", None) if pool else None
            if callable(disconnect):
                maybe = disconnect()
                if asyncio.iscoroutine(maybe):
                    await maybe
    if cred:
        # Properly close the async credential if used
        await cred.close()


app = FastAPI(title="Azure DevSecOps URL Scanner", lifespan=lifespan)


@app.middleware("http")
async def otel_request_spans(request: Request, call_next):
    if not APPINSIGHTS_CONN or request.url.path == "/healthz":
        return await call_next(request)

    from opentelemetry import trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    tracer = trace.get_tracer("aca-fastapi-api")
    span_name = f"{request.method} {request.url.path}"

    with tracer.start_as_current_span(span_name, kind=SpanKind.SERVER) as span:
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.target", request.url.path)
        span.set_attribute("http.url", str(request.url))

        try:
            response = await call_next(request)
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise

        route = request.scope.get("route")
        route_path = getattr(route, "path", None)
        if route_path:
            span.update_name(f"{request.method} {route_path}")
            span.set_attribute("http.route", route_path)

        span.set_attribute("http.status_code", response.status_code)
        if response.status_code >= 500:
            span.set_status(Status(StatusCode.ERROR))
        return response


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    # Minimal single-file dashboard; avoids extra dependencies.
    template = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Azure DevSecOps URL Scanner</title>
    <meta name="description" content="Submit URL scan jobs and poll for results." />
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f6f7fb;
        --card: #ffffff;
        --text: #111827;
        --muted: #6b7280;
        --border: #e5e7eb;
        --shadow: 0 10px 30px rgba(0,0,0,0.08);
        --primary: #2563eb;
        --primary-ink: #ffffff;
        --success: #16a34a;
        --danger: #dc2626;
        --code-bg: #0b1020;
        --code-fg: #d6e0ff;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #0b1020;
          --card: #0f172a;
          --text: #e5e7eb;
          --muted: #94a3b8;
          --border: #22304a;
          --shadow: 0 14px 40px rgba(0,0,0,0.35);
          --primary: #60a5fa;
          --primary-ink: #0b1020;
          --success: #4ade80;
          --danger: #fb7185;
          --code-bg: #070b18;
          --code-fg: #d6e0ff;
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        background: var(--bg);
        color: var(--text);
      }
      a { color: var(--primary); }
      code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      .app { max-width: 1100px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
      .header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
      .header h1 { margin: 0; font-size: 1.65rem; letter-spacing: -0.02em; }
      .sub { margin: 0.35rem 0 0; color: var(--muted); line-height: 1.4; }
      .grid { margin-top: 1.25rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; align-items: start; }
      @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
      .card { background: var(--card); border: 1px solid var(--border); border-radius: 14px; box-shadow: var(--shadow); padding: 1rem; }
      .card.full { grid-column: 1 / -1; }
      .card h2 { margin: 0 0 0.75rem; font-size: 1.05rem; }
      .card-head { display: flex; justify-content: space-between; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.75rem; }
      .field { margin-bottom: 0.9rem; }
      label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.35rem; }
      input {
        width: 100%;
        padding: 0.65rem 0.75rem;
        border-radius: 10px;
        border: 1px solid var(--border);
        background: transparent;
        color: var(--text);
      }
      .help { margin-top: 0.35rem; font-size: 0.85rem; color: var(--muted); }
      .actions { display: flex; gap: 0.6rem; flex-wrap: wrap; align-items: center; }
      button {
        border: 1px solid var(--border);
        background: transparent;
        color: var(--text);
        padding: 0.6rem 0.85rem;
        border-radius: 10px;
        cursor: pointer;
      }
      button.primary {
        background: var(--primary);
        border-color: var(--primary);
        color: var(--primary-ink);
        font-weight: 600;
      }
      button:disabled { opacity: 0.55; cursor: not-allowed; }
      .status { margin-top: 0.85rem; min-height: 1.25rem; display: flex; align-items: center; gap: 0.5rem; color: var(--muted); }
      .badge { font-size: 0.75rem; padding: 0.2rem 0.55rem; border-radius: 999px; border: 1px solid var(--border); background: transparent; color: var(--text); }
      .badge.ok { border-color: rgba(22,163,74,0.5); background: rgba(22,163,74,0.12); }
      .badge.bad { border-color: rgba(220,38,38,0.5); background: rgba(220,38,38,0.12); }
      .badge.info { border-color: rgba(37,99,235,0.45); background: rgba(37,99,235,0.12); }
      .muted { color: var(--muted); }
      .small { font-size: 0.85rem; }
      pre {
        margin: 0;
        background: var(--code-bg);
        color: var(--code-fg);
        padding: 1rem;
        border-radius: 12px;
        overflow: auto;
        border: 1px solid var(--border);
      }
      .table-wrap { overflow: auto; border: 1px solid var(--border); border-radius: 12px; }
      table { width: 100%; border-collapse: collapse; min-width: 720px; }
      th, td { text-align: left; padding: 0.55rem 0.65rem; border-bottom: 1px solid var(--border); vertical-align: top; }
      th {
        font-size: 0.78rem;
        letter-spacing: 0.02em;
        text-transform: uppercase;
        color: var(--muted);
        background: rgba(148,163,184,0.10);
        position: sticky;
        top: 0;
      }
      tr:last-child td { border-bottom: none; }
      .nowrap { white-space: nowrap; }
      .url-cell { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .filter { flex: 1; min-width: 220px; }
    </style>
  </head>
  <body>
    <div class="app">
      <header class="header">
        <div>
          <h1>Azure DevSecOps URL Scanner</h1>
          <p class="sub">Submit scan jobs and poll results. Swagger: <a href="/docs">/docs</a>. API key required for scan endpoints.</p>
        </div>
        <div class="actions">
          <button id="clearHistory" type="button">Clear history</button>
        </div>
      </header>

      <div class="grid">
        <section class="card">
          <h2>New scan</h2>
          <div class="field">
            <label for="apiKey">API key <span class="muted">(header: __API_KEY_HEADER__)</span></label>
            <input id="apiKey" autocomplete="off" placeholder="Paste API key" />
            <div class="help">Saved in this browser only (local storage).</div>
          </div>
          <div class="field">
            <label for="url">HTTPS URL to scan</label>
            <input id="url" inputmode="url" value="https://example.com" placeholder="https://example.com" />
            <div class="help">Only public HTTPS destinations on port 443 are allowed.</div>
          </div>
          <div class="actions">
            <button id="start" class="primary" type="button">Start scan</button>
            <button id="checkCurrent" type="button" disabled>Check job</button>
            <button id="copyJson" type="button" disabled>Copy JSON</button>
          </div>
          <div id="status" class="status" aria-live="polite"></div>
        </section>

        <section class="card">
          <div class="card-head">
            <h2>History</h2>
            <input id="historyFilter" class="filter" placeholder="Filter by URL or job id" />
          </div>
          <div class="table-wrap" role="region" aria-label="Scan history">
            <table>
              <thead>
                <tr>
                  <th class="nowrap">When</th>
                  <th>URL</th>
                  <th class="nowrap">Job</th>
                  <th class="nowrap">Status</th>
                  <th class="nowrap">Actions</th>
                </tr>
              </thead>
              <tbody id="historyBody"></tbody>
            </table>
          </div>
          <p class="muted small">History is stored locally in your browser.</p>
        </section>

        <section class="card full">
          <div class="card-head">
            <h2>Response</h2>
            <div class="actions">
              <button id="copyJson2" type="button" disabled>Copy JSON</button>
            </div>
          </div>
          <pre id="out">{}</pre>
        </section>
      </div>
    </div>

    <script>
      (function () {
        const API_KEY_HEADER = __API_KEY_HEADER_JSON__;
        const MAX_POLL_SECONDS = __MAX_DASHBOARD_POLL_SECONDS__;

        const LS = {
          apiKey: 'acaScanner.apiKey',
          history: 'acaScanner.scanHistory.v1',
          legacyApiKey: 'apiKey',
        };

        const apiKeyEl = document.getElementById('apiKey');
        const urlEl = document.getElementById('url');
        const outEl = document.getElementById('out');
        const statusEl = document.getElementById('status');
        const startEl = document.getElementById('start');
        const historyBodyEl = document.getElementById('historyBody');
        const historyFilterEl = document.getElementById('historyFilter');
        const clearHistoryEl = document.getElementById('clearHistory');
        const checkCurrentEl = document.getElementById('checkCurrent');
        const copyJsonEl = document.getElementById('copyJson');
        const copyJson2El = document.getElementById('copyJson2');

        let history = [];
        let currentJobId = null;
        let isPolling = false;

        const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

        function readJson(key, fallback) {
          try {
            const raw = localStorage.getItem(key);
            if (!raw) return fallback;
            return JSON.parse(raw);
          } catch (_) {
            return fallback;
          }
        }

        function writeJson(key, value) {
          localStorage.setItem(key, JSON.stringify(value));
        }

        function loadHistory() {
          const items = readJson(LS.history, []);
          if (!Array.isArray(items)) return [];
          return items.filter(Boolean).slice(0, 50);
        }

        function saveHistory() {
          writeJson(LS.history, history.slice(0, 50));
        }

        function upsertHistory(entry) {
          const idx = history.findIndex(x => x && x.job_id === entry.job_id);
          if (idx >= 0) history[idx] = Object.assign({}, history[idx], entry);
          else history.unshift(entry);
          history = history.slice(0, 50);
          saveHistory();
          renderHistory();
        }

        function patchHistory(jobId, patch) {
          const idx = history.findIndex(x => x && x.job_id === jobId);
          if (idx < 0) return;
          history[idx] = Object.assign({}, history[idx], patch);
          saveHistory();
          renderHistory();
        }

        function clearHistory() {
          history = [];
          saveHistory();
          renderHistory();
        }

        function el(tag, attrs) {
          const node = document.createElement(tag);
          if (attrs) {
            for (const [k, v] of Object.entries(attrs)) {
              if (k === 'class') node.className = v;
              else if (k === 'text') node.textContent = v;
              else if (k === 'title') node.title = v;
              else if (k === 'href') node.href = v;
              else if (k === 'target') node.target = v;
              else if (k === 'rel') node.rel = v;
              else node.setAttribute(k, v);
            }
          }
          for (let i = 2; i < arguments.length; i++) {
            const child = arguments[i];
            if (child == null) continue;
            if (typeof child === 'string') node.appendChild(document.createTextNode(child));
            else node.appendChild(child);
          }
          return node;
        }

        function makeBadge(kind, label) {
          const cls = kind ? ('badge ' + kind) : 'badge';
          return el('span', { class: cls, text: label });
        }

        function setStatus(kind, text) {
          statusEl.textContent = '';
          if (!text) return;
          const label = kind === 'ok' ? 'OK' : (kind === 'bad' ? 'ERROR' : 'INFO');
          statusEl.appendChild(makeBadge(kind || 'info', label));
          statusEl.appendChild(document.createTextNode(' ' + text));
        }

        function setButtonsEnabled(hasJson) {
          copyJsonEl.disabled = !hasJson;
          copyJson2El.disabled = !hasJson;
          checkCurrentEl.disabled = !currentJobId;
        }

        function show(obj) {
          outEl.textContent = JSON.stringify(obj, null, 2);
          setButtonsEnabled(true);
        }

        async function copyText(text) {
          try {
            await navigator.clipboard.writeText(text);
            setStatus('ok', 'Copied to clipboard');
          } catch (_) {
            const ta = el('textarea', { style: 'position:fixed;left:-1000px;top:-1000px;' });
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
            setStatus('ok', 'Copied to clipboard');
          }
        }

        async function api(path, method, body) {
          const headers = { 'content-type': 'application/json' };
          const key = apiKeyEl.value.trim();
          if (key) headers[API_KEY_HEADER] = key;
          const res = await fetch(path, {
            method: method,
            headers: headers,
            body: body ? JSON.stringify(body) : undefined
          });
          const text = await res.text();
          let data;
          try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
          if (!res.ok) {
            const err = new Error('HTTP ' + res.status);
            err.status = res.status;
            err.data = data;
            throw err;
          }
          return data;
        }

        function formatWhen(iso) {
          if (!iso) return '';
          try { return dtf.format(new Date(iso)); } catch (_) { return iso; }
        }

        function statusKind(status) {
          if (status === 'completed') return 'ok';
          if (status === 'error') return 'bad';
          return 'info';
        }

        function verdictKind(verdict) {
          if (!verdict) return 'info';
          const v = String(verdict).toLowerCase();
          if (v === 'clean') return 'ok';
          if (v === 'malicious') return 'bad';
          return 'info';
        }

        function renderHistory() {
          const filter = (historyFilterEl.value || '').trim().toLowerCase();
          historyBodyEl.textContent = '';

          const items = history.filter(item => {
            if (!item) return false;
            if (!filter) return true;
            const hay = (String(item.url || '') + ' ' + String(item.job_id || '')).toLowerCase();
            return hay.indexOf(filter) >= 0;
          });

          if (items.length === 0) {
            const msg = filter ? 'No matching scans.' : 'No scans yet. Start one to see it here.';
            const td = el('td', { class: 'muted', text: msg });
            td.colSpan = 5;
            historyBodyEl.appendChild(el('tr', null, td));
            return;
          }

          for (const item of items) {
            const when = formatWhen(item.submitted_at || item.last_checked_at);
            const job = item.job_id || '';
            const shortJob = job ? (job.slice(0, 8) + '…') : '';
            const s = String(item.status || 'unknown');

            const whenTd = el('td', { class: 'nowrap', text: when });

            const urlLink = el('a', { href: item.url || '#', target: '_blank', rel: 'noreferrer', text: item.url || '' });
            const urlTd = el('td', { class: 'url-cell' }, urlLink);

            const jobCode = el('code', { text: shortJob, title: job });
            const jobTd = el('td', { class: 'nowrap' }, jobCode);

            const statusTd = el('td', { class: 'nowrap' });
            statusTd.appendChild(makeBadge(statusKind(s), s));
            if (item.verdict) {
              statusTd.appendChild(document.createTextNode(' '));
              statusTd.appendChild(makeBadge(verdictKind(item.verdict), String(item.verdict)));
            }

            const actionsTd = el('td', { class: 'nowrap' });
            const useBtn = el('button', { type: 'button', text: 'Use URL' });
            useBtn.addEventListener('click', () => {
              if (!item.url) return;
              urlEl.value = item.url;
              urlEl.focus();
              setStatus('info', 'Loaded URL from history');
            });

            const checkBtn = el('button', { type: 'button', text: 'Check' });
            checkBtn.addEventListener('click', () => refreshJob(job, true));

            const setCurrentBtn = el('button', { type: 'button', text: 'Set current' });
            setCurrentBtn.addEventListener('click', () => {
              currentJobId = job;
              setButtonsEnabled(true);
              setStatus('info', 'Current job set to ' + job);
            });

            actionsTd.appendChild(useBtn);
            actionsTd.appendChild(checkBtn);
            actionsTd.appendChild(setCurrentBtn);

            historyBodyEl.appendChild(el('tr', null, whenTd, urlTd, jobTd, statusTd, actionsTd));
          }
        }

        async function refreshJob(jobId, showOutput) {
          if (!jobId) return null;
          setStatus('info', 'Fetching status for ' + jobId + '...');
          try {
            const s = await api('/scan/' + jobId, 'GET');
            const now = new Date().toISOString();
            patchHistory(jobId, {
              status: s.status,
              verdict: s.verdict || null,
              error: s.error || null,
              submitted_at: s.submitted_at || undefined,
              scanned_at: s.scanned_at || null,
              last_checked_at: now
            });
            if (showOutput) show(s);
            setStatus(statusKind(s.status), 'Job ' + jobId + ' is ' + s.status);
            return s;
          } catch (e) {
            const msg = e && e.data ? JSON.stringify(e.data) : (e ? e.message : 'Unknown error');
            setStatus('bad', msg);
            if (showOutput) show({ error: msg });
            return null;
          }
        }

        function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

        async function pollJob(jobId) {
          const deadline = Date.now() + (MAX_POLL_SECONDS * 1000);
          while (Date.now() < deadline) {
            const s = await refreshJob(jobId, true);
            if (s && (s.status === 'completed' || s.status === 'error')) return s;
            await sleep(4000);
          }
          throw new Error('Timed out waiting for result');
        }

        async function startScan() {
          if (isPolling) return;
          const target = urlEl.value.trim();
          if (!target) {
            setStatus('bad', 'Enter a URL');
            return;
          }

          setStatus('info', 'Submitting scan...');
          show({});
          setButtonsEnabled(false);
          startEl.disabled = true;
          checkCurrentEl.disabled = true;

          try {
            const submit = await api('/scan', 'POST', { url: target, type: 'url' });
            show(submit);

            currentJobId = submit.job_id || null;
            setButtonsEnabled(true);

            if (currentJobId) {
              const now = new Date().toISOString();
              upsertHistory({
                job_id: currentJobId,
                url: target,
                status: submit.status || 'queued',
                verdict: null,
                error: null,
                submitted_at: now,
                scanned_at: null,
                last_checked_at: null
              });
            }

            if (!currentJobId) {
              setStatus('bad', 'No job_id returned');
              return;
            }

            isPolling = true;
            setStatus('info', 'Job queued; polling for results...');
            const result = await pollJob(currentJobId);
            if (result && result.status === 'completed') setStatus('ok', 'Completed');
            else setStatus('bad', 'Error');
          } catch (e) {
            const msg = e && e.data ? JSON.stringify(e.data) : (e ? e.message : 'Unknown error');
            setStatus('bad', msg);
            show({ error: msg });
          } finally {
            isPolling = false;
            startEl.disabled = false;
            setButtonsEnabled(true);
          }
        }

        function init() {
          const stored = localStorage.getItem(LS.apiKey) || localStorage.getItem(LS.legacyApiKey) || '';
          apiKeyEl.value = stored;
          if (stored && !localStorage.getItem(LS.apiKey)) localStorage.setItem(LS.apiKey, stored);

          apiKeyEl.addEventListener('input', () => localStorage.setItem(LS.apiKey, apiKeyEl.value));
          history = loadHistory();
          renderHistory();
          show({});
          setButtonsEnabled(false);
        }

        startEl.addEventListener('click', startScan);
        checkCurrentEl.addEventListener('click', () => refreshJob(currentJobId, true));
        clearHistoryEl.addEventListener('click', () => {
          clearHistory();
          setStatus('ok', 'History cleared');
        });
        historyFilterEl.addEventListener('input', renderHistory);
        copyJsonEl.addEventListener('click', () => copyText(outEl.textContent || ''));
        copyJson2El.addEventListener('click', () => copyText(outEl.textContent || ''));

        init();
      })();
    </script>
  </body>
</html>
"""

    api_key_header_html = html.escape(API_KEY_HEADER or "")
    api_key_header_json = json.dumps(API_KEY_HEADER or "X-API-Key")
    return (
        template.replace("__API_KEY_HEADER__", api_key_header_html)
        .replace("__API_KEY_HEADER_JSON__", api_key_header_json)
        .replace(
            "__MAX_DASHBOARD_POLL_SECONDS__", str(int(MAX_DASHBOARD_POLL_SECONDS or 0))
        )
    )


@app.post("/tasks")
async def enqueue_task(task: TaskIn, _: None = Security(require_api_key)):
    try:
        await _enqueue_json(task.payload, schema="task-v1", message_id=str(uuid4()))
        return {"status": "queued", "item": task.payload}
    except HTTPException:
        raise
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.post("/scan")
async def enqueue_scan(req: ScanRequest, _: None = Security(require_api_key)):
    if RESULT_BACKEND == "table" and not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    if RESULT_BACKEND == "redis" and not redis_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")

    _require_https(req.url)
    await _validate_public_destination(req.url)
    job_id = str(uuid4())
    correlation_id = str(uuid4())
    submitted_at = datetime.now(timezone.utc).isoformat()

    payload = {
        "job_id": job_id,
        "correlation_id": correlation_id,
        "url": req.url,
        "type": req.type,
        "source": req.source,
        "metadata": req.metadata or {},
        "submitted_at": submitted_at,
    }
    try:
        await _enqueue_json(
            payload,
            schema="scan-v1",
            message_id=job_id,
            application_properties={"correlation_id": correlation_id},
        )
        await _upsert_result(
            job_id,
            status="queued",
            details={"url": req.url, "type": req.type, "source": req.source},
            extra={"submitted_at": submitted_at},
        )
        return {"job_id": job_id, "status": "queued"}
    except HTTPException:
        raise
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.get("/scan/{job_id}")
async def get_scan_status(job_id: str, _: None = Security(require_api_key)):
    entity = await _get_result_entity(job_id)
    if not entity:
        return {"job_id": job_id, "status": "pending"}

    response = {
        "job_id": job_id,
        "status": entity.get("status", "unknown"),
        "verdict": entity.get("verdict") or None,
        "error": entity.get("error") or None,
        "submitted_at": entity.get("submitted_at"),
        "scanned_at": entity.get("scanned_at"),
        "details": None,
    }
    # details are stored as JSON string to fit Table constraints
    if entity.get("details"):
        try:
            response["details"] = json.loads(entity["details"])
        except Exception:
            response["details"] = {"raw": entity["details"]}
    return response
