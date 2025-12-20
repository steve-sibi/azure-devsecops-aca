from contextlib import asynccontextmanager
from collections import deque
from datetime import datetime, timezone
import asyncio
import hashlib
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
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")  # connection string (current)
SERVICEBUS_FQDN = os.getenv(
    "SERVICEBUS_FQDN"
)  # e.g. "mynamespace.servicebus.windows.net"
USE_MI = os.getenv("USE_MANAGED_IDENTITY", "false").lower() in ("1", "true", "yes")
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sb_client, sb_sender, table_service, table_client

    cred = None  # will hold DefaultAzureCredential if MI is used

    # --- Build Service Bus client ---
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

    if not RESULT_STORE_CONN:
        raise RuntimeError("RESULT_STORE_CONN environment variable is required")
    table_service = TableServiceClient.from_connection_string(conn_str=RESULT_STORE_CONN)
    table_client = table_service.get_table_client(table_name=RESULT_TABLE)

    # Enter client and sender once for app lifetime
    await sb_client.__aenter__()
    sb_sender = sb_client.get_queue_sender(queue_name=QUEUE_NAME)
    await sb_sender.__aenter__()
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
    if cred:
        # Properly close the async credential if used
        await cred.close()


app = FastAPI(title="FastAPI on Azure Container Apps", lifespan=lifespan)


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
    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>DevSecOps ACA Scanner</title>
    <style>
      body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; max-width: 980px; }}
      .row {{ display: flex; gap: 1rem; flex-wrap: wrap; align-items: end; }}
      label {{ display: block; font-size: 0.9rem; color: #444; margin-bottom: 0.25rem; }}
      input {{ padding: 0.6rem; width: min(480px, 100%); }}
      button {{ padding: 0.65rem 0.9rem; cursor: pointer; }}
      pre {{ background: #0b1020; color: #d6e0ff; padding: 1rem; border-radius: 8px; overflow: auto; }}
      .hint {{ color: #666; font-size: 0.9rem; }}
      .ok {{ color: #0a7a0a; }}
      .bad {{ color: #b00020; }}
    </style>
  </head>
  <body>
    <h1>DevSecOps ACA Scanner</h1>
    <p class="hint">Use <code>/docs</code> for Swagger. API key required for scan endpoints.</p>
    <div class="row">
      <div>
        <label>API Key (header: {API_KEY_HEADER})</label>
        <input id="apiKey" placeholder="paste API key" />
      </div>
      <div>
        <label>HTTPS URL to scan</label>
        <input id="url" value="https://example.com" />
      </div>
      <div>
        <button id="start">Start scan</button>
      </div>
    </div>
    <p id="status" class="hint"></p>
    <pre id="out">{{}}</pre>
    <script>
      const apiKeyEl = document.getElementById('apiKey');
      const urlEl = document.getElementById('url');
      const outEl = document.getElementById('out');
      const statusEl = document.getElementById('status');
      const startEl = document.getElementById('start');

      apiKeyEl.value = localStorage.getItem('apiKey') || '';
      apiKeyEl.addEventListener('change', () => localStorage.setItem('apiKey', apiKeyEl.value));

      function show(obj) {{
        outEl.textContent = JSON.stringify(obj, null, 2);
      }}

      async function api(path, method, body) {{
        const headers = {{'content-type': 'application/json'}};
        const key = apiKeyEl.value.trim();
        if (key) headers['{API_KEY_HEADER}'] = key;
        const res = await fetch(path, {{
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined
        }});
        const text = await res.text();
        let data;
        try {{ data = JSON.parse(text); }} catch {{ data = {{ raw: text }}; }}
        if (!res.ok) {{
          throw Object.assign(new Error('HTTP ' + res.status), {{ status: res.status, data }});
        }}
        return data;
      }}

      async function sleep(ms) {{ return new Promise(r => setTimeout(r, ms)); }}

      startEl.addEventListener('click', async () => {{
        statusEl.textContent = '';
        show({{}});
        const target = urlEl.value.trim();
        if (!target) {{ statusEl.textContent = 'Enter a URL'; return; }}
        try {{
          statusEl.textContent = 'Submitting scan...';
          const submit = await api('/scan', 'POST', {{ url: target, type: 'url' }});
          show(submit);
          const jobId = submit.job_id;
          if (!jobId) return;
          statusEl.textContent = 'Job ' + jobId + ' queued; polling...';

          const deadline = Date.now() + ({MAX_DASHBOARD_POLL_SECONDS} * 1000);
          while (Date.now() < deadline) {{
            const s = await api('/scan/' + jobId, 'GET');
            show(s);
            if (s.status === 'completed') {{
              statusEl.innerHTML = '<span class="ok">Completed</span>';
              return;
            }}
            if (s.status === 'error') {{
              statusEl.innerHTML = '<span class="bad">Error</span>';
              return;
            }}
            await sleep(4000);
          }}
          statusEl.innerHTML = '<span class="bad">Timed out waiting for result</span>';
        }} catch (e) {{
          statusEl.innerHTML = '<span class="bad">' + (e.data ? JSON.stringify(e.data) : e.message) + '</span>';
        }}
      }});
    </script>
  </body>
</html>
"""


@app.post("/tasks")
async def enqueue_task(task: TaskIn, _: None = Security(require_api_key)):
    if not sb_sender:
        raise HTTPException(status_code=503, detail="Service Bus not initialized")
    try:
        msg = ServiceBusMessage(
            json.dumps(task.payload),
            content_type="application/json",
            message_id=str(uuid4()),
            application_properties={"schema": "task-v1"},
        )
        await sb_sender.send_messages(msg)
        return {"status": "queued", "item": task.payload}
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.post("/scan")
async def enqueue_scan(req: ScanRequest, _: None = Security(require_api_key)):
    if not sb_sender or not table_client:
        raise HTTPException(status_code=503, detail="Service dependencies not ready")

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
        msg = ServiceBusMessage(
            json.dumps(payload),
            content_type="application/json",
            message_id=job_id,
            application_properties={"schema": "scan-v1", "correlation_id": correlation_id},
        )
        await sb_sender.send_messages(msg)
        await _upsert_result(
            job_id,
            status="queued",
            details={"url": req.url, "type": req.type, "source": req.source},
            extra={"submitted_at": submitted_at},
        )
        return {"job_id": job_id, "status": "queued"}
    except ServiceBusError as e:
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )


@app.get("/scan/{job_id}")
async def get_scan_status(job_id: str, _: None = Security(require_api_key)):
    if not table_client:
        raise HTTPException(status_code=503, detail="Result store not initialized")
    try:
        entity = await table_client.get_entity(
            partition_key=RESULT_PARTITION, row_key=job_id
        )
    except ResourceNotFoundError:
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
