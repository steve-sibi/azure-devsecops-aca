# app/api/main.py
import json
import os
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Any, Optional
from uuid import uuid4
from urllib.parse import urlsplit

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError
from azure.data.tables.aio import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError
from fastapi import FastAPI, HTTPException
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

# Globals set during app startup
sb_client: Optional[ServiceBusClient] = None
sb_sender: Optional[ServiceBusSender] = None
table_service: Optional[TableServiceClient] = None
table_client = None


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


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/tasks")
async def enqueue_task(task: TaskIn):
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
async def enqueue_scan(req: ScanRequest):
    if not sb_sender or not table_client:
        raise HTTPException(status_code=503, detail="Service dependencies not ready")

    _require_https(req.url)
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
async def get_scan_status(job_id: str):
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
