# app/api/main.py
import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import Optional
from uuid import uuid4

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# ---------- Settings ----------
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")  # connection string (current)
SERVICEBUS_FQDN = os.getenv(
    "SERVICEBUS_FQDN"
)  # e.g. "mynamespace.servicebus.windows.net"
USE_MI = os.getenv("USE_MANAGED_IDENTITY", "false").lower() in ("1", "true", "yes")

# Globals set during app startup
sb_client: Optional[ServiceBusClient] = None
sb_sender: Optional[ServiceBusSender] = None


class TaskIn(BaseModel):
    # adjust fields to your real payload
    payload: dict


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sb_client, sb_sender

    # --- Build Service Bus client ---
    if USE_MI:
        # Optional MI path (requires azure-identity if you enable it)
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

    # Enter client and sender once for app lifetime
    await sb_client.__aenter__()
    sb_sender = sb_client.get_queue_sender(queue_name=QUEUE_NAME)
    await sb_sender.__aenter__()

    # --- Optional OpenTelemetry tracing (only if packages + conn are present) ---
    APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")
    if APPINSIGHTS_CONN:
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.azure.monitor import AzureMonitorTraceExporter
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
            # Safe: telemetry is optional
            print("OTel init skipped:", e)

    yield  # ---- App runs ----

    # ---- Cleanup on shutdown ----
    if sb_sender:
        await sb_sender.__aexit__(None, None, None)
    if sb_client:
        await sb_client.__aexit__(None, None, None)

    # Close MI credential if used
    if USE_MI:
        try:
            await cred.__aexit__(None, None, None)  # type: ignore[name-defined]
        except Exception:
            pass


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
        # Surface a safe error; logs will have the details
        raise HTTPException(
            status_code=502, detail=f"Queue send failed: {e.__class__.__name__}"
        )
