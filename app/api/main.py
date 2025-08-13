import asyncio
import json
import os

from azure.servicebus import ServiceBusMessage
from azure.servicebus.aio import ServiceBusClient
from fastapi import FastAPI

app = FastAPI(title="FastAPI on Azure Container Apps")

SERVICEBUS_CONN = os.environ["SERVICEBUS_CONN"]
QUEUE_NAME = os.environ.get("QUEUE_NAME", "tasks")

# Service Bus client (async)
sb_client = ServiceBusClient.from_connection_string(SERVICEBUS_CONN)


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.post("/tasks")
async def enqueue_task(payload: dict):
    async with sb_client:
        sender = sb_client.get_queue_sender(queue_name=QUEUE_NAME)
        async with sender:
            await sender.send_messages(ServiceBusMessage(json.dumps(payload)))
    return {"status": "queued", "item": payload}


# OpenTelemetry (optional: comment out until App Insights conn is set)
try:
    from opentelemetry import trace
    from opentelemetry.exporter.azure.monitor import AzureMonitorTraceExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    APPINSIGHTS_CONN = os.environ.get("APPINSIGHTS_CONN")
    if APPINSIGHTS_CONN:
        trace.set_tracer_provider(TracerProvider())
        exporter = AzureMonitorTraceExporter.from_connection_string(APPINSIGHTS_CONN)
        trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(exporter))
except Exception as e:
    # don't crash if not configured yet
    print("OTel init skipped:", e)
