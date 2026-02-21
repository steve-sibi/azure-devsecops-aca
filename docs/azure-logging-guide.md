# Azure Structured Logging and Tracing Guide

## Overview

This project emits structured JSON logs for all services (`api`, `fetcher`, `worker`) and exports OpenTelemetry traces to workspace-based Application Insights (Azure) or any OTLP endpoint (local/dev).

- Logs: stdout/stderr -> Azure Container Apps -> Log Analytics
- Traces:
  - Azure: OpenTelemetry -> Azure Monitor exporter -> Application Insights
  - Local/dev: OpenTelemetry -> OTLP HTTP exporter -> Jaeger (or another OTLP backend)
- Correlation: `correlation_id` (app-level) + `trace_id`/`span_id` (trace-level)

## Log Format

Example event:

```json
{
  "timestamp": "2026-02-11T20:41:41.862665+00:00",
  "level": "INFO",
  "service": "fetcher",
  "logger": "worker.fetcher",
  "message": "Fetcher queued scan artifact",
  "correlation_id": "req-123",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "job_id": "job-001",
  "duration_ms": 1432,
  "size_bytes": 2048
}
```

### Standard Fields

- `timestamp`: ISO 8601 UTC timestamp.
- `level`: log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- `service`: service identifier (`api`, `fetcher`, `worker`).
- `logger`: Python logger name.
- `message`: human-readable event text.
- `correlation_id`: request/job correlation identifier.
- `trace_id`: OpenTelemetry trace ID when a span is active.
- `span_id`: OpenTelemetry span ID when a span is active.

### Context Fields

Depending on operation, events can include:

- `job_id`, `run_id`, `url`, `scan_type`, `status`
- `duration_ms`, `size_bytes`
- `error`, `error_type`
- `http_method`, `http_route`, `http_status_code`

## Correlation and Trace Propagation

### Correlation ID

- API middleware captures `X-Correlation-ID` / `X-Request-ID` (or creates UUID).
- ID is injected into logs via `contextvars`.
- Fetcher/worker read `correlation_id` from queue payload and set per-message context.

### Trace Context

- API injects W3C trace context into scan messages (`traceparent`, `tracestate`).
- Fetcher extracts incoming trace context and forwards refreshed context to scan queue.
- Worker extracts trace context and creates child spans for read/analyze/persist work.
- Spans also carry explicit identifiers for search:
  - `app.request_id`: per-request id returned as API `job_id`
  - `app.run_id`: execution id returned as API `run_id`
  - `app.job_id`: compatibility alias of `app.run_id`

## OpenTelemetry Configuration

Implemented in [`app/common/telemetry.py`](../app/common/telemetry.py).

Runtime environment variables:

- `OTEL_ENABLED`:
  - unset: auto-enable when App Insights connection string exists
  - `true`/`false`: force behavior
- `OTEL_TRACES_SAMPLER_RATIO` (default `0.10`)
- `OTEL_SERVICE_NAMESPACE` (default `aca-urlscanner`)
- `APPINSIGHTS_CONN` or `APPLICATIONINSIGHTS_CONNECTION_STRING`
- `OTEL_EXPORTER_OTLP_ENDPOINT` (base endpoint, e.g. `http://jaeger:4318`)
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (optional explicit traces endpoint override)
- `OTEL_EXPORTER_OTLP_HEADERS` (optional comma-separated `k=v` headers)

## Azure Integration

### Log Analytics

Container logs are queryable in `ContainerAppConsoleLogs_CL`.

Use the query pack in [`docs/observability/kql/`](observability/kql/):

- [`api_5xx.kql`](observability/kql/api_5xx.kql)
- [`pipeline_errors.kql`](observability/kql/pipeline_errors.kql)
- [`queue_backlog.kql`](observability/kql/queue_backlog.kql)
- [`deadletter_growth.kql`](observability/kql/deadletter_growth.kql)
- [`stalled_pipeline.kql`](observability/kql/stalled_pipeline.kql)
- [`correlation_flow.kql`](observability/kql/correlation_flow.kql)
- [`scan_latency.kql`](observability/kql/scan_latency.kql)

### Application Insights

OpenTelemetry spans are exported through Azure Monitor exporter.

Typical troubleshooting flow:

1. Find `correlation_id`/`trace_id` in Log Analytics.
2. Pivot to Application Insights traces for latency and dependency timing.

## Local Development

### Viewing Logs

```bash
# All services
docker compose logs -f

# Filter by correlation ID
docker compose logs -f api | grep "my-correlation-id"

# Pretty-print JSON from worker
docker logs azure-devsecops-aca-worker-1 2>&1 | tail -20 | jq .
```

### Testing Correlation and Trace Context

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: local-dev-key" \
  -H "X-Correlation-ID: my-custom-trace-id" \
  -d '{"url": "https://example.com", "type": "url"}'
```

Then inspect logs in `api`, `fetcher`, and `worker` for the same `correlation_id`.

### Local sampler-ratio validation (without Azure)

```bash
OTEL_ENABLED=true OTEL_TRACES_SAMPLER_RATIO=0.10 \
  docker compose --profile observability up --build -d
```

Jaeger endpoints:
- UI/API: `http://localhost:16686`
- OTLP HTTP ingest: `http://localhost:4318/v1/traces`
- OTLP gRPC ingest: `localhost:4317`

Run validation against Jaeger:

```bash
python3 scripts/local/verify_trace_sampling.py \
  --api-url http://localhost:8000 \
  --api-key local-dev-key \
  --jaeger-url http://localhost:16686 \
  --expected-ratio 0.10 \
  --requests 80
```

If this returns `PASS`, observed sampled traces are within tolerance for the configured ratio.

## Implementation Map

- Logging format/config: [`app/common/logging_config.py`](../app/common/logging_config.py)
- Telemetry setup and trace helpers: [`app/common/telemetry.py`](../app/common/telemetry.py)
- API request + queue propagation: [`app/api/main.py`](../app/api/main.py)
- Fetcher propagation + forwarding: [`app/worker/fetcher.py`](../app/worker/fetcher.py)
- Worker trace extraction and child spans: [`app/worker/worker.py`](../app/worker/worker.py)

## Operations References

- Query pack: [`docs/observability/kql/`](observability/kql/)
- Incident guide: [`docs/observability/runbook.md`](observability/runbook.md)
- Terraform monitoring resources: [`infra/monitoring.tf`](../infra/monitoring.tf)
