# Observability Assets

This folder contains reusable day-2 operations assets for both Azure and local development.

## Azure (KQL query pack)

Run these in Log Analytics:

- [`api_5xx.kql`](kql/api_5xx.kql) - API error-rate spikes
- [`pipeline_errors.kql`](kql/pipeline_errors.kql) - pipeline exceptions/failures
- [`queue_backlog.kql`](kql/queue_backlog.kql) - queue depth and stuck backlog
- [`deadletter_growth.kql`](kql/deadletter_growth.kql) - DLQ growth trend
- [`stalled_pipeline.kql`](kql/stalled_pipeline.kql) - stalled jobs (`queued`, `queued_scan`)
- [`correlation_flow.kql`](kql/correlation_flow.kql) - end-to-end log correlation by `job_id`/`correlation_id`
- [`scan_latency.kql`](kql/scan_latency.kql) - latency distribution and regression checks

## Local development (Jaeger)

Jaeger is included as an optional Docker Compose profile for local trace inspection.

### Quick start

```bash
OTEL_ENABLED=true docker compose --profile observability up --build -d
```

> `OTEL_ENABLED` defaults to `false` in Docker Compose. You **must** set it to `true` (or export it in `.env`) for traces to appear in Jaeger.

### Endpoints

| Endpoint | URL |
|----------|-----|
| Jaeger UI | `http://localhost:16686` |
| OTLP HTTP ingest | `http://localhost:4318/v1/traces` |
| OTLP gRPC ingest | `localhost:4317` |

### What to look for

- Service names: `api`, `fetcher`, `worker` (under namespace `aca-urlscanner`)
- Search by `correlation_id` tag to trace a request end-to-end
- Verify sampler ratio with the validation script:

```bash
python3 scripts/local/verify_trace_sampling.py \
  --api-url http://localhost:8000 \
  --api-key local-dev-key \
  --jaeger-url http://localhost:16686 \
  --expected-ratio 0.10 \
  --requests 80
```

## Runbook and tracing guide

- Incident runbook: [`runbook.md`](runbook.md)
- Logging/tracing guide: [`docs/structured-logging-and-tracing.md`](../structured-logging-and-tracing.md)

## Recommended usage flow

### Azure

1. Identify symptom/alert (5xx, backlog, DLQ, latency, or stuck jobs).
2. Run the matching KQL query above.
3. Pivot to [`correlation_flow.kql`](kql/correlation_flow.kql) with `job_id` or `correlation_id`.
4. Use traces in Application Insights for deeper dependency timing.

### Local (Jaeger)

1. Open Jaeger UI at `http://localhost:16686`.
2. Select the service (`api`, `fetcher`, or `worker`).
3. Search traces by `correlation_id` or `job_id` tag.
4. Inspect span timings and propagation across services.
