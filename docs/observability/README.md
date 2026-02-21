# Observability Assets

This folder contains reusable day-2 operations assets.

## KQL query pack

Run these in Log Analytics:

- `docs/observability/kql/api_5xx.kql` - API error-rate spikes
- `docs/observability/kql/pipeline_errors.kql` - pipeline exceptions/failures
- `docs/observability/kql/queue_backlog.kql` - queue depth and stuck backlog
- `docs/observability/kql/deadletter_growth.kql` - DLQ growth trend
- `docs/observability/kql/stalled_pipeline.kql` - stalled jobs (`queued`, `queued_scan`)
- `docs/observability/kql/correlation_flow.kql` - end-to-end log correlation by `job_id`/`correlation_id`
- `docs/observability/kql/scan_latency.kql` - latency distribution and regression checks

## Runbook and tracing

- Incident runbook: `docs/observability/runbook.md`
- Logging/tracing guide: `docs/azure-logging-guide.md`

## Recommended usage flow

1. Identify symptom/alert (5xx, backlog, DLQ, latency, or stuck jobs).
2. Run the matching KQL query above.
3. Pivot to `correlation_flow.kql` with `job_id` or `correlation_id`.
4. Use traces in Application Insights for deeper dependency timing.
