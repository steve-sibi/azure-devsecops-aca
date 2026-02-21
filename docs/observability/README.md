# Observability Assets

This folder contains reusable day-2 operations assets.

## KQL query pack

Run these in Log Analytics:

- [`api_5xx.kql`](kql/api_5xx.kql) - API error-rate spikes
- [`pipeline_errors.kql`](kql/pipeline_errors.kql) - pipeline exceptions/failures
- [`queue_backlog.kql`](kql/queue_backlog.kql) - queue depth and stuck backlog
- [`deadletter_growth.kql`](kql/deadletter_growth.kql) - DLQ growth trend
- [`stalled_pipeline.kql`](kql/stalled_pipeline.kql) - stalled jobs (`queued`, `queued_scan`)
- [`correlation_flow.kql`](kql/correlation_flow.kql) - end-to-end log correlation by `job_id`/`correlation_id`
- [`scan_latency.kql`](kql/scan_latency.kql) - latency distribution and regression checks

## Runbook and tracing

- Incident runbook: [`runbook.md`](runbook.md)
- Logging/tracing guide: [`docs/azure-logging-guide.md`](../azure-logging-guide.md)

## Recommended usage flow

1. Identify symptom/alert (5xx, backlog, DLQ, latency, or stuck jobs).
2. Run the matching KQL query above.
3. Pivot to [`correlation_flow.kql`](kql/correlation_flow.kql) with `job_id` or `correlation_id`.
4. Use traces in Application Insights for deeper dependency timing.
