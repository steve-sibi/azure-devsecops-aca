# Observability Runbook

This runbook covers the most common production triage paths for this project.

## Prerequisites

- Azure Log Analytics workspace connected to the ACA environment.
- Workspace-based Application Insights.
- Terraform monitoring resources applied (`infra/monitoring.tf`).

## 1) High API 5xx Rate

Symptoms:
- Alert: `${prefix}-api-5xx-alert`
- Dashboard/API requests failing.

Steps:
1. Run `docs/observability/kql/api_5xx.kql` in Log Analytics.
2. Group by `http_route` and `correlation_id`.
3. Pivot to full flow with `docs/observability/kql/correlation_flow.kql`.
4. Check latest API revision and recent app rollout logs.

Likely causes:
- Dependency errors (Service Bus, Table Storage, Blob).
- App regressions in request validation or enqueue path.

## 2) Stuck Jobs (`queued` / `queued_scan`)

Symptoms:
- Jobs remain non-terminal for long periods.
- Alert: `${prefix}-stalled-pipeline-alert`.

Steps:
1. Run `docs/observability/kql/queue_backlog.kql`.
2. Run `docs/observability/kql/pipeline_errors.kql`.
3. Check `fetcher` and `worker` logs for the same `job_id` / `correlation_id`.
4. Check Service Bus active/dead-letter counts.

Likely causes:
- Fetcher/worker revision startup failure.
- Service Bus auth/connection secret mismatch.
- Message repeatedly retrying and later dead-lettering.

## 3) Dead-Letter Growth

Symptoms:
- Alert: `${prefix}-deadletter-alert`.
- Increasing dead-letter message count.

Steps:
1. Run `docs/observability/kql/deadletter_growth.kql`.
2. Inspect `DLQ'd message` events in `worker`/`fetcher` logs.
3. Identify top `error_code` and `job_id` values.
4. Confirm if issue is transient (retryable) or terminal input (blocked).

Likely causes:
- Repeated transient downstream failures.
- Invalid payloads or permanently blocked URLs.

## 4) Latency Regression

Symptoms:
- Increased end-to-end duration (`duration_ms`) for `completed` scans.

Steps:
1. Run `docs/observability/kql/scan_latency.kql`.
2. Compare P50/P95 over recent windows.
3. Correlate with queue depth from `queue_backlog.kql`.
4. Inspect App Insights traces by `trace_id` for slow segments.

Likely causes:
- Queue contention/scale lag.
- Slow external URL fetches.
- Worker resource pressure.

## 5) Correlation/Trace Walkthrough

Given a `job_id` or `correlation_id`:
1. Run `correlation_flow.kql`.
2. Copy `trace_id` from log row.
3. Query App Insights traces by `operation_Id`/trace context.
4. Validate route from API to fetcher to worker.

## Notes

- Logs are emitted as structured JSON with `service`, `correlation_id`, `trace_id`, and `span_id`.
- App Insights is used for traces; Log Analytics remains the primary operations view.
- Deployment workflow trace enforcement can be made strict by setting repo variable `ACA_OBS_VERIFY_REQUIRE_TRACE=true`.
