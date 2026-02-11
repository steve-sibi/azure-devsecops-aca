#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env var: ${name}" >&2
    exit 2
  fi
}

require_env RG
require_env PREFIX

LA_NAME="${LA_NAME:-${PREFIX}-la}"
JOB_ID="${E2E_JOB_ID:-}"

if [[ -z "${JOB_ID}" ]]; then
  echo "[observability] E2E_JOB_ID is empty; skipping observability verification."
  exit 0
fi

workspace_id="$(az monitor log-analytics workspace show \
  -g "${RG}" \
  -n "${LA_NAME}" \
  --query customerId -o tsv)"

if [[ -z "${workspace_id}" ]]; then
  echo "[observability] Failed to resolve Log Analytics workspace customerId." >&2
  exit 1
fi

query_logs="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(30m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) == '${JOB_ID}'
| summarize count()"

query_trace="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(30m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) == '${JOB_ID}'
| where isnotempty(tostring(logData.trace_id))
| summarize count()"

log_count="$(az monitor log-analytics query \
  --workspace "${workspace_id}" \
  --analytics-query "${query_logs}" \
  --query "tables[0].rows[0][0]" \
  -o tsv 2>/dev/null || echo "0")"

trace_count="$(az monitor log-analytics query \
  --workspace "${workspace_id}" \
  --analytics-query "${query_trace}" \
  --query "tables[0].rows[0][0]" \
  -o tsv 2>/dev/null || echo "0")"

echo "[observability] job_id=${JOB_ID} log_count=${log_count:-0} trace_count=${trace_count:-0}"

if [[ "${log_count:-0}" -eq 0 ]]; then
  echo "[observability] No Log Analytics entries found for E2E job_id=${JOB_ID}." >&2
  exit 1
fi

if [[ "${trace_count:-0}" -eq 0 ]]; then
  echo "[observability] Logs found but no trace_id yet for E2E job_id=${JOB_ID}." >&2
  exit 1
fi

echo "[observability] Verification passed."
