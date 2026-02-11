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
RUN_ID="${E2E_RUN_ID:-}"
LOOKBACK_MINUTES="${OBS_VERIFY_LOOKBACK_MINUTES:-120}"
MAX_ATTEMPTS="${OBS_VERIFY_ATTEMPTS:-6}"
SLEEP_SECONDS="${OBS_VERIFY_SLEEP_SECONDS:-20}"
REQUIRE_TRACE="${OBS_VERIFY_REQUIRE_TRACE:-false}"

is_truthy() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -z "${JOB_ID}" ]]; then
  echo "[observability] E2E_JOB_ID is empty; skipping observability verification."
  exit 0
fi

if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="${JOB_ID}"
fi

workspace_id="$(az monitor log-analytics workspace show \
  -g "${RG}" \
  -n "${LA_NAME}" \
  --query customerId -o tsv)"

if [[ -z "${workspace_id}" ]]; then
  echo "[observability] Failed to resolve Log Analytics workspace customerId." >&2
  exit 1
fi

query_counts="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LOOKBACK_MINUTES}m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.request_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.run_id) in~ ('${JOB_ID}', '${RUN_ID}')
| summarize log_count=count(), trace_count=countif(isnotempty(tostring(logData.trace_id)))"

query_sample="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LOOKBACK_MINUTES}m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.request_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.run_id) in~ ('${JOB_ID}', '${RUN_ID}')
| project TimeGenerated, service=tostring(logData.service), message=tostring(logData.message), job_id=tostring(logData.job_id), request_id=tostring(logData.request_id), run_id=tostring(logData.run_id), trace_id=tostring(logData.trace_id)
| order by TimeGenerated desc
| take 10"

log_count=0
trace_count=0

for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
  row="$(az monitor log-analytics query \
    --workspace "${workspace_id}" \
    --analytics-query "${query_counts}" \
    --query "tables[0].rows[0]" \
    -o tsv)"

  log_count="$(awk '{print $1}' <<<"${row:-0}")"
  trace_count="$(awk '{print $2}' <<<"${row:-0 0}")"
  [[ -z "${log_count}" ]] && log_count=0
  [[ -z "${trace_count}" ]] && trace_count=0

  echo "[observability] attempt=${attempt}/${MAX_ATTEMPTS} job_id=${JOB_ID} run_id=${RUN_ID} log_count=${log_count} trace_count=${trace_count}"

  if [[ "${log_count}" -gt 0 ]]; then
    break
  fi

  if [[ "${attempt}" -lt "${MAX_ATTEMPTS}" ]]; then
    sleep "${SLEEP_SECONDS}"
  fi
done

if [[ "${log_count}" -eq 0 ]]; then
  echo "[observability] No matching Log Analytics entries found for E2E IDs (job_id=${JOB_ID}, run_id=${RUN_ID})." >&2
  echo "[observability] Sample query output (if any):" >&2
  az monitor log-analytics query \
    --workspace "${workspace_id}" \
    --analytics-query "${query_sample}" \
    -o table || true
  exit 1
fi

if [[ "${trace_count}" -eq 0 ]]; then
  if is_truthy "${REQUIRE_TRACE}"; then
    echo "[observability] Logs found but no trace_id for E2E IDs (job_id=${JOB_ID}, run_id=${RUN_ID})." >&2
    exit 1
  fi
  echo "[observability] Logs found but no trace_id yet (sampling or delayed export). Continuing." >&2
fi

echo "[observability] Verification passed."
