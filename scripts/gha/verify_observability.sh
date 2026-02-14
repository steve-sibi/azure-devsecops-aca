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
APPI_NAME="${APPI_NAME:-${PREFIX}-appi}"
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

appi_app_id="$(az monitor app-insights component show \
  -g "${RG}" \
  -a "${APPI_NAME}" \
  --query appId -o tsv 2>/dev/null || true)"

if [[ -z "${appi_app_id}" ]]; then
  echo "[observability] App Insights appId not resolved (name=${APPI_NAME}); App Insights trace verification may be unavailable." >&2
fi

query_logs="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LOOKBACK_MINUTES}m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.request_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.run_id) in~ ('${JOB_ID}', '${RUN_ID}')
| summarize count()"

query_trace="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LOOKBACK_MINUTES}m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.request_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.run_id) in~ ('${JOB_ID}', '${RUN_ID}')
| where isnotempty(tostring(logData.trace_id))
| summarize count()"

query_appi_traces="traces
| where timestamp > ago(${LOOKBACK_MINUTES}m)
| extend job_id=tostring(customDimensions['app.job_id']),
         request_id=tostring(customDimensions['app.request_id']),
         run_id=tostring(customDimensions['app.run_id'])
| where job_id in~ ('${JOB_ID}', '${RUN_ID}')
   or request_id in~ ('${JOB_ID}', '${RUN_ID}')
   or run_id in~ ('${JOB_ID}', '${RUN_ID}')
| summarize count()"

query_presence="ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LOOKBACK_MINUTES}m)
| extend logData = parse_json(Log_s)
| where tostring(logData.job_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.request_id) in~ ('${JOB_ID}', '${RUN_ID}')
   or tostring(logData.run_id) in~ ('${JOB_ID}', '${RUN_ID}')
| take 1"

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
appi_trace_count=0

run_la_count_query() {
  local query="$1"
  local out
  local err_file
  err_file="$(mktemp)"
  if ! out="$(az monitor log-analytics query \
    --workspace "${workspace_id}" \
    --analytics-query "${query}" \
    -o json 2>"${err_file}")"; then
    local err_text
    err_text="$(cat "${err_file}" 2>/dev/null || true)"
    rm -f "${err_file}"
    echo "[observability] Query execution failed: ${err_text}" >&2
    echo "0"
    return 1
  fi
  rm -f "${err_file}"
  python3 -c 'import json,sys
raw=sys.stdin.read().strip()
if not raw:
    print(0); raise SystemExit(0)
try:
    data=json.loads(raw)
except Exception:
    print(0); raise SystemExit(0)
tables=data.get("tables") if isinstance(data,dict) else None
if not isinstance(tables,list) or not tables:
    print(0); raise SystemExit(0)
rows=tables[0].get("rows") if isinstance(tables[0],dict) else None
if not isinstance(rows,list) or not rows:
    print(0); raise SystemExit(0)
first=rows[0][0] if isinstance(rows[0],list) and rows[0] else 0
try:
    print(int(first))
except Exception:
    print(0)
' <<<"${out}"
}

run_appi_count_query() {
  local query="$1"
  local out
  local err_file
  if [[ -z "${appi_app_id}" ]]; then
    echo "0"
    return 0
  fi
  err_file="$(mktemp)"
  if ! out="$(az monitor app-insights query \
    --app "${appi_app_id}" \
    --analytics-query "${query}" \
    -o json 2>"${err_file}")"; then
    local err_text
    err_text="$(cat "${err_file}" 2>/dev/null || true)"
    rm -f "${err_file}"
    echo "[observability] App Insights query failed: ${err_text}" >&2
    echo "0"
    return 1
  fi
  rm -f "${err_file}"
  python3 -c 'import json,sys
raw=sys.stdin.read().strip()
if not raw:
    print(0); raise SystemExit(0)
try:
    data=json.loads(raw)
except Exception:
    print(0); raise SystemExit(0)
tables=data.get("tables") if isinstance(data,dict) else None
if not isinstance(tables,list) or not tables:
    print(0); raise SystemExit(0)
rows=tables[0].get("rows") if isinstance(tables[0],dict) else None
if not isinstance(rows,list) or not rows:
    print(0); raise SystemExit(0)
first=rows[0][0] if isinstance(rows[0],list) and rows[0] else 0
try:
    print(int(first))
except Exception:
    print(0)
' <<<"${out}"
}

run_presence_query() {
  local query="$1"
  local out
  local err_file
  err_file="$(mktemp)"
  if ! out="$(az monitor log-analytics query \
    --workspace "${workspace_id}" \
    --analytics-query "${query}" \
    -o json 2>"${err_file}")"; then
    local err_text
    err_text="$(cat "${err_file}" 2>/dev/null || true)"
    rm -f "${err_file}"
    echo "[observability] Presence query failed: ${err_text}" >&2
    echo "0"
    return 1
  fi
  rm -f "${err_file}"
  python3 -c 'import json,sys
raw=sys.stdin.read().strip()
if not raw:
    print(0); raise SystemExit(0)
try:
    data=json.loads(raw)
except Exception:
    print(0); raise SystemExit(0)
tables=data.get("tables") if isinstance(data,dict) else None
if not isinstance(tables,list) or not tables:
    print(0); raise SystemExit(0)
rows=tables[0].get("rows") if isinstance(tables[0],dict) else None
print(len(rows) if isinstance(rows,list) else 0)
' <<<"${out}"
}

for ((attempt=1; attempt<=MAX_ATTEMPTS; attempt++)); do
  log_count="$(run_la_count_query "${query_logs}" || true)"
  trace_count="$(run_la_count_query "${query_trace}" || true)"
  appi_trace_count="$(run_appi_count_query "${query_appi_traces}" || true)"

  echo "[observability] attempt=${attempt}/${MAX_ATTEMPTS} job_id=${JOB_ID} run_id=${RUN_ID} log_count=${log_count} log_trace_count=${trace_count} appi_trace_count=${appi_trace_count}"

  if [[ "${log_count}" -gt 0 ]]; then
    if ! is_truthy "${REQUIRE_TRACE}"; then
      break
    fi
    if [[ -n "${appi_app_id}" && "${appi_trace_count}" -gt 0 ]]; then
      break
    fi
  fi

  if [[ "${attempt}" -lt "${MAX_ATTEMPTS}" ]]; then
    sleep "${SLEEP_SECONDS}"
  fi
done

# One final immediate check to reduce race conditions around ingestion timing.
if [[ "${log_count}" -eq 0 ]]; then
  log_count="$(run_la_count_query "${query_logs}" || true)"
  trace_count="$(run_la_count_query "${query_trace}" || true)"
  appi_trace_count="$(run_appi_count_query "${query_appi_traces}" || true)"
  echo "[observability] final-check job_id=${JOB_ID} run_id=${RUN_ID} log_count=${log_count} log_trace_count=${trace_count} appi_trace_count=${appi_trace_count}"
fi

if [[ "${log_count}" -eq 0 ]]; then
  presence_count="$(run_presence_query "${query_presence}" || true)"
  if [[ "${presence_count}" -gt 0 ]]; then
    log_count="${presence_count}"
    echo "[observability] Count query returned 0 but presence query found matching rows; continuing." >&2
  fi
fi

sample_table=""
sample_row_count=0

# Final fallback: if aggregate/presence checks still say 0, inspect table output directly.
# This avoids false negatives when the extension returns null rows for JSON but renders table rows.
if [[ "${log_count}" -eq 0 ]]; then
  sample_table="$(az monitor log-analytics query \
    --workspace "${workspace_id}" \
    --analytics-query "${query_sample}" \
    -o table 2>/dev/null || true)"
  sample_row_count="$(grep -cE '^[[:space:]]*PrimaryResult[[:space:]]' <<<"${sample_table}" || true)"
  [[ "${sample_row_count}" =~ ^[0-9]+$ ]] || sample_row_count=0
  if [[ "${sample_row_count}" -gt 0 ]]; then
    log_count="${sample_row_count}"
    echo "[observability] Aggregate query returned 0 but table output contains matching rows; continuing." >&2
  fi
fi

if [[ "${log_count}" -eq 0 ]]; then
  echo "[observability] No matching Log Analytics entries found for E2E IDs (job_id=${JOB_ID}, run_id=${RUN_ID})." >&2
  echo "[observability] Sample query output (if any):" >&2
  if [[ -n "${sample_table}" ]]; then
    echo "${sample_table}"
  else
    az monitor log-analytics query \
      --workspace "${workspace_id}" \
      --analytics-query "${query_sample}" \
      -o table || true
  fi
  exit 1
fi

if [[ "${trace_count}" -eq 0 ]]; then
  echo "[observability] Logs found but no trace_id in container logs yet (sampling or delayed export)." >&2
fi

if [[ -z "${appi_app_id}" ]]; then
  if is_truthy "${REQUIRE_TRACE}"; then
    echo "[observability] Strict trace verification enabled but App Insights appId could not be resolved." >&2
    exit 1
  fi
  echo "[observability] App Insights appId unavailable; skipping App Insights trace count check." >&2
elif [[ "${appi_trace_count}" -eq 0 ]]; then
  if is_truthy "${REQUIRE_TRACE}"; then
    echo "[observability] Logs found but no matching App Insights traces for E2E IDs (job_id=${JOB_ID}, run_id=${RUN_ID})." >&2
    exit 1
  fi
  echo "[observability] Logs found but no matching App Insights traces yet (sampling or delayed export). Continuing." >&2
fi

echo "[observability] Verification passed."
