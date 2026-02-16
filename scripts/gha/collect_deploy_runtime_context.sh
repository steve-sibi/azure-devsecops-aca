#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"
# shellcheck source=scripts/gha/lib/common.sh
source "${ROOT_DIR}/scripts/gha/lib/common.sh"

require_env RG
require_env PREFIX
require_env QUEUE_NAME

require_command az
require_command terraform
require_command python3

deploy_log_file="${DEPLOY_LOG_FILE:-deploy_output.log}"
context_output_file="${DEPLOY_CONTEXT_OUTPUT_FILE:-deploy_runtime_context.env}"
mkdir -p "$(dirname "${context_output_file}")"

tf_output_json="$(terraform -chdir="${INFRA_DIR}" output -json 2>/dev/null || true)"

read_tf_output_string() {
  local key="$1"
  TF_OUTPUT_JSON="${tf_output_json}" TF_OUTPUT_KEY="${key}" python3 - <<'PY'
import json
import os

raw = os.environ.get("TF_OUTPUT_JSON", "").strip()
key = os.environ["TF_OUTPUT_KEY"]
if not raw:
    print("")
    raise SystemExit(0)
try:
    doc = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
if not isinstance(doc, dict):
    print("")
    raise SystemExit(0)
entry = doc.get(key) or {}
if not isinstance(entry, dict):
    print("")
    raise SystemExit(0)
value = entry.get("value")
print(value if isinstance(value, str) else "")
PY
}

api_url="$(read_tf_output_string "fastapi_url" || true)"
monitor_action_group_id="$(read_tf_output_string "monitor_action_group_id" || true)"
monitor_workbook_id="$(read_tf_output_string "monitor_workbook_id" || true)"
scan_queue_name="${SCAN_QUEUE_NAME:-}"
if [[ -z "${scan_queue_name}" ]]; then
  scan_queue_name="$(read_tf_output_string "scan_queue_name" || true)"
fi
if [[ -z "${scan_queue_name}" ]]; then
  scan_queue_name="${QUEUE_NAME}-scan"
fi

api_replicas="$(az containerapp replica list -g "${RG}" -n "${PREFIX}-api" --query "length(@)" -o tsv 2>/dev/null || echo "—")"
fetcher_replicas="$(az containerapp replica list -g "${RG}" -n "${PREFIX}-fetcher" --query "length(@)" -o tsv 2>/dev/null || echo "—")"
worker_replicas="$(az containerapp replica list -g "${RG}" -n "${PREFIX}-worker" --query "length(@)" -o tsv 2>/dev/null || echo "—")"

sbns="${PREFIX}-sbns"
tasks_queue_active="$(az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${QUEUE_NAME}" --query "countDetails.activeMessageCount" -o tsv 2>/dev/null || echo "—")"
tasks_queue_dead="$(az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${QUEUE_NAME}" --query "countDetails.deadLetterMessageCount" -o tsv 2>/dev/null || echo "—")"
scan_queue_active="$(az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${scan_queue_name}" --query "countDetails.activeMessageCount" -o tsv 2>/dev/null || echo "—")"
scan_queue_dead="$(az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${scan_queue_name}" --query "countDetails.deadLetterMessageCount" -o tsv 2>/dev/null || echo "—")"

health_status="unknown"
e2e_status="unknown"
e2e_job_id=""
e2e_run_id=""

if [[ -f "${deploy_log_file}" ]]; then
  if grep -q "API is healthy" "${deploy_log_file}"; then
    health_status="healthy"
  elif grep -q "API did not become healthy" "${deploy_log_file}"; then
    health_status="failed"
  fi

  if grep -q "E2E scan completed" "${deploy_log_file}"; then
    e2e_status="completed"
  elif grep -q "E2E scan failed" "${deploy_log_file}" \
    || grep -q "E2E submit did not return job_id" "${deploy_log_file}" \
    || grep -q "E2E scan failed for all configured targets" "${deploy_log_file}"; then
    e2e_status="error"
  elif grep -q "E2E scan timed out waiting for completion" "${deploy_log_file}" \
    || grep -q "Timed out waiting for scan" "${deploy_log_file}"; then
    e2e_status="timeout"
  fi

  e2e_job_id="$(grep -o 'job_id=[^[:space:]]*' "${deploy_log_file}" | tail -1 | cut -d= -f2 || true)"
  e2e_run_id="$(grep -o 'run_id=[^[:space:]]*' "${deploy_log_file}" | tail -1 | cut -d= -f2 || true)"
fi

context_keys=(
  API_URL
  MONITOR_ACTION_GROUP_ID
  MONITOR_WORKBOOK_ID
  API_REPLICAS
  FETCHER_REPLICAS
  WORKER_REPLICAS
  TASKS_QUEUE_ACTIVE
  TASKS_QUEUE_DEAD
  SCAN_QUEUE_ACTIVE
  SCAN_QUEUE_DEAD
  SCAN_QUEUE_NAME
  HEALTH_STATUS
  E2E_STATUS
  E2E_JOB_ID
  E2E_RUN_ID
)

: > "${context_output_file}"
for key in "${context_keys[@]}"; do
  case "${key}" in
    API_URL) value="${api_url}" ;;
    MONITOR_ACTION_GROUP_ID) value="${monitor_action_group_id}" ;;
    MONITOR_WORKBOOK_ID) value="${monitor_workbook_id}" ;;
    API_REPLICAS) value="${api_replicas}" ;;
    FETCHER_REPLICAS) value="${fetcher_replicas}" ;;
    WORKER_REPLICAS) value="${worker_replicas}" ;;
    TASKS_QUEUE_ACTIVE) value="${tasks_queue_active}" ;;
    TASKS_QUEUE_DEAD) value="${tasks_queue_dead}" ;;
    SCAN_QUEUE_ACTIVE) value="${scan_queue_active}" ;;
    SCAN_QUEUE_DEAD) value="${scan_queue_dead}" ;;
    SCAN_QUEUE_NAME) value="${scan_queue_name}" ;;
    HEALTH_STATUS) value="${health_status}" ;;
    E2E_STATUS) value="${e2e_status}" ;;
    E2E_JOB_ID) value="${e2e_job_id}" ;;
    E2E_RUN_ID) value="${e2e_run_id}" ;;
  esac
  emit_env "${key}" "${value}"
  printf "%s=%s\n" "${key}" "${value}" >> "${context_output_file}"
done

echo "[deploy] Runtime context written to ${context_output_file}"
