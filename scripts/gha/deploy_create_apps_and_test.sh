#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"
FORMAT_LOGS_PY="${ROOT_DIR}/.github/scripts/format_aca_logs.py"
# shellcheck source=scripts/gha/lib/common.sh
source "${ROOT_DIR}/scripts/gha/lib/common.sh"

require_env RG
require_env PREFIX
require_env TFSTATE_SA
require_env TFSTATE_CONTAINER
require_env TFSTATE_KEY
require_env QUEUE_NAME

IMAGE_TAG="${IMAGE_TAG:-${GITHUB_SHA:-}}"
if [[ -z "${IMAGE_TAG}" ]]; then
  echo "Missing IMAGE_TAG (or GITHUB_SHA)" >&2
  exit 2
fi

require_command az
require_command terraform
require_command curl
require_command python3

SUB_ID="$(az account show --query id -o tsv)"
set_terraform_subscription_env "${SUB_ID}"
set_terraform_principal_env_from_client_id "${AZURE_CLIENT_ID:-}" >/dev/null
apply_common_tf_var_overrides

terraform_init_azure_backend "${INFRA_DIR}"

echo "[deploy] Importing env + apps if they exist..."

ACA_ENV_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/managedEnvironments/${PREFIX}-acaenv"
API_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-api"
FETCHER_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-fetcher"
WORKER_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-worker"

terraform_import_if_exists "${INFRA_DIR}" "azurerm_container_app_environment.env" "${ACA_ENV_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_container_app.api[0]" "${API_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_container_app.fetcher[0]" "${FETCHER_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_container_app.worker[0]" "${WORKER_ID}"

echo "[deploy] Terraform apply (create/update apps)..."
SCAN_QUEUE_NAME_RESOLVED="$(resolve_scan_queue_name "${QUEUE_NAME}" "${INFRA_DIR}")"

tf_var_args=(
  "-var=prefix=${PREFIX}"
  "-var=resource_group_name=${RG}"
  "-var=queue_name=${QUEUE_NAME}"
  "-var=scan_queue_name=${SCAN_QUEUE_NAME_RESOLVED}"
  "-var=create_apps=true"
  "-var=image_tag=${IMAGE_TAG}"
)

terraform -chdir="${INFRA_DIR}" apply -auto-approve -input=false -no-color -lock-timeout=2m \
  "${tf_var_args[@]}"

API_URL="$(terraform -chdir="${INFRA_DIR}" output -raw fastapi_url)"
echo "API_URL=${API_URL}"

diagnose_api() {
  local app="${PREFIX}-api"
  az containerapp show -g "${RG}" -n "${app}" -o table || true
  az containerapp revision list -g "${RG}" -n "${app}" -o table || true
  az containerapp logs show -g "${RG}" -n "${app}" --type system --tail 200 2>&1 \
    | python3 "${FORMAT_LOGS_PY}" || true
  az containerapp logs show -g "${RG}" -n "${app}" --type console --tail 200 2>&1 \
    | python3 "${FORMAT_LOGS_PY}" || true
}

diagnose_e2e() {
  local sbns="${PREFIX}-sbns"
  local scan_queue="${SCAN_QUEUE_NAME_RESOLVED}"

  echo "[deploy] Service Bus queue depths:"
  az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${QUEUE_NAME}" \
    --query "{queue:name,active:countDetails.activeMessageCount,dead:countDetails.deadLetterMessageCount}" -o tsv 2>/dev/null || true
  az servicebus queue show -g "${RG}" --namespace-name "${sbns}" -n "${scan_queue}" \
    --query "{queue:name,active:countDetails.activeMessageCount,dead:countDetails.deadLetterMessageCount}" -o tsv 2>/dev/null || true

  show_app() {
    local app="$1"
    echo "---- ${app} ----"
    az containerapp show -g "${RG}" -n "${app}" -o table 2>/dev/null || true
    az containerapp revision list -g "${RG}" -n "${app}" -o table 2>/dev/null || true
    local replicas
    replicas="$(az containerapp replica list -g "${RG}" -n "${app}" --query "length(@)" -o tsv 2>/dev/null || echo "")"
    echo "[deploy] ${app} replicas=${replicas:-unknown}"
    if [[ "${replicas}" =~ ^[0-9]+$ ]] && [[ "${replicas}" -gt 0 ]]; then
      az containerapp logs show -g "${RG}" -n "${app}" --type console --tail 200 2>&1 \
        | python3 "${FORMAT_LOGS_PY}" || true
      az containerapp logs show -g "${RG}" -n "${app}" --type system --tail 200 2>&1 \
        | python3 "${FORMAT_LOGS_PY}" || true
    else
      echo "[deploy] ${app}: no active replicas; skipping log tail."
    fi
  }

  show_app "${PREFIX}-api"
  show_app "${PREFIX}-fetcher"
  show_app "${PREFIX}-worker"
}

assert_container_image_tag() {
  local app="$1"
  local container="$2"
  local expected_image="$3"
  local actual_image

  actual_image="$(az containerapp show \
    -g "${RG}" \
    -n "${app}" \
    --query "properties.template.containers[?name=='${container}'].image | [0]" \
    -o tsv 2>/dev/null || true)"
  actual_image="${actual_image//$'\r'/}"
  actual_image="${actual_image//$'\n'/}"

  if [[ -z "${actual_image}" ]]; then
    echo "[deploy] Failed to resolve image for ${app}/${container}." >&2
    return 1
  fi

  if [[ "${actual_image}" != *":${IMAGE_TAG}" ]]; then
    echo "[deploy] Image mismatch for ${app}/${container}: expected suffix ':${IMAGE_TAG}', actual='${actual_image}', expected='${expected_image}'." >&2
    return 1
  fi

  echo "[deploy] Verified ${app}/${container} image: ${actual_image}"
}

ACR_LOGIN_SERVER="$(az acr show -g "${RG}" -n "${PREFIX}acr" --query loginServer -o tsv)"
API_IMAGE="${ACR_LOGIN_SERVER}/${PREFIX}-api:${IMAGE_TAG}"
WORKER_IMAGE="${ACR_LOGIN_SERVER}/${PREFIX}-worker:${IMAGE_TAG}"
CLAMAV_IMAGE="${ACR_LOGIN_SERVER}/${PREFIX}-clamav:${IMAGE_TAG}"

echo "[deploy] Rolling out freshly built images (explicit app rollout)..."
SMOKE_TEST=false \
DEPLOY_API=true \
DEPLOY_WORKER=true \
DEPLOY_CLAMAV=true \
API_IMAGE="${API_IMAGE}" \
WORKER_IMAGE="${WORKER_IMAGE}" \
CLAMAV_IMAGE="${CLAMAV_IMAGE}" \
bash "${ROOT_DIR}/scripts/gha/deploy_app_rollout.sh"

echo "[deploy] Verifying active container image tags..."
if ! assert_container_image_tag "${PREFIX}-api" "api" "${API_IMAGE}" \
  || ! assert_container_image_tag "${PREFIX}-api" "clamav" "${CLAMAV_IMAGE}" \
  || ! assert_container_image_tag "${PREFIX}-fetcher" "fetcher" "${WORKER_IMAGE}" \
  || ! assert_container_image_tag "${PREFIX}-worker" "worker" "${WORKER_IMAGE}"; then
  echo "[deploy] Container image rollout assertion failed." >&2
  diagnose_e2e
  exit 1
fi

echo "[deploy] Smoke test API (/healthz)..."
for i in {1..30}; do
  # Use --fail-with-body for better error detection; network failures return 000
  code="$(curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' "${API_URL}/healthz" 2>/dev/null)" || code="000"
  if [[ "${code}" == "200" ]]; then
    echo "[deploy] API is healthy."
    break
  fi
  if [[ "${code}" == "000" ]]; then
    echo "[deploy] Waiting for API... (${i}/30) - network error or timeout"
  else
    echo "[deploy] Waiting for API... (${i}/30) HTTP ${code}"
  fi
  if [[ "${i}" == "1" || "${i}" == "10" || "${i}" == "20" ]]; then
    echo "---- ACA diagnostics (attempt ${i}) ----"
    diagnose_api
    echo "----------------------------------------"
  fi
  sleep 10
done

code="$(curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' "${API_URL}/healthz" 2>/dev/null)" || code="000"
if [[ "${code}" != "200" ]]; then
  echo "[deploy] API did not become healthy in time (HTTP ${code})."
  diagnose_api
  exit 1
fi

echo "[deploy] End-to-end scan test (/scan -> /scan/{job_id})..."

KV="${PREFIX}-kv"
API_KEY=""
for i in {1..12}; do
  API_KEY="$(az keyvault secret show --vault-name "${KV}" --name "ApiKey" --query value -o tsv 2>/dev/null || true)"
  if [[ -n "${API_KEY}" ]]; then
    break
  fi
  echo "[deploy] Waiting for Key Vault secret access... (${i}/12)"
  sleep 10
done
if [[ -z "${API_KEY}" ]]; then
  echo "[deploy] Failed to read ApiKey from Key Vault (${KV})."
  diagnose_e2e
  exit 1
fi

e2e_nonce=""
if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
  e2e_nonce="${GITHUB_RUN_ID}"
  if [[ -n "${GITHUB_RUN_ATTEMPT:-}" ]]; then
    e2e_nonce="${e2e_nonce}-${GITHUB_RUN_ATTEMPT}"
  fi
else
  e2e_nonce="$(date +%s)"
fi

default_internal_e2e_scan_url="${API_URL}/healthz?e2e=${e2e_nonce}"
e2e_blob_storage_account=""
e2e_blob_container=""
e2e_blob_name=""

# shellcheck disable=SC2329 # Invoked via trap.
cleanup_e2e_blob() {
  if [[ -z "${e2e_blob_storage_account}" || -z "${e2e_blob_container}" || -z "${e2e_blob_name}" ]]; then
    return 0
  fi

  local account_key=""
  account_key="$(az storage account keys list \
    -g "${RG}" \
    -n "${e2e_blob_storage_account}" \
    --query "[0].value" -o tsv 2>/dev/null || true)"
  if [[ -z "${account_key}" ]]; then
    echo "[deploy] Warning: unable to resolve storage account key for E2E blob cleanup (${e2e_blob_storage_account}/${e2e_blob_container}/${e2e_blob_name})."
    return 0
  fi

  if az storage blob delete \
    --account-name "${e2e_blob_storage_account}" \
    --account-key "${account_key}" \
    --container-name "${e2e_blob_container}" \
    --name "${e2e_blob_name}" \
    --only-show-errors >/dev/null 2>&1; then
    echo "[deploy] Cleaned up temporary E2E blob (${e2e_blob_container}/${e2e_blob_name})."
  else
    echo "[deploy] Warning: failed to clean up temporary E2E blob (${e2e_blob_container}/${e2e_blob_name})."
  fi
}

trap cleanup_e2e_blob EXIT

build_storage_backed_e2e_url() {
  local storage_account="${E2E_RESULTS_STORAGE_ACCOUNT:-${PREFIX}scan}"
  local container_name="${E2E_BLOB_CONTAINER:-e2e}"
  local blob_name="e2e-${e2e_nonce}.txt"
  local account_key
  local expiry
  local sas
  local tmp_file

  account_key="$(az storage account keys list \
    -g "${RG}" \
    -n "${storage_account}" \
    --query "[0].value" -o tsv 2>/dev/null || true)"
  if [[ -z "${account_key}" ]]; then
    return 1
  fi

  tmp_file="$(mktemp)"
  printf 'aca e2e probe %s\n' "${e2e_nonce}" >"${tmp_file}"

  if ! az storage container create \
    --account-name "${storage_account}" \
    --account-key "${account_key}" \
    --name "${container_name}" \
    --only-show-errors >/dev/null 2>&1; then
    rm -f "${tmp_file}"
    return 1
  fi

  if ! az storage blob upload \
    --account-name "${storage_account}" \
    --account-key "${account_key}" \
    --container-name "${container_name}" \
    --name "${blob_name}" \
    --file "${tmp_file}" \
    --overwrite true \
    --only-show-errors >/dev/null 2>&1; then
    rm -f "${tmp_file}"
    return 1
  fi

  rm -f "${tmp_file}"
  expiry="$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)+timedelta(hours=2)).strftime("%Y-%m-%dT%H:%MZ"))')"
  sas="$(az storage blob generate-sas \
    --account-name "${storage_account}" \
    --account-key "${account_key}" \
    --container-name "${container_name}" \
    --name "${blob_name}" \
    --permissions r \
    --https-only \
    --expiry "${expiry}" \
    -o tsv 2>/dev/null || true)"
  if [[ -z "${sas}" ]]; then
    return 1
  fi

  e2e_blob_storage_account="${storage_account}"
  e2e_blob_container="${container_name}"
  e2e_blob_name="${blob_name}"

  echo "https://${storage_account}.blob.core.windows.net/${container_name}/${blob_name}?${sas}"
}

redact_url_for_log() {
  local raw_url="$1"
  if [[ "${raw_url}" == *"?"* ]]; then
    printf '%s [query redacted]\n' "${raw_url%%\?*}"
  else
    printf '%s\n' "${raw_url}"
  fi
}

submit_e2e_scan() {
  local target_url="$1"
  local target_url_for_log
  local submit
  local job_id
  local run_id
  local error_code
  local resp
  local status

  target_url_for_log="$(redact_url_for_log "${target_url}")"
  echo "[deploy] E2E scan target URL: ${target_url_for_log}"

  scan_payload="$(
    E2E_SCAN_URL="${target_url}" python3 -c 'import json, os
print(json.dumps({
    "url": os.environ["E2E_SCAN_URL"],
    "type": "url",
    "force": True,
    "visibility": "private",
}))
'
  )"

  submit="$(curl -sS -X POST "${API_URL}/scan" \
    -H "content-type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d "${scan_payload}")"

  job_id="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("job_id") or "")' <<<"${submit}" || true)"
  run_id="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("run_id") or "")' <<<"${submit}" || true)"
  if [[ -z "${job_id}" ]]; then
    error_code="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("code") or "")' <<<"${submit}" 2>/dev/null || true)"
    echo "[deploy] E2E submit did not return job_id (code=${error_code:-unknown})."
    echo "${submit}"
    return 1
  fi

  echo "job_id=${job_id}"
  if [[ -n "${run_id}" ]]; then
    echo "run_id=${run_id}"
  fi

  for i in {1..40}; do
    resp="$(curl -sS "${API_URL}/scan/${job_id}" -H "X-API-Key: ${API_KEY}" || true)"
    status="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("status") or "")' <<<"${resp}" 2>/dev/null || true)"

    if [[ "${status}" == "completed" ]]; then
      echo "[deploy] E2E scan completed."
      return 0
    fi
    if [[ "${status}" == "error" ]]; then
      echo "[deploy] E2E scan failed:"
      echo "${resp}"
      return 1
    fi
    echo "[deploy] Waiting for scan... (${i}/40) status=${status:-unknown}"
    sleep 10
  done

  echo "[deploy] E2E scan timed out waiting for completion."
  return 1
}

scan_targets=()
if [[ -n "${E2E_SCAN_URL:-}" ]]; then
  scan_targets+=("${E2E_SCAN_URL}")
else
  storage_backed_url="$(build_storage_backed_e2e_url || true)"
  if [[ -n "${storage_backed_url}" ]]; then
    scan_targets+=("${storage_backed_url}")
  else
    echo "[deploy] Warning: failed to build storage-backed E2E URL; falling back to public probe URLs."
  fi
  scan_targets+=(
    "${default_internal_e2e_scan_url}"
    "https://example.com"
    "${E2E_PUBLIC_FALLBACK_URL:-https://msftconnecttest.com/connecttest.txt}"
  )
fi

for target_url in "${scan_targets[@]}"; do
  if submit_e2e_scan "${target_url}"; then
    echo "[deploy] Deploy create-apps + tests complete."
    exit 0
  fi
done

echo "[deploy] E2E scan failed for all configured targets."
diagnose_e2e
exit 1
