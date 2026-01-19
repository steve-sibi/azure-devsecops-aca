#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"
FORMAT_LOGS_PY="${ROOT_DIR}/.github/scripts/format_aca_logs.py"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env var: ${name}" >&2
    exit 2
  fi
}

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

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "terraform not found" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }

SUB_ID="$(az account show --query id -o tsv)"
export ARM_SUBSCRIPTION_ID="${SUB_ID}"
export TF_VAR_subscription_id="${SUB_ID}"

if [[ -n "${AZURE_CLIENT_ID:-}" ]]; then
  SP_OBJ_ID="$(az ad sp show --id "${AZURE_CLIENT_ID}" --query id -o tsv)"
  export TF_VAR_terraform_principal_object_id="${SP_OBJ_ID}"
fi

terraform -chdir="${INFRA_DIR}" init \
  -backend-config="resource_group_name=${RG}" \
  -backend-config="storage_account_name=${TFSTATE_SA}" \
  -backend-config="container_name=${TFSTATE_CONTAINER}" \
  -backend-config="key=${TFSTATE_KEY}" \
  -backend-config="use_azuread_auth=true"

echo "[deploy] Importing env + apps if they exist..."

ACA_ENV_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/managedEnvironments/${PREFIX}-acaenv"
API_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-api"
FETCHER_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-fetcher"
WORKER_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.App/containerApps/${PREFIX}-worker"

exists() { az resource show --ids "$1" >/dev/null 2>&1; }
instate() { terraform -chdir="${INFRA_DIR}" state show "$1" >/dev/null 2>&1; }

if exists "${ACA_ENV_ID}" && ! instate azurerm_container_app_environment.env; then
  terraform -chdir="${INFRA_DIR}" import azurerm_container_app_environment.env "${ACA_ENV_ID}" || true
fi
if exists "${API_ID}" && ! instate azurerm_container_app.api[0]; then
  terraform -chdir="${INFRA_DIR}" import azurerm_container_app.api[0] "${API_ID}" || true
fi
if exists "${FETCHER_ID}" && ! instate azurerm_container_app.fetcher[0]; then
  terraform -chdir="${INFRA_DIR}" import azurerm_container_app.fetcher[0] "${FETCHER_ID}" || true
fi
if exists "${WORKER_ID}" && ! instate azurerm_container_app.worker[0]; then
  terraform -chdir="${INFRA_DIR}" import azurerm_container_app.worker[0] "${WORKER_ID}" || true
fi

echo "[deploy] Terraform apply (create/update apps)..."

terraform -chdir="${INFRA_DIR}" apply -auto-approve -input=false -no-color -lock-timeout=2m \
  -var="prefix=${PREFIX}" \
  -var="resource_group_name=${RG}" \
  -var="queue_name=${QUEUE_NAME}" \
  -var="create_apps=true" \
  -var="image_tag=${IMAGE_TAG}"

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
  local scan_queue="${QUEUE_NAME}-scan"

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

echo "[deploy] Smoke test API (/healthz)..."
for i in {1..30}; do
  code="$(curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' "${API_URL}/healthz" || true)"
  if [[ "${code}" == "200" ]]; then
    echo "[deploy] API is healthy."
    break
  fi
  echo "[deploy] Waiting for API... (${i}/30) HTTP ${code}"
  if [[ "${i}" == "1" || "${i}" == "10" || "${i}" == "20" ]]; then
    echo "---- ACA diagnostics (attempt ${i}) ----"
    diagnose_api
    echo "----------------------------------------"
  fi
  sleep 10
done

code="$(curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' "${API_URL}/healthz" || true)"
if [[ "${code}" != "200" ]]; then
  echo "[deploy] API did not become healthy in time."
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

submit="$(curl -sS -X POST "${API_URL}/scan" \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url"}')"

job_id="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("job_id") or "")' <<<"${submit}" || true)"
if [[ -z "${job_id}" ]]; then
  echo "[deploy] Failed to get job_id from /scan response:"
  echo "${submit}"
  diagnose_e2e
  exit 1
fi

echo "job_id=${job_id}"
for i in {1..40}; do
  resp="$(curl -sS "${API_URL}/scan/${job_id}" -H "X-API-Key: ${API_KEY}" || true)"
  status="$(python3 -c 'import json,sys; doc=json.loads(sys.stdin.read() or "{}"); print(doc.get("status") or "")' <<<"${resp}" 2>/dev/null || true)"

  if [[ "${status}" == "completed" ]]; then
    echo "[deploy] E2E scan completed."
    echo "[deploy] Deploy create-apps + tests complete."
    exit 0
  fi
  if [[ "${status}" == "error" ]]; then
    echo "[deploy] E2E scan failed:"
    echo "${resp}"
    diagnose_e2e
    exit 1
  fi
  echo "[deploy] Waiting for scan... (${i}/40) status=${status:-unknown}"
  sleep 10
done

echo "[deploy] Timed out waiting for scan to complete."
diagnose_e2e
exit 1
