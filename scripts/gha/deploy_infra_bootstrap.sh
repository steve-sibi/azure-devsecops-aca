#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env var: ${name}" >&2
    exit 2
  fi
}

require_env RG
require_env REGION
require_env PREFIX
require_env TFSTATE_SA
require_env TFSTATE_CONTAINER
require_env TFSTATE_KEY
require_env QUEUE_NAME
require_env AZURE_CLIENT_ID

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "terraform not found" >&2; exit 1; }

KV="${PREFIX}-kv"
ACR="${PREFIX}acr"
LA="${PREFIX}-la"

echo "[deploy] Ensuring RG + foundation resources exist..."

az group create -n "${RG}" -l "${REGION}" >/dev/null

if az keyvault show -g "${RG}" -n "${KV}" >/dev/null 2>&1; then
  echo "[deploy] Key Vault ${KV} exists"
else
  if az keyvault show-deleted -n "${KV}" >/dev/null 2>&1; then
    echo "[deploy] Recovering soft-deleted Key Vault ${KV}"
    az keyvault recover -n "${KV}" >/dev/null
    for i in {1..30}; do
      az keyvault show -g "${RG}" -n "${KV}" >/dev/null 2>&1 && break
      echo "[deploy] Waiting for Key Vault recovery... (${i}/30)"
      sleep 5
    done
  else
    echo "[deploy] Creating Key Vault ${KV}"
    az keyvault create -g "${RG}" -n "${KV}" -l "${REGION}" >/dev/null
  fi
fi

az acr show -g "${RG}" -n "${ACR}" >/dev/null 2>&1 || \
  az acr create -g "${RG}" -n "${ACR}" -l "${REGION}" --sku Basic >/dev/null

az monitor log-analytics workspace show -g "${RG}" -n "${LA}" >/dev/null 2>&1 || \
  az monitor log-analytics workspace create -g "${RG}" -n "${LA}" -l "${REGION}" >/dev/null

echo "[deploy] Ensuring Terraform state storage exists..."

if az storage account show -g "${RG}" -n "${TFSTATE_SA}" >/dev/null 2>&1; then
  az storage account update \
    -g "${RG}" -n "${TFSTATE_SA}" \
    --min-tls-version TLS1_2 >/dev/null
else
  az storage account create \
    -g "${RG}" -n "${TFSTATE_SA}" -l "${REGION}" \
    --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 >/dev/null
fi

az storage container create \
  --account-name "${TFSTATE_SA}" \
  --name "${TFSTATE_CONTAINER}" \
  --auth-mode login >/dev/null

echo "[deploy] Ensuring CI principal can access Terraform state (data plane RBAC)..."

SUB_ID="$(az account show --query id -o tsv)"
SP_OBJ_ID="$(az ad sp show --id "${AZURE_CLIENT_ID}" --query id -o tsv)"
SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${TFSTATE_SA}"

az role assignment list --assignee-object-id "${SP_OBJ_ID}" --scope "${SCOPE}" \
  --role "Storage Blob Data Contributor" --query "[0].id" -o tsv | grep . >/dev/null || \
  az role assignment create \
    --assignee-object-id "${SP_OBJ_ID}" \
    --assignee-principal-type ServicePrincipal \
    --role "Storage Blob Data Contributor" \
    --scope "${SCOPE}" >/dev/null

for i in {1..12}; do
  if az storage blob list --account-name "${TFSTATE_SA}" \
    --container-name "${TFSTATE_CONTAINER}" --auth-mode login 1>/dev/null 2>&1; then
    echo "[deploy] RBAC verified"
    break
  fi
  echo "[deploy] Waiting for RBAC propagation... (${i}/12)"
  sleep 10
done

echo "[deploy] Terraform init (remote backend)..."

terraform -chdir="${INFRA_DIR}" init \
  -backend-config="resource_group_name=${RG}" \
  -backend-config="storage_account_name=${TFSTATE_SA}" \
  -backend-config="container_name=${TFSTATE_CONTAINER}" \
  -backend-config="key=${TFSTATE_KEY}" \
  -backend-config="use_azuread_auth=true"

echo "[deploy] Breaking stale Terraform state lease (if any)..."

if az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login >/dev/null 2>&1; then
  ST="$(az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login --query "properties.lease.state" -o tsv || echo "")"
  SS="$(az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login --query "properties.lease.status" -o tsv || echo "")"
  if [[ "${ST}" == "leased" || "${SS}" == "locked" ]]; then
    az storage blob lease break --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" --blob-name "${TFSTATE_KEY}" --auth-mode login >/dev/null
    sleep 5
  fi
fi

echo "[deploy] Import existing core resources (safe if absent)..."

SUB="$(az account show --query id -o tsv)"
APPINSIGHTS_ID="/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.Insights/components/${PREFIX}-appi"
SB_NS_ID="/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.ServiceBus/namespaces/${PREFIX}-sbns"
SB_QUEUE_ID="${SB_NS_ID}/queues/${QUEUE_NAME}"
SB_SCAN_QUEUE_ID="${SB_NS_ID}/queues/${QUEUE_NAME}-scan"
Q_SEND_ID="${SB_QUEUE_ID}/authorizationRules/api-send"
Q_LISTEN_ID="${SB_QUEUE_ID}/authorizationRules/worker-listen"
Q_MANAGE_ID="${SB_QUEUE_ID}/authorizationRules/scale-manage"
Q_SCAN_SEND_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/fetcher-send"
Q_SCAN_LISTEN_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/worker-scan-listen"
Q_SCAN_MANAGE_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/scale-manage-scan"

exists() { az resource show --ids "$1" >/dev/null 2>&1; }
instate() { terraform -chdir="${INFRA_DIR}" state show "$1" >/dev/null 2>&1; }

if exists "${APPINSIGHTS_ID}" && ! instate azurerm_application_insights.appi; then
  terraform -chdir="${INFRA_DIR}" import azurerm_application_insights.appi "${APPINSIGHTS_ID}" || true
fi
if exists "${SB_NS_ID}" && ! instate azurerm_servicebus_namespace.sb; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_namespace.sb "${SB_NS_ID}" || true
fi
if exists "${SB_QUEUE_ID}" && ! instate azurerm_servicebus_queue.q; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue.q "${SB_QUEUE_ID}" || true
fi
if exists "${SB_SCAN_QUEUE_ID}" && ! instate azurerm_servicebus_queue.q_scan; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue.q_scan "${SB_SCAN_QUEUE_ID}" || true
fi
if exists "${Q_SEND_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_send; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_send "${Q_SEND_ID}" || true
fi
if exists "${Q_LISTEN_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_listen; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_listen "${Q_LISTEN_ID}" || true
fi
if exists "${Q_MANAGE_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_manage; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_manage "${Q_MANAGE_ID}" || true
fi
if exists "${Q_SCAN_SEND_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_scan_send; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_scan_send "${Q_SCAN_SEND_ID}" || true
fi
if exists "${Q_SCAN_LISTEN_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_scan_listen; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_scan_listen "${Q_SCAN_LISTEN_ID}" || true
fi
if exists "${Q_SCAN_MANAGE_ID}" && ! instate azurerm_servicebus_queue_authorization_rule.q_scan_manage; then
  terraform -chdir="${INFRA_DIR}" import azurerm_servicebus_queue_authorization_rule.q_scan_manage "${Q_SCAN_MANAGE_ID}" || true
fi

echo "[deploy] Terraform apply (infra only, no apps)..."

terraform -chdir="${INFRA_DIR}" apply -auto-approve -input=false -no-color -lock-timeout=2m \
  -var="prefix=${PREFIX}" \
  -var="resource_group_name=${RG}" \
  -var="queue_name=${QUEUE_NAME}" \
  -var="create_apps=false"

echo "[deploy] Infra bootstrap complete."
