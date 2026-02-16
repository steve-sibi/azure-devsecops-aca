#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"
# shellcheck source=scripts/gha/lib/common.sh
source "${ROOT_DIR}/scripts/gha/lib/common.sh"

require_env RG
require_env REGION
require_env PREFIX
require_env TFSTATE_SA
require_env TFSTATE_CONTAINER
require_env TFSTATE_KEY
require_env QUEUE_NAME
require_env AZURE_CLIENT_ID

TERRAFORM_OPERATION="${TERRAFORM_OPERATION:-apply}"
if [[ "${TERRAFORM_OPERATION}" != "plan" && "${TERRAFORM_OPERATION}" != "apply" ]]; then
  echo "Unsupported TERRAFORM_OPERATION='${TERRAFORM_OPERATION}'. Use 'plan' or 'apply'." >&2
  exit 2
fi

require_command az
require_command terraform

KV="${PREFIX}-kv"
ACR="${PREFIX}acr"
LA="${PREFIX}-la"

echo "[deploy] Ensuring RG + foundation resources exist..."

retry az group create -n "${RG}" -l "${REGION}" >/dev/null

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
    retry az keyvault create -g "${RG}" -n "${KV}" -l "${REGION}" --enable-rbac-authorization true >/dev/null
  fi
fi

echo "[deploy] Ensuring Key Vault ${KV} uses Azure RBAC authorization..."
KV_RBAC="$(az keyvault show -g "${RG}" -n "${KV}" --query "properties.enableRbacAuthorization" -o tsv 2>/dev/null || echo "")"
if [[ "${KV_RBAC,,}" != "true" ]]; then
  echo "[deploy] Enabling RBAC authorization on Key Vault ${KV}"
  retry az keyvault update -g "${RG}" -n "${KV}" --enable-rbac-authorization true >/dev/null
fi

az acr show -g "${RG}" -n "${ACR}" >/dev/null 2>&1 || \
  retry az acr create -g "${RG}" -n "${ACR}" -l "${REGION}" --sku Basic >/dev/null

az monitor log-analytics workspace show -g "${RG}" -n "${LA}" >/dev/null 2>&1 || \
  retry az monitor log-analytics workspace create -g "${RG}" -n "${LA}" -l "${REGION}" >/dev/null

echo "[deploy] Verifying required Azure provider namespace registrations..."
# Provider registration is subscription-scoped and should be handled manually by subscription admins.
check_provider_registered() {
  local ns="$1"
  local state
  state="$(az provider show --namespace "${ns}" --query registrationState -o tsv 2>/dev/null || echo "")"
  if [[ "${state}" != "Registered" ]]; then
    echo "[deploy] Provider namespace '${ns}' is not registered (state='${state:-unknown}')." >&2
    echo "[deploy] Register it manually, then rerun:" >&2
    echo "  az provider register --namespace ${ns} --wait" >&2
    exit 1
  fi
}
check_provider_registered "Microsoft.SignalRService"
check_provider_registered "Microsoft.App"

echo "[deploy] Ensuring Terraform state storage exists..."

if az storage account show -g "${RG}" -n "${TFSTATE_SA}" >/dev/null 2>&1; then
  retry az storage account update \
    -g "${RG}" -n "${TFSTATE_SA}" \
    --min-tls-version TLS1_2 \
    --only-show-errors >/dev/null
else
  retry az storage account create \
    -g "${RG}" -n "${TFSTATE_SA}" -l "${REGION}" \
    --sku Standard_LRS --kind StorageV2 \
    --min-tls-version TLS1_2 \
    --only-show-errors >/dev/null
fi

retry az storage container create \
  --account-name "${TFSTATE_SA}" \
  --name "${TFSTATE_CONTAINER}" \
  --auth-mode login >/dev/null

echo "[deploy] Ensuring CI principal can access Terraform state (data plane RBAC)..."

SUB_ID="$(az account show --query id -o tsv)"
SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${TFSTATE_SA}"

set_terraform_subscription_env "${SUB_ID}"
SP_OBJ_ID="$(set_terraform_principal_env_from_client_id "${AZURE_CLIENT_ID}")"
apply_common_tf_var_overrides

ensure_role_assignment "${SP_OBJ_ID}" "${SCOPE}" "Storage Blob Data Contributor" "ServicePrincipal"

if ! wait_for_storage_blob_access "${TFSTATE_SA}" "${TFSTATE_CONTAINER}" "12" "10" "[deploy]"; then
  echo "[deploy] Failed to verify TF state RBAC in time." >&2
  exit 1
fi

echo "[deploy] Terraform init (remote backend)..."
terraform_init_azure_backend "${INFRA_DIR}"

echo "[deploy] Breaking stale Terraform state lease (if any)..."
break_terraform_state_lease_if_any "${TFSTATE_SA}" "${TFSTATE_CONTAINER}" "${TFSTATE_KEY}"

echo "[deploy] Import existing core resources (safe if absent)..."

SCAN_QUEUE_NAME_RESOLVED="$(resolve_scan_queue_name "${QUEUE_NAME}" "${INFRA_DIR}")"
APPINSIGHTS_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Insights/components/${PREFIX}-appi"
SB_NS_ID="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.ServiceBus/namespaces/${PREFIX}-sbns"
SB_QUEUE_ID="${SB_NS_ID}/queues/${QUEUE_NAME}"
SB_SCAN_QUEUE_ID="${SB_NS_ID}/queues/${SCAN_QUEUE_NAME_RESOLVED}"
Q_SEND_ID="${SB_QUEUE_ID}/authorizationRules/api-send"
Q_LISTEN_ID="${SB_QUEUE_ID}/authorizationRules/worker-listen"
Q_MANAGE_ID="${SB_QUEUE_ID}/authorizationRules/scale-manage"
Q_SCAN_SEND_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/fetcher-send"
Q_SCAN_LISTEN_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/worker-scan-listen"
Q_SCAN_MANAGE_ID="${SB_SCAN_QUEUE_ID}/authorizationRules/scale-manage-scan"

terraform_import_if_exists "${INFRA_DIR}" "azurerm_application_insights.appi" "${APPINSIGHTS_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_namespace.sb" "${SB_NS_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue.q" "${SB_QUEUE_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue.q_scan" "${SB_SCAN_QUEUE_ID}"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_send\"]" "${Q_SEND_ID}" "azurerm_servicebus_queue_authorization_rule.q_send"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_listen\"]" "${Q_LISTEN_ID}" "azurerm_servicebus_queue_authorization_rule.q_listen"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_manage\"]" "${Q_MANAGE_ID}" "azurerm_servicebus_queue_authorization_rule.q_manage"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_scan_send\"]" "${Q_SCAN_SEND_ID}" "azurerm_servicebus_queue_authorization_rule.q_scan_send"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_scan_listen\"]" "${Q_SCAN_LISTEN_ID}" "azurerm_servicebus_queue_authorization_rule.q_scan_listen"
terraform_import_if_exists "${INFRA_DIR}" "azurerm_servicebus_queue_authorization_rule.queue_rule[\"q_scan_manage\"]" "${Q_SCAN_MANAGE_ID}" "azurerm_servicebus_queue_authorization_rule.q_scan_manage"

TF_CREATE_APPS="${CREATE_APPS:-auto}"
if [[ "${TF_CREATE_APPS}" == "auto" ]]; then
  if az containerapp show -g "${RG}" -n "${PREFIX}-api" >/dev/null 2>&1 \
    && az containerapp show -g "${RG}" -n "${PREFIX}-fetcher" >/dev/null 2>&1 \
    && az containerapp show -g "${RG}" -n "${PREFIX}-worker" >/dev/null 2>&1; then
    TF_CREATE_APPS="true"
    echo "[deploy] Existing Container Apps detected; preserving apps during infra ${TERRAFORM_OPERATION}."
  else
    TF_CREATE_APPS="false"
    echo "[deploy] Container Apps not fully present; infra ${TERRAFORM_OPERATION} will skip app resources."
  fi
fi

tf_var_args=(
  "-var=prefix=${PREFIX}"
  "-var=resource_group_name=${RG}"
  "-var=queue_name=${QUEUE_NAME}"
  "-var=scan_queue_name=${SCAN_QUEUE_NAME_RESOLVED}"
  "-var=create_apps=${TF_CREATE_APPS}"
)

if [[ "${TERRAFORM_OPERATION}" == "plan" ]]; then
  PLAN_FILE="${TF_PLAN_FILE:-infra.tfplan}"
  PLAN_TEXT_FILE="${TF_PLAN_TEXT_FILE:-infra-plan.txt}"
  echo "[deploy] Terraform plan (infra)..."
  terraform -chdir="${INFRA_DIR}" plan -input=false -no-color -lock-timeout=2m \
    -out "${PLAN_FILE}" \
    "${tf_var_args[@]}"
  terraform -chdir="${INFRA_DIR}" show -no-color "${PLAN_FILE}" > "${PLAN_TEXT_FILE}"
  echo "[deploy] Infra plan complete."
else
  if [[ -n "${TF_PLAN_FILE:-}" && -f "${INFRA_DIR}/${TF_PLAN_FILE}" ]]; then
    echo "[deploy] Terraform apply (saved plan)..."
    terraform -chdir="${INFRA_DIR}" apply -auto-approve -input=false -no-color -lock-timeout=2m "${TF_PLAN_FILE}"
  else
    echo "[deploy] Terraform apply (infra only, no apps)..."
    terraform -chdir="${INFRA_DIR}" apply -auto-approve -input=false -no-color -lock-timeout=2m \
      "${tf_var_args[@]}"
  fi
  echo "[deploy] Infra bootstrap complete."
fi
