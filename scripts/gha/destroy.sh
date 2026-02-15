#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"
# shellcheck source=scripts/gha/lib/common.sh
source "${ROOT_DIR}/scripts/gha/lib/common.sh"

require_env RG
require_env PREFIX
require_env TFSTATE_SA
require_env TFSTATE_CONTAINER
require_env TFSTATE_KEY
require_env QUEUE_NAME
require_env AZURE_CLIENT_ID

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "terraform not found" >&2; exit 1; }

echo "[destroy] Verifying TF state data-plane access (retry)..."

SUB_ID="$(az account show --query id -o tsv)"
SP_OBJ_ID="$(az ad sp show --id "${AZURE_CLIENT_ID}" --query id -o tsv)"
SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${TFSTATE_SA}"

export ARM_SUBSCRIPTION_ID="${SUB_ID}"
export TF_VAR_subscription_id="${SUB_ID}"
export TF_VAR_terraform_principal_object_id="${SP_OBJ_ID}"

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
    echo "[destroy] RBAC verified"
    break
  fi
  echo "[destroy] Waiting for RBAC propagation... (${i}/12)"
  sleep 10
done

echo "[destroy] Terraform init (remote backend)..."

terraform -chdir="${INFRA_DIR}" init \
  -backend-config="resource_group_name=${RG}" \
  -backend-config="storage_account_name=${TFSTATE_SA}" \
  -backend-config="container_name=${TFSTATE_CONTAINER}" \
  -backend-config="key=${TFSTATE_KEY}" \
  -backend-config="use_azuread_auth=true"

echo "[destroy] Breaking stale Terraform state lease (if any)..."

if az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login >/dev/null 2>&1; then
  ST="$(az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login --query "properties.lease.state" -o tsv || echo "")"
  SS="$(az storage blob show --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" -n "${TFSTATE_KEY}" --auth-mode login --query "properties.lease.status" -o tsv || echo "")"
  if [[ "${ST}" == "leased" || "${SS}" == "locked" ]]; then
    az storage blob lease break --account-name "${TFSTATE_SA}" -c "${TFSTATE_CONTAINER}" --blob-name "${TFSTATE_KEY}" --auth-mode login >/dev/null
    sleep 5
  fi
fi

echo "[destroy] Terraform plan (destroy)..."

terraform -chdir="${INFRA_DIR}" plan -destroy -input=false -no-color \
  -var="prefix=${PREFIX}" \
  -var="resource_group_name=${RG}" \
  -var="queue_name=${QUEUE_NAME}" \
  -var="create_apps=true"

echo "[destroy] Terraform destroy (apps + infra)..."

terraform -chdir="${INFRA_DIR}" destroy -auto-approve -lock-timeout=2m \
  -var="prefix=${PREFIX}" \
  -var="resource_group_name=${RG}" \
  -var="queue_name=${QUEUE_NAME}" \
  -var="create_apps=true"

echo "[destroy] Deleting Resource Group (async)..."
az group delete -n "${RG}" --yes --no-wait || true

echo "[destroy] Destroy complete; RG deletion submitted."
