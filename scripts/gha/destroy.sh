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

require_command az
require_command terraform

echo "[destroy] Verifying TF state data-plane access (retry)..."

SUB_ID="$(az account show --query id -o tsv)"
SCOPE="/subscriptions/${SUB_ID}/resourceGroups/${RG}/providers/Microsoft.Storage/storageAccounts/${TFSTATE_SA}"

set_terraform_subscription_env "${SUB_ID}"
SP_OBJ_ID="$(set_terraform_principal_env_from_client_id "${AZURE_CLIENT_ID}")"
apply_common_tf_var_overrides

ensure_role_assignment "${SP_OBJ_ID}" "${SCOPE}" "Storage Blob Data Contributor" "ServicePrincipal"
if ! wait_for_storage_blob_access "${TFSTATE_SA}" "${TFSTATE_CONTAINER}" "12" "10" "[destroy]"; then
  echo "[destroy] Failed to verify TF state RBAC in time." >&2
  exit 1
fi

echo "[destroy] Terraform init (remote backend)..."
terraform_init_azure_backend "${INFRA_DIR}"

echo "[destroy] Breaking stale Terraform state lease (if any)..."
break_terraform_state_lease_if_any "${TFSTATE_SA}" "${TFSTATE_CONTAINER}" "${TFSTATE_KEY}"

SCAN_QUEUE_NAME_RESOLVED="$(resolve_scan_queue_name "${QUEUE_NAME}" "${INFRA_DIR}")"

tf_var_args=(
  "-var=prefix=${PREFIX}"
  "-var=resource_group_name=${RG}"
  "-var=queue_name=${QUEUE_NAME}"
  "-var=scan_queue_name=${SCAN_QUEUE_NAME_RESOLVED}"
  "-var=create_apps=true"
)

echo "[destroy] Terraform plan (destroy)..."
terraform -chdir="${INFRA_DIR}" plan -destroy -input=false -no-color "${tf_var_args[@]}"

echo "[destroy] Terraform destroy (apps + infra)..."
terraform -chdir="${INFRA_DIR}" destroy -auto-approve -lock-timeout=2m "${tf_var_args[@]}"

echo "[destroy] Deleting Resource Group (async)..."
az group delete -n "${RG}" --yes --no-wait || true

echo "[destroy] Destroy complete; RG deletion submitted."
