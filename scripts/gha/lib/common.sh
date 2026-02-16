#!/usr/bin/env bash

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required env var: ${name}" >&2
    exit 2
  fi
}

# Retry helper for transient Azure API failures
retry() {
  local max_attempts="${RETRY_MAX:-3}"
  local delay="${RETRY_DELAY:-10}"
  local attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    if [[ ${attempt} -ge ${max_attempts} ]]; then
      echo "[retry] Command failed after ${max_attempts} attempts: $*" >&2
      return 1
    fi
    echo "[retry] Attempt ${attempt}/${max_attempts} failed, retrying in ${delay}s..." >&2
    sleep "${delay}"
    ((attempt++))
  done
}

is_truthy() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

emit_env() {
  local name="$1"
  local value="${2-}"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    printf "%s=%s\n" "${name}" "${value}" >> "${GITHUB_ENV}"
    return 0
  fi
  export "${name}=${value}"
}

require_command() {
  local name="$1"
  command -v "${name}" >/dev/null 2>&1 || {
    echo "${name} not found" >&2
    exit 1
  }
}

set_terraform_subscription_env() {
  local sub_id="$1"
  export ARM_SUBSCRIPTION_ID="${sub_id}"
  export TF_VAR_subscription_id="${sub_id}"
}

set_terraform_principal_env_from_client_id() {
  local client_id="${1:-}"
  if [[ -z "${client_id}" ]]; then
    return 0
  fi
  local sp_obj_id
  sp_obj_id="$(az ad sp show --id "${client_id}" --query id -o tsv)"
  export TF_VAR_terraform_principal_object_id="${sp_obj_id}"
  echo "${sp_obj_id}"
}

apply_common_tf_var_overrides() {
  local kv_secret_readers_json
  kv_secret_readers_json="${KV_SECRET_READER_OBJECT_IDS_JSON:-${ACA_KV_SECRET_READER_OBJECT_IDS_JSON:-}}"
  if [[ -n "${kv_secret_readers_json}" ]]; then
    export TF_VAR_kv_secret_reader_object_ids="${kv_secret_readers_json}"
    echo "[deploy] Using kv_secret_reader_object_ids from workflow configuration."
  fi

  if [[ -n "${MONITOR_ACTION_GROUP_EMAIL_RECEIVERS_JSON:-}" ]]; then
    export TF_VAR_monitor_action_group_email_receivers="${MONITOR_ACTION_GROUP_EMAIL_RECEIVERS_JSON}"
    echo "[deploy] Using monitor_action_group_email_receivers from workflow configuration."
  fi

  if [[ -n "${MONITOR_ALERTS_ENABLED:-}" ]]; then
    export TF_VAR_monitor_alerts_enabled="${MONITOR_ALERTS_ENABLED}"
  fi
  if [[ -n "${MONITOR_WORKBOOK_ENABLED:-}" ]]; then
    export TF_VAR_monitor_workbook_enabled="${MONITOR_WORKBOOK_ENABLED}"
  fi
  if [[ -n "${OTEL_TRACES_SAMPLER_RATIO:-}" ]]; then
    export TF_VAR_otel_traces_sampler_ratio="${OTEL_TRACES_SAMPLER_RATIO}"
    echo "[deploy] Using OTEL trace sampler ratio from workflow configuration."
  fi
  if [[ -n "${SCAN_QUEUE_NAME:-}" ]]; then
    export TF_VAR_scan_queue_name="${SCAN_QUEUE_NAME}"
    echo "[deploy] Using scan_queue_name from workflow input."
  fi
}

terraform_init_azure_backend() {
  local infra_dir="$1"
  terraform -chdir="${infra_dir}" init \
    -backend-config="resource_group_name=${RG}" \
    -backend-config="storage_account_name=${TFSTATE_SA}" \
    -backend-config="container_name=${TFSTATE_CONTAINER}" \
    -backend-config="key=${TFSTATE_KEY}" \
    -backend-config="use_azuread_auth=true"
}

ensure_role_assignment() {
  local assignee_object_id="$1"
  local scope="$2"
  local role_name="$3"
  local assignee_principal_type="${4:-ServicePrincipal}"

  if az role assignment list --assignee-object-id "${assignee_object_id}" --scope "${scope}" \
    --role "${role_name}" --query "[0].id" -o tsv | grep . >/dev/null; then
    return 0
  fi

  az role assignment create \
    --assignee-object-id "${assignee_object_id}" \
    --assignee-principal-type "${assignee_principal_type}" \
    --role "${role_name}" \
    --scope "${scope}" >/dev/null
}

wait_for_storage_blob_access() {
  local account_name="$1"
  local container_name="$2"
  local attempts="${3:-12}"
  local sleep_seconds="${4:-10}"
  local prefix="${5:-[deploy]}"
  local i

  for ((i = 1; i <= attempts; i++)); do
    if az storage blob list --account-name "${account_name}" \
      --container-name "${container_name}" --auth-mode login 1>/dev/null 2>&1; then
      echo "${prefix} RBAC verified"
      return 0
    fi
    echo "${prefix} Waiting for RBAC propagation... (${i}/${attempts})"
    sleep "${sleep_seconds}"
  done

  return 1
}

break_terraform_state_lease_if_any() {
  local account_name="$1"
  local container_name="$2"
  local blob_name="$3"

  if ! az storage blob show --account-name "${account_name}" -c "${container_name}" -n "${blob_name}" --auth-mode login >/dev/null 2>&1; then
    return 0
  fi

  local state
  local status
  state="$(az storage blob show --account-name "${account_name}" -c "${container_name}" -n "${blob_name}" --auth-mode login --query "properties.lease.state" -o tsv || echo "")"
  status="$(az storage blob show --account-name "${account_name}" -c "${container_name}" -n "${blob_name}" --auth-mode login --query "properties.lease.status" -o tsv || echo "")"
  if [[ "${state}" == "leased" || "${status}" == "locked" ]]; then
    az storage blob lease break --account-name "${account_name}" -c "${container_name}" --blob-name "${blob_name}" --auth-mode login >/dev/null
    sleep 5
  fi
}

terraform_import_if_exists() {
  local infra_dir="$1"
  local address="$2"
  local resource_id="$3"
  local legacy_address="${4:-}"

  if ! az resource show --ids "${resource_id}" >/dev/null 2>&1; then
    return 0
  fi
  if terraform -chdir="${infra_dir}" state show "${address}" >/dev/null 2>&1; then
    return 0
  fi
  if [[ -n "${legacy_address}" ]] && terraform -chdir="${infra_dir}" state show "${legacy_address}" >/dev/null 2>&1; then
    return 0
  fi
  terraform -chdir="${infra_dir}" import "${address}" "${resource_id}"
}

resolve_scan_queue_name() {
  local queue_name="$1"
  local infra_dir="${2:-}"
  local resolved="${SCAN_QUEUE_NAME:-}"

  if [[ -z "${resolved}" && -n "${infra_dir}" ]] && command -v terraform >/dev/null 2>&1; then
    resolved="$(terraform -chdir="${infra_dir}" output -raw scan_queue_name 2>/dev/null || true)"
  fi
  if [[ -z "${resolved}" ]]; then
    resolved="${queue_name}-scan"
  fi

  echo "${resolved}"
}
