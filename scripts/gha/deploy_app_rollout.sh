#!/usr/bin/env bash
set -euo pipefail

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

require_env RG
require_env PREFIX

SMOKE_TEST="${SMOKE_TEST:-true}"
DEPLOY_API="${DEPLOY_API:-true}"
DEPLOY_WORKER="${DEPLOY_WORKER:-true}"
DEPLOY_CLAMAV="${DEPLOY_CLAMAV:-true}"

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }

update_container_image() {
  local app_name="$1"
  local container_name="$2"
  local image="$3"

  echo "[rollout] ${app_name}/${container_name} -> ${image}"
  retry az containerapp update \
    -g "${RG}" \
    -n "${app_name}" \
    --container-name "${container_name}" \
    --image "${image}" \
    >/dev/null
}

echo "[rollout] Updating Container Apps images..."

if is_truthy "${DEPLOY_API}"; then
  require_env API_IMAGE
  # API app (api container)
  update_container_image "${PREFIX}-api" "api" "${API_IMAGE}"
else
  echo "[rollout] DEPLOY_API=${DEPLOY_API}; skipping API container image update."
fi

if is_truthy "${DEPLOY_CLAMAV}"; then
  require_env CLAMAV_IMAGE
  # API app (clamav sidecar)
  update_container_image "${PREFIX}-api" "clamav" "${CLAMAV_IMAGE}"
else
  echo "[rollout] DEPLOY_CLAMAV=${DEPLOY_CLAMAV}; skipping ClamAV container image update."
fi

if is_truthy "${DEPLOY_WORKER}"; then
  require_env WORKER_IMAGE
  # Fetcher/Worker apps (same worker image, different WORKER_MODE)
  update_container_image "${PREFIX}-fetcher" "fetcher" "${WORKER_IMAGE}"
  update_container_image "${PREFIX}-worker" "worker" "${WORKER_IMAGE}"
else
  echo "[rollout] DEPLOY_WORKER=${DEPLOY_WORKER}; skipping Worker/Fetcher image updates."
fi

if ! is_truthy "${SMOKE_TEST}"; then
  echo "[rollout] SMOKE_TEST=${SMOKE_TEST}; skipping /healthz check."
  echo "[rollout] Rollout complete."
  exit 0
fi

command -v curl >/dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }

API_FQDN="$(az containerapp show -g "${RG}" -n "${PREFIX}-api" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || true)"
API_FQDN="$(printf "%s" "${API_FQDN:-}" | tr -d '\r' | awk '{$1=$1};1')"
if [[ -z "${API_FQDN}" ]]; then
  echo "[rollout] Failed to resolve API FQDN for ${PREFIX}-api (RG=${RG})." >&2
  exit 1
fi

API_URL="https://${API_FQDN}"
echo "[rollout] Smoke test: GET ${API_URL}/healthz"

diagnose_api() {
  local app="${PREFIX}-api"
  az containerapp show -g "${RG}" -n "${app}" -o table 2>/dev/null || true
  az containerapp revision list -g "${RG}" -n "${app}" -o table 2>/dev/null || true
  az containerapp logs show -g "${RG}" -n "${app}" --type system --tail 200 2>/dev/null || true
  az containerapp logs show -g "${RG}" -n "${app}" --type console --tail 200 2>/dev/null || true
}

for i in {1..30}; do
  code="$(curl --connect-timeout 5 --max-time 10 -sS -o /dev/null -w '%{http_code}' "${API_URL}/healthz" 2>/dev/null)" || code="000"
  if [[ "${code}" == "200" ]]; then
    echo "[rollout] API is healthy."
    echo "[rollout] Rollout complete."
    exit 0
  fi
  if [[ "${code}" == "000" ]]; then
    echo "[rollout] Waiting for API... (${i}/30) - network error or timeout"
  else
    echo "[rollout] Waiting for API... (${i}/30) HTTP ${code}"
  fi
  if [[ "${i}" == "1" || "${i}" == "10" || "${i}" == "20" ]]; then
    echo "---- ACA diagnostics (attempt ${i}) ----"
    diagnose_api
    echo "----------------------------------------"
  fi
  sleep 10
done

echo "[rollout] API did not become healthy in time."
diagnose_api
exit 1
