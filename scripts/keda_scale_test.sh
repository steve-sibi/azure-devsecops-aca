#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="${ROOT_DIR}/infra"

usage() {
  cat <<'EOF'
KEDA scale test for the fetcher/worker Container Apps.

Enqueues N scan messages directly to Service Bus, then polls the target app replica count
until it reaches the expected minimum.

Requirements:
  - Azure CLI logged in: az login (or use OIDC in GitHub Actions)
  - Python deps for enqueue script:
      python3 -m pip install -r app/worker/requirements.txt

Usage:
  bash scripts/keda_scale_test.sh \
    --resource-group rg-devsecops-aca \
    --prefix devsecopsaca \
    --queue-name tasks \
    --scan-queue-name tasks-scan \
    --stage scan \
    --message-count 100 \
    --expected-min-replicas 1 \
    --scan-url https://example.com \
    --timeout-seconds 600

Optional:
  --servicebus-connection-string "<conn>"   (skips Key Vault lookup)
EOF
}

RG=""
PREFIX=""
QUEUE_NAME="tasks"
SCAN_QUEUE_NAME=""
STAGE="scan"
MESSAGE_COUNT="100"
EXPECTED_MIN_REPLICAS="1"
SCAN_URL="https://example.com"
TIMEOUT_SECONDS="600"
SB_CONN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group) RG="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --queue-name) QUEUE_NAME="${2:-}"; shift 2 ;;
    --scan-queue-name) SCAN_QUEUE_NAME="${2:-}"; shift 2 ;;
    --stage) STAGE="${2:-}"; shift 2 ;;
    --message-count) MESSAGE_COUNT="${2:-}"; shift 2 ;;
    --expected-min-replicas) EXPECTED_MIN_REPLICAS="${2:-}"; shift 2 ;;
    --scan-url) SCAN_URL="${2:-}"; shift 2 ;;
    --timeout-seconds) TIMEOUT_SECONDS="${2:-}"; shift 2 ;;
    --servicebus-connection-string) SB_CONN="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$RG" || -z "$PREFIX" ]]; then
  echo "Missing required args: --resource-group and --prefix" >&2
  usage
  exit 2
fi

command -v az >/dev/null 2>&1 || { echo "az CLI not found" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found" >&2; exit 1; }

resolve_scan_queue_name_local() {
  local resolved="${SCAN_QUEUE_NAME}"
  if [[ -z "${resolved}" ]] && command -v terraform >/dev/null 2>&1; then
    resolved="$(terraform -chdir="${INFRA_DIR}" output -raw scan_queue_name 2>/dev/null || true)"
  fi
  if [[ -z "${resolved}" ]]; then
    resolved="${QUEUE_NAME}-scan"
  fi
  echo "${resolved}"
}

python3 -c "import azure.servicebus" >/dev/null 2>&1 || {
  echo "Missing Python dependency: azure-servicebus" >&2
  echo "Install: python3 -m pip install -r app/worker/requirements.txt" >&2
  exit 1
}

az account show >/dev/null 2>&1 || {
  echo "Azure CLI not logged in. Run: az login" >&2
  exit 1
}

WORKER_APP="${PREFIX}-worker"
FETCHER_APP="${PREFIX}-fetcher"
SB_NAMESPACE="${PREFIX}-sbns"
KV_NAME="${PREFIX}-kv"

STAGE="$(echo "${STAGE}" | tr '[:upper:]' '[:lower:]')"
if [[ "${STAGE}" != "fetch" && "${STAGE}" != "scan" ]]; then
  echo "Invalid --stage (expected: fetch or scan)" >&2
  exit 2
fi

TARGET_QUEUE="${QUEUE_NAME}"
TARGET_APP="${WORKER_APP}"
KV_SECRET="ServiceBusScanSend"
if [[ "${STAGE}" == "fetch" ]]; then
  TARGET_APP="${FETCHER_APP}"
  KV_SECRET="ServiceBusSend"
else
  TARGET_QUEUE="$(resolve_scan_queue_name_local)"
fi

if [[ -z "$SB_CONN" ]]; then
  SB_CONN="$(az keyvault secret show --vault-name "$KV_NAME" --name "${KV_SECRET}" --query value -o tsv)"
fi

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  echo "::add-mask::$SB_CONN"
fi

echo "Enqueueing ${MESSAGE_COUNT} messages to Service Bus queue '${TARGET_QUEUE}' (stage=${STAGE})..."
SERVICEBUS_CONN="$SB_CONN" python3 scripts/send_servicebus_messages.py \
  --queue "$TARGET_QUEUE" \
  --count "$MESSAGE_COUNT" \
  --url "$SCAN_URL" \
  --source "keda-scale-test"

echo "Waiting for scale-out: app=${TARGET_APP} expected_min_replicas=${EXPECTED_MIN_REPLICAS}"
deadline=$((SECONDS + TIMEOUT_SECONDS))
while [[ $SECONDS -lt $deadline ]]; do
  replicas="$(az containerapp replica list -g "$RG" -n "$TARGET_APP" --query 'length(@)' -o tsv 2>/dev/null || echo 0)"
  depth="$(az servicebus queue show -g "$RG" --namespace-name "$SB_NAMESPACE" -n "$TARGET_QUEUE" --query 'countDetails.activeMessageCount' -o tsv 2>/dev/null || echo 0)"
  echo "replicas=${replicas:-0} queue_depth=${depth:-unknown}"

  if [[ "${replicas:-0}" -ge "$EXPECTED_MIN_REPLICAS" ]]; then
    echo "PASS: scale-out observed."
    exit 0
  fi
  sleep 15
done

echo "FAIL: timed out waiting for scale-out after ${TIMEOUT_SECONDS}s" >&2
echo "Diagnostics:" >&2
az containerapp show -g "$RG" -n "$TARGET_APP" -o table || true
az containerapp revision list -g "$RG" -n "$TARGET_APP" -o table || true
az containerapp logs show -g "$RG" -n "$TARGET_APP" --type system --tail 200 || true
exit 1
