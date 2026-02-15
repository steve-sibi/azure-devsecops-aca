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
