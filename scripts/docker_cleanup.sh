#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

echo "[docker_cleanup] Removing dangling images..."
docker image prune -f

if [[ "${PRUNE_BUILD_CACHE:-false}" == "true" || "${PRUNE_BUILD_CACHE:-false}" == "1" ]]; then
  echo "[docker_cleanup] Pruning build cache (PRUNE_BUILD_CACHE=true)..."
  docker builder prune -f
fi

echo "[docker_cleanup] Done."
