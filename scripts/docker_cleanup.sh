#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# docker_cleanup.sh — Tear down project Docker resources safely.
#
# Usage:
#   scripts/docker_cleanup.sh [--keep-images] [--prune-volumes]
#
# Flags:
#   --keep-images     Stop containers and remove volumes/networks but keep
#                     built images (faster restart on next `docker compose up`).
#   --prune-volumes   Also remove any remaining dangling volumes belonging
#                     to this Compose project (anonymous/orphaned volumes).
#
# Environment variables:
#   PRUNE_BUILD_CACHE=1    Also prune the Docker build cache after teardown.
#   PRUNE_VOLUMES=1        Same as --prune-volumes.
# ---------------------------------------------------------------------------

usage() {
  cat <<'EOF'
Usage:
  scripts/docker_cleanup.sh [--keep-images] [--prune-volumes]

Flags:
  --keep-images     Stop containers and remove volumes/networks but keep built images.
  --prune-volumes   Remove dangling project-scoped volumes after teardown.

Environment variables:
  PRUNE_BUILD_CACHE=1    Also prune the Docker build cache after teardown.
  PRUNE_VOLUMES=1        Same as --prune-volumes.
EOF
}

keep_images=false
prune_volumes=false
for arg in "$@"; do
  case "${arg}" in
    --keep-images) keep_images=true ;;
    --prune-volumes) prune_volumes=true ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown flag: ${arg}" >&2
      exit 1
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable (is it running?)" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  compose_cmd=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  compose_cmd=(docker-compose)
else
  echo "docker compose not found (install Docker Compose v2 or docker-compose)" >&2
  exit 1
fi

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="${project_root}/docker-compose.yml"

if [[ ! -f "${compose_file}" ]]; then
  echo "compose file not found at ${compose_file}" >&2
  exit 1
fi

# Build the `down` arguments.
down_args=(--volumes --remove-orphans)
if [[ "${keep_images}" == "false" ]]; then
  down_args+=(--rmi all)
fi

# Include the observability profile so jaeger containers/images are also
# cleaned up regardless of whether the profile was active at start time.
log_suffix=""
if [[ "${keep_images}" == "true" ]]; then
  log_suffix=" (keeping images)"
fi
echo "[docker_cleanup] Removing project containers, networks, volumes${log_suffix}..."
"${compose_cmd[@]}" \
  --project-directory "${project_root}" \
  -f "${compose_file}" \
  --profile observability \
  down "${down_args[@]}"

# Remove any remaining dangling volumes scoped to this Compose project.
# Docker Compose labels every volume with com.docker.compose.project, so
# we filter on that to avoid touching volumes from other projects.
if [[ "${prune_volumes}" == "true" || "${PRUNE_VOLUMES:-0}" == "1" ]]; then
  project_name="${COMPOSE_PROJECT_NAME:-$(basename "${project_root}")}"
  echo "[docker_cleanup] Removing dangling volumes for project '${project_name}'..."
  # shellcheck disable=SC2046
  docker volume rm \
    $(docker volume ls -q --filter "label=com.docker.compose.project=${project_name}" --filter dangling=true 2>/dev/null) \
    2>/dev/null || true
fi

# Optional build-cache prune (opt-in via environment variable).
if [[ "${PRUNE_BUILD_CACHE:-0}" == "1" ]]; then
  echo "[docker_cleanup] Pruning Docker build cache..."
  docker builder prune -f
fi

echo "[docker_cleanup] Done."
