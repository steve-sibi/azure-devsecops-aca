#!/usr/bin/env bash
set -euo pipefail

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

echo "[docker_cleanup] Removing only this project's containers, networks, volumes, and images..."
"${compose_cmd[@]}" \
  --project-directory "${project_root}" \
  -f "${compose_file}" \
  down --rmi all --volumes --remove-orphans

echo "[docker_cleanup] Done."
