#!/usr/bin/env sh
set -eu

MODE="$(printf '%s' "${WORKER_MODE:-analyzer}" | tr '[:upper:]' '[:lower:]')"
ART_DIR="${ARTIFACT_DIR:-/artifacts}"

mkdir -p "${ART_DIR}" 2>/dev/null || true
if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
  chmod 777 "${ART_DIR}" 2>/dev/null || true
fi

case "${MODE}" in
  fetcher)
    echo "[fetcher] starting..."
    exec python -u fetcher.py
    ;;
  analyzer|worker|"")
    echo "[worker] starting analyzer..."
    exec python -u worker.py
    ;;
  *)
    echo "[entrypoint] unknown WORKER_MODE: ${MODE}" >&2
    exit 1
    ;;
esac
