#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

touch "${LOG_DIR}/clamd.log" "${LOG_DIR}/freshclam.log"

# Stream ClamAV logs to container stdout so ACA can collect them.
tail -n 0 -F "${LOG_DIR}/freshclam.log" "${LOG_DIR}/clamd.log" 2>/dev/null &

if ! ls "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld >/dev/null 2>&1; then
  echo "[clamav] ERROR: no signature database found in ${DB_DIR}. Image build should seed signatures."
  echo "[clamav] Hint: check Docker build logs for the freshclam seed step."
  exit 1
fi

echo "[clamav] starting signature updater loop..."
(
  interval="${FRESHCLAM_INTERVAL_SECONDS:-7200}"
  while true; do
    freshclam --config-file=/etc/clamav/freshclam.conf >> "${LOG_DIR}/freshclam.log" 2>&1 || true
    sleep "${interval}"
  done
) &

echo "[clamav] starting clamd..."
exec clamd -c /etc/clamav/clamd.conf
