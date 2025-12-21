#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

touch "${LOG_DIR}/clamd.log" "${LOG_DIR}/freshclam.log"

# Stream ClamAV logs to container stdout so ACA can collect them.
tail -n 0 -F "${LOG_DIR}/freshclam.log" "${LOG_DIR}/clamd.log" 2>/dev/null &

if ! ls "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld >/dev/null 2>&1; then
  echo "[clamav] bootstrapping signatures..."
  attempts="${FRESHCLAM_BOOTSTRAP_ATTEMPTS:-30}"
  delay="${FRESHCLAM_BOOTSTRAP_DELAY_SECONDS:-10}"
  i=1
  while [ "${i}" -le "${attempts}" ]; do
    if freshclam --config-file=/etc/clamav/freshclam.conf; then
      break
    fi
    echo "[clamav] freshclam bootstrap failed (${i}/${attempts}); retrying in ${delay}s..."
    sleep "${delay}"
    i=$((i + 1))
  done
fi

echo "[clamav] starting signature updater (daemon)..."
(freshclam -d --config-file=/etc/clamav/freshclam.conf || true) &

echo "[clamav] starting clamd..."
exec clamd -c /etc/clamav/clamd.conf
