#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

touch "${LOG_DIR}/clamd.log" "${LOG_DIR}/freshclam.log"

# Stream ClamAV logs to container stdout so ACA can collect them.
tail -n 0 -F "${LOG_DIR}/freshclam.log" "${LOG_DIR}/clamd.log" 2>/dev/null &

listener_pid=""
if command -v socat >/dev/null 2>&1; then
  echo "[clamav] opening temporary TCP listener on :3310 (helps ACA startup probe during bootstrap)..."
  socat -T 1 TCP-LISTEN:3310,reuseaddr,fork EXEC:'/bin/true' >/dev/null 2>&1 &
  listener_pid="$!"
fi

if ! ls "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld >/dev/null 2>&1; then
  echo "[clamav] bootstrapping signatures..."
  attempts="${FRESHCLAM_BOOTSTRAP_ATTEMPTS:-30}"
  delay="${FRESHCLAM_BOOTSTRAP_DELAY_SECONDS:-10}"
  i=1
  while [ "${i}" -le "${attempts}" ]; do
    if freshclam --config-file=/etc/clamav/freshclam.conf >> "${LOG_DIR}/freshclam.log" 2>&1; then
      break
    fi
    echo "[clamav] freshclam bootstrap failed (${i}/${attempts}); retrying in ${delay}s..."
    sleep "${delay}"
    i=$((i + 1))
  done
fi

if ! ls "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld >/dev/null 2>&1; then
  echo "[clamav] ERROR: no signature database found in ${DB_DIR} after bootstrap."
  exit 1
fi

if [ -n "${listener_pid}" ]; then
  echo "[clamav] stopping temporary TCP listener..."
  kill "${listener_pid}" 2>/dev/null || true
  wait "${listener_pid}" 2>/dev/null || true
  listener_pid=""
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
