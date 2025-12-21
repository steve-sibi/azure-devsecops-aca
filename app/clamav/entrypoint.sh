#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

touch "${LOG_DIR}/clamd.log" "${LOG_DIR}/freshclam.log"

# Stream clamd logs to container stdout so ACA can collect them.
tail -n 0 -F "${LOG_DIR}/clamd.log" 2>/dev/null &

have_db() {
  for f in "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld "${DB_DIR}"/*.cud; do
    if [ -e "${f}" ]; then
      return 0
    fi
  done
  return 1
}

if command -v socat >/dev/null 2>&1; then
  echo "[clamav] starting TCP proxy :3310 -> 127.0.0.1:3311 (keeps ACA startup probe happy)..."
  socat -T 1 TCP-LISTEN:3310,reuseaddr,fork TCP:127.0.0.1:3311 >/dev/null 2>&1 &
  proxy_pid="$!"
  sleep 0.1
  if ! kill -0 "${proxy_pid}" 2>/dev/null; then
    echo "[clamav] ERROR: TCP proxy failed to start."
    exit 1
  fi
else
  echo "[clamav] WARNING: socat not found; TCP ingress/probes may fail."
fi

if ! have_db; then
  echo "[clamav] bootstrapping signatures..."
  attempts="${FRESHCLAM_BOOTSTRAP_ATTEMPTS:-30}"
  delay="${FRESHCLAM_BOOTSTRAP_DELAY_SECONDS:-10}"
  i=1
  while [ "${i}" -le "${attempts}" ]; do
    echo "[clamav] freshclam bootstrap attempt (${i}/${attempts})..."
    freshclam --config-file=/etc/clamav/freshclam.conf 2>&1 | tee -a "${LOG_DIR}/freshclam.log" || true
    if have_db; then
      break
    fi
    echo "[clamav] signature DB still missing; retrying in ${delay}s..."
    sleep "${delay}"
    i=$((i + 1))
  done
fi

if ! have_db; then
  echo "[clamav] ERROR: no signature database found in ${DB_DIR} after bootstrap."
  echo "[clamav] freshclam log tail:"
  tail -n 200 "${LOG_DIR}/freshclam.log" 2>/dev/null || true
  exit 1
fi

echo "[clamav] starting signature updater loop..."
(
  interval="${FRESHCLAM_INTERVAL_SECONDS:-7200}"
  while true; do
    freshclam --config-file=/etc/clamav/freshclam.conf 2>&1 | tee -a "${LOG_DIR}/freshclam.log" || true
    sleep "${interval}"
  done
) &

echo "[clamav] starting clamd..."
exec clamd -c /etc/clamav/clamd.conf
