#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

mkdir -p "${LOG_DIR}"
touch "${LOG_DIR}/clamd.log"

# Stream clamd logs to container stdout.
tail -n 0 -F "${LOG_DIR}/clamd.log" 2>/dev/null &

have_db() {
  for f in "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld "${DB_DIR}"/*.cud; do
    if [ -e "${f}" ]; then
      return 0
    fi
  done
  return 1
}

if ! have_db; then
  echo "[worker/clamav] waiting for signatures in ${DB_DIR}..."
  attempts="${CLAMAV_DB_WAIT_ATTEMPTS:-120}"
  delay="${CLAMAV_DB_WAIT_DELAY_SECONDS:-5}"
  i=1
  while [ "${i}" -le "${attempts}" ]; do
    if have_db; then
      break
    fi
    sleep "${delay}"
    i=$((i + 1))
  done
fi

if ! have_db; then
  echo "[worker/clamav] ERROR: no signature database found in ${DB_DIR}."
  exit 1
fi

echo "[worker/clamav] starting clamd..."
clamd -c /etc/clamav/clamd.conf &
clamd_pid="$!"

echo "[worker/clamav] waiting for clamd PING/PONG..."
attempts="${CLAMAV_READY_ATTEMPTS:-60}"
delay="${CLAMAV_READY_DELAY_SECONDS:-1}"
i=1
while [ "${i}" -le "${attempts}" ]; do
  if /usr/local/bin/clamav-healthcheck; then
    break
  fi
  sleep "${delay}"
  i=$((i + 1))
done

if ! /usr/local/bin/clamav-healthcheck; then
  echo "[worker/clamav] ERROR: clamd is not responding."
  kill "${clamd_pid}" 2>/dev/null || true
  exit 1
fi

echo "[worker] starting worker..."
exec python -u worker.py
