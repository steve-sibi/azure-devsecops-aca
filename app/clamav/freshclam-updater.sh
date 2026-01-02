#!/usr/bin/env sh
set -eu

LOG_DIR="/var/log/clamav"
DB_DIR="/var/lib/clamav"

mkdir -p "${LOG_DIR}" "${DB_DIR}"
touch "${LOG_DIR}/freshclam.log"

have_db() {
  for f in "${DB_DIR}"/*.cvd "${DB_DIR}"/*.cld "${DB_DIR}"/*.cud; do
    if [ -e "${f}" ]; then
      return 0
    fi
  done
  return 1
}

if [ "$(id -u)" = "0" ]; then
  chown -R clamav:clamav "${DB_DIR}" "${LOG_DIR}" || true
fi

if ! have_db; then
  echo "[clamav-updater] bootstrapping signatures..."
  attempts="${FRESHCLAM_BOOTSTRAP_ATTEMPTS:-30}"
  delay="${FRESHCLAM_BOOTSTRAP_DELAY_SECONDS:-10}"
  i=1
  while [ "${i}" -le "${attempts}" ]; do
    echo "[clamav-updater] freshclam bootstrap attempt (${i}/${attempts})..."
    freshclam --config-file=/etc/clamav/freshclam.conf 2>&1 | tee -a "${LOG_DIR}/freshclam.log" || true
    if have_db; then
      break
    fi
    echo "[clamav-updater] signature DB still missing; retrying in ${delay}s..."
    sleep "${delay}"
    i=$((i + 1))
  done
fi

if ! have_db; then
  echo "[clamav-updater] ERROR: no signature database found in ${DB_DIR} after bootstrap."
  echo "[clamav-updater] freshclam log tail:"
  tail -n 200 "${LOG_DIR}/freshclam.log" 2>/dev/null || true
  exit 1
fi

echo "[clamav-updater] starting update loop..."
interval="${FRESHCLAM_INTERVAL_SECONDS:-7200}"
while true; do
  freshclam --config-file=/etc/clamav/freshclam.conf 2>&1 | tee -a "${LOG_DIR}/freshclam.log" || true
  sleep "${interval}"
done
