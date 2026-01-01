#!/usr/bin/env sh
set -eu

HOST="${CLAMAV_HEALTH_HOST:-127.0.0.1}"
PORT="${CLAMAV_HEALTH_PORT:-3310}"
TIMEOUT_SECONDS="${CLAMAV_HEALTH_TIMEOUT_SECONDS:-2}"

resp="$(printf 'PING\n' | nc -N -w "${TIMEOUT_SECONDS}" "${HOST}" "${PORT}" 2>/dev/null || true)"
resp="$(printf '%s' "${resp}" | tr -d '\r\n')"

[ "${resp}" = "PONG" ]
