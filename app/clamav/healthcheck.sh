#!/usr/bin/env bash
set -euo pipefail

HOST="${CLAMAV_HEALTH_HOST:-127.0.0.1}"
PORT="${CLAMAV_HEALTH_PORT:-3310}"
TIMEOUT_SECONDS="${CLAMAV_HEALTH_TIMEOUT_SECONDS:-2}"

exec 3<>"/dev/tcp/${HOST}/${PORT}"
printf 'PING\n' >&3
IFS= read -r -t "${TIMEOUT_SECONDS}" RESP <&3
RESP="${RESP//$'\r'/}"
RESP="${RESP//$'\n'/}"

[[ "${RESP}" == "PONG" ]]
