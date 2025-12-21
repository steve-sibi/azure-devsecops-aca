#!/usr/bin/env sh
set -eu

echo "[clamav] updating signatures (initial)..."
freshclam --config-file=/etc/clamav/freshclam.conf || true

echo "[clamav] starting signature updater (daemon)..."
freshclam -d --config-file=/etc/clamav/freshclam.conf || true

echo "[clamav] starting clamd..."
exec clamd -c /etc/clamav/clamd.conf

