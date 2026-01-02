# app/clamav/Dockerfile
FROM debian:bookworm-slim

ARG REQUIRE_SIGNATURE_DB=false

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      clamav \
      clamav-daemon \
      clamav-freshclam \
      netcat-openbsd \
      tini \
    && rm -rf /var/lib/apt/lists/*

COPY clamav/clamd.conf /etc/clamav/clamd.conf
COPY clamav/freshclam.conf /etc/clamav/freshclam.conf
COPY clamav/entrypoint.sh /entrypoint.sh
COPY clamav/healthcheck.sh /usr/local/bin/clamav-healthcheck
COPY clamav/freshclam-updater.sh /usr/local/bin/clamav-freshclam-updater

RUN chmod +x /entrypoint.sh \
    /usr/local/bin/clamav-healthcheck \
    /usr/local/bin/clamav-freshclam-updater \
    && if ! id -u clamav >/dev/null 2>&1; then useradd -r -s /usr/sbin/nologin clamav; fi \
    && mkdir -p /var/lib/clamav /var/run/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/lib/clamav /var/run/clamav /var/log/clamav

# Optional: seed signatures at build time (best effort). Runtime bootstrap will handle failures.
RUN set -eux; \
    attempts="${FRESHCLAM_BUILD_ATTEMPTS:-5}"; \
    delay="${FRESHCLAM_BUILD_DELAY_SECONDS:-10}"; \
    i=1; \
    while [ "${i}" -le "${attempts}" ]; do \
      if freshclam --config-file=/etc/clamav/freshclam.conf; then \
        break; \
      fi; \
      echo "freshclam seed failed (${i}/${attempts}); retrying in ${delay}s..."; \
      sleep "${delay}"; \
      i=$((i + 1)); \
    done; \
    ls -lah /var/lib/clamav; \
    found=""; \
    for f in /var/lib/clamav/*.cvd /var/lib/clamav/*.cld /var/lib/clamav/*.cud; do \
      if [ -e "${f}" ]; then found="yes"; break; fi; \
    done; \
    if [ -n "${found}" ]; then \
      echo "freshclam seed: signature database present"; \
    else \
      echo "freshclam seed: signature database missing"; \
      if [ "${REQUIRE_SIGNATURE_DB}" = "true" ]; then \
        echo "ERROR: signature database required but missing. Set REQUIRE_SIGNATURE_DB=false to allow build without signatures." >&2; \
        exit 1; \
      fi; \
    fi; \
    chown -R clamav:clamav /var/lib/clamav

USER clamav

EXPOSE 3310

HEALTHCHECK --interval=10s --timeout=3s --start-period=90s --retries=10 CMD ["/usr/local/bin/clamav-healthcheck"]

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/entrypoint.sh"]
