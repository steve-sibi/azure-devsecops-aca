# app/clamav/Dockerfile
FROM debian:bookworm-slim

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
      tini \
    && rm -rf /var/lib/apt/lists/*

COPY clamd.conf /etc/clamav/clamd.conf
COPY freshclam.conf /etc/clamav/freshclam.conf
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh \
    && if ! id -u clamav >/dev/null 2>&1; then useradd -r -s /usr/sbin/nologin clamav; fi \
    && mkdir -p /var/lib/clamav /var/run/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/lib/clamav /var/run/clamav /var/log/clamav

# Seed signatures at build time so clamd can start immediately in ACA.
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
    ls /var/lib/clamav/*.cvd /var/lib/clamav/*.cld >/dev/null 2>&1; \
    chown -R clamav:clamav /var/lib/clamav

USER clamav

EXPOSE 3310

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/entrypoint.sh"]
