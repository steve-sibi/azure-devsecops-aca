# app/clamav/Dockerfile
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
      ca-certificates \
      clamav \
      clamav-daemon \
      clamav-freshclam \
      tini \
    && rm -rf /var/lib/apt/lists/*

COPY clamav/freshclam.conf /etc/clamav/freshclam.conf
COPY clamav/clamd.sidecar.conf /etc/clamav/clamd.sidecar.conf
COPY clamav/clamd.compose.conf /etc/clamav/clamd.compose.conf
COPY clamav/freshclam-updater.sh /usr/local/bin/clamav-freshclam-updater

RUN chmod +x /usr/local/bin/clamav-freshclam-updater \
    && if ! id -u clamav >/dev/null 2>&1; then useradd -r -s /usr/sbin/nologin clamav; fi \
    && mkdir -p /var/lib/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/lib/clamav /var/log/clamav

USER clamav

ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/usr/local/bin/clamav-freshclam-updater"]
