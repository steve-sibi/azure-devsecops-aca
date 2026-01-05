# Threat model (portfolio notes)

This is a demo project, but it intentionally implements a few “real-world” controls to show security thinking.

## Assets

- API surface (public ingress) and API keys
- Service Bus queue messages (scan jobs)
- Scan results (Table Storage or Redis locally)
- Container images + build pipeline
- ClamAV signature database (Azure Files share in Azure; Docker volume locally)

## Trust boundaries

- Public internet → API (`POST /scan`)
- API → queue backend (Service Bus / Redis)
- Worker → public internet (downloads URLs)
- Worker → ClamAV (local `clamd` process)
- Apps → result store (Table Storage / Redis)
- GitHub Actions → Azure (OIDC) → Terraform / deployments

## Main threats & mitigations

### SSRF / internal network access

- Only `https://` URLs allowed; only port `443`; blocks localhost and non-public IP ranges (`app/common/url_validation.py`).
- Worker re-validates every redirect hop before downloading (defense in depth).

### Malicious content / decompression bombs / large payloads

- Download is streamed with a hard size cap (`MAX_DOWNLOAD_BYTES`) and timeouts (`REQUEST_TIMEOUT`).
- Scanning is done on the downloaded bytes (ClamAV/YARA) without executing content.

### Abuse / DoS of the API

- API key required by default and per-key rate limiting is enforced in the API (`RATE_LIMIT_RPM`).
- Worker is event-driven and scales via KEDA on queue depth in Azure.

### Secrets leakage

- Azure path stores secrets in Key Vault; Container Apps use Key Vault secret references resolved via UAMI (no secrets in the repo).
- Deploy workflow uses GitHub OIDC (no long-lived cloud credentials).

### Supply chain / image vulnerabilities

- CI runs Checkov (IaC) and Trivy (container images) and uploads SARIF to GitHub Security.
- Dockerfiles run as non-root where possible.

## Non-goals (v1)

- Private networking / Private Link / WAF
- Strong multi-tenant auth and per-user API keys
- Sandbox detonation of payloads

