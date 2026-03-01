# Configuration Reference

This page centralizes runtime configuration for local Docker Compose and Azure Container Apps.

## Source of truth

- Local defaults: [`.env.example`](../.env.example)
- Local wiring: [`docker-compose.yml`](../docker-compose.yml)
- Azure runtime wiring: Terraform ([`infra/`](../infra/)) and workflow scripts ([`scripts/gha/`](../scripts/gha/))

## API key bootstrap and admin workflows

### Bootstrap key (Deploy workflow)

The Deploy workflow generates a bootstrap API key and stores it in Key Vault as `ApiKey`.

Example retrieval:

```bash
KV_NAME="<prefix>-kv"
API_KEY="$(az keyvault secret show --vault-name "$KV_NAME" --name ApiKey --query value -o tsv)"
```

If you receive `ForbiddenByRbac`, grant your identity `Key Vault Secrets User` on the vault scope (or configure persistent reader assignments through Terraform via `ACA_KV_SECRET_READER_OBJECT_IDS_JSON`).

### Mint/revoke user keys (admin)

Admin endpoints:

- `POST /admin/api-keys`
- `GET /admin/api-keys`
- `POST /admin/api-keys/{key_hash}/revoke`

Admin auth behavior:

- `API_ADMIN_KEY` or `API_ADMIN_KEYS` defines explicit admin keys.
- If not set, `API_KEY` is treated as admin.

Example mint request:

```bash
curl -sS -X POST "${API_URL}/admin/api-keys" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"label":"analyst-a","read_rpm":600,"write_rpm":120}'
```

## Key local variables (`.env`)

### Authentication and API keys

- `ACA_API_KEY`: primary local key injected to API container as `API_KEY`
- `ACA_API_KEYS`: optional comma-separated additional keys
- `API_ADMIN_KEY`, `API_ADMIN_KEYS`: optional admin keys
- `REQUIRE_API_KEY`: enforce auth on protected endpoints
- `API_KEY_STORE_ENABLED`: enable persisted key store
- `API_KEY_STORE_PARTITION`: key-store partition (table backend)
- `REDIS_API_KEY_PREFIX`, `REDIS_API_KEY_INDEX_KEY`: key-store Redis keys
- `API_KEY_MINT_PREFIX`, `API_KEY_MINT_BYTES`: minted key format

### Rate limiting

- `RATE_LIMIT_RPM`: base fallback rate limit
- `RATE_LIMIT_WRITE_RPM`: write endpoint limit (`POST /scan`, etc.)
- `RATE_LIMIT_READ_RPM`: read endpoint limit (`GET /scan/{job_id}`, `GET /jobs`, etc.)
- `RATE_LIMIT_WINDOW_SECONDS`: limit window

### Queue, result backend, and storage behavior

- `QUEUE_BACKEND`: `redis` (local) or Service Bus wiring in Azure
- `RESULT_BACKEND`: `redis` (local) or table backend in Azure
- `QUEUE_NAME`, `SCAN_QUEUE_NAME`
- `REDIS_URL`
- `REDIS_QUEUE_KEY`, `REDIS_SCAN_QUEUE_KEY`
- `REDIS_FETCHER_DLQ_KEY`, `REDIS_DLQ_KEY`
- `REDIS_RESULT_PREFIX`, `REDIS_RESULT_TTL_SECONDS`
- `RESULT_DETAILS_MAX_BYTES`: details truncation guard (table backend)

### URL dedupe and visibility

- `URL_DEDUPE_TTL_SECONDS`
- `URL_DEDUPE_IN_PROGRESS_TTL_SECONDS`
- `URL_DEDUPE_SCOPE`: `global` or `apikey`
- `URL_DEDUPE_INDEX_PARTITION`
- `REDIS_URL_INDEX_PREFIX`
- `URL_RESULT_VISIBILITY_DEFAULT`: `shared` or `private`

### SSRF and fetch controls

- `BLOCK_PRIVATE_NETWORKS`
- `REQUEST_TIMEOUT`
- `MAX_DOWNLOAD_BYTES`
- `MAX_REDIRECTS`

### Realtime updates (Web PubSub)

- `WEBPUBSUB_CONNECTION_STRING`
- `WEBPUBSUB_HUB`
- `WEBPUBSUB_TOKEN_TTL_MINUTES`
- `WEBPUBSUB_GROUP_PREFIX`
- `WEBPUBSUB_USER_GROUP_PREFIX`

When `WEBPUBSUB_CONNECTION_STRING` is unset, dashboard falls back to polling.

### OpenTelemetry and tracing

- `OTEL_ENABLED`
- `OTEL_TRACES_SAMPLER_RATIO`
- `OTEL_SERVICE_NAMESPACE`
- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
- `OTEL_EXPORTER_OTLP_HEADERS`
- `APPINSIGHTS_CONN` / `APPLICATIONINSIGHTS_CONNECTION_STRING`

### Screenshot capture

- `CAPTURE_SCREENSHOTS`
- `SCREENSHOT_FORMAT`
- `SCREENSHOT_TIMEOUT_SECONDS`
- `SCREENSHOT_VIEWPORT_WIDTH`, `SCREENSHOT_VIEWPORT_HEIGHT`
- `SCREENSHOT_FULL_PAGE`
- `SCREENSHOT_JPEG_QUALITY`
- `SCREENSHOT_SETTLE_MS`
- `SCREENSHOT_LOCALE`
- `SCREENSHOT_USER_AGENT`
- `SCREENSHOT_REDIS_PREFIX`
- `SCREENSHOT_CONTAINER`
- `SCREENSHOT_TTL_SECONDS`

### File scanning (ClamAV)

- `CLAMAV_HOST` (`clamav` in Compose, `127.0.0.1` in ACA sidecar mode)
- `CLAMAV_PORT`
- `CLAMAV_TIMEOUT_SECONDS`
- `FILE_SCAN_MAX_BYTES`
- `FILE_SCAN_INCLUDE_VERSION`

### Optional key rotation (Terraform)

```bash
cd infra
terraform apply \
  -replace="random_password.api_key" \
  -var="create_apps=true" \
  -var="image_tag=<tag>"
```

### Logging

- `LOG_FORMAT`: log output format — `json` (default, production) or `pretty` (local dev)

### Live updates

- `LIVE_UPDATES_BACKEND`: realtime backend selection — `auto` (default), `webpubsub`, `redis_streams`, or `none`. In `auto` mode, the system prefers Web PubSub if configured, falls back to Redis Streams if Redis is available, otherwise disables.
- `REDIS_LIVE_UPDATES_STREAM_PREFIX`: key prefix for per-key event streams (default `events:apikey:`)
- `REDIS_LIVE_UPDATES_MAXLEN`: max entries per stream (default `10000`)
- `REDIS_LIVE_UPDATES_BLOCK_MS`: blocking read timeout in milliseconds (default `30000`)

### Consumer tuning

- `BATCH_SIZE`: messages per consumer batch (default `10`)
- `MAX_WAIT`: max seconds to wait for a batch (default `5`)
- `PREFETCH`: prefetch count for queue consumer (default `20`)
- `MAX_RETRIES`: max retry attempts before dead-lettering (default `5`)

### Worker internals

- `WORKER_MODE`: selects worker behavior — `fetcher` (URL download stage) or `analyzer` (scan/analysis stage). Both share the same Docker image (`Dockerfile.sidecar`).
- `ARTIFACT_DIR`: directory for shared artifacts between fetcher and worker (default `/artifacts`)
- `ARTIFACT_DELETE_ON_SUCCESS`: remove artifact files after successful analysis (default `false`)

### Web analysis limits

- `WEB_YARA_RULES_PATH`: path to custom YARA rules file for web content analysis. Defaults to the bundled `app/common/web_yara_rules.yar` which detects suspicious JS, fingerprinting, eval/innerHTML usage, and inline trackers.
- `WEB_MAX_HTML_BYTES`: max HTML bytes to analyze
- `WEB_MAX_INLINE_SCRIPT_CHARS`: max inline script characters to extract
- `WEB_MAX_RESOURCES`: max external resource URLs to extract
- `WEB_WHOIS_TIMEOUT_SECONDS`: WHOIS lookup timeout (default `6.0`)
- `WEB_MAX_HEADERS`: max HTTP response headers to include in results
- `WEB_MAX_HEADER_VALUE_LEN`: max length per header value

### Dashboard

- `MAX_DASHBOARD_POLL_SECONDS`: max polling timeout for dashboard long-poll requests (default `180`)

### OpenTelemetry (additional)

- `OTEL_SERVICE_VERSION`: service version reported in traces (default `1.0.0`)

## Related docs

- CI/CD behavior and workflow gates: [`docs/cicd-workflows.md`](cicd-workflows.md)
- API examples and endpoint reference: [`docs/api-usage.md`](api-usage.md)
- Local Terraform usage and state notes: [`docs/terraform-local.md`](terraform-local.md)
