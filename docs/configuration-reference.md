# Configuration Reference

This page centralizes the supported public configuration surface for local Docker Compose, Azure Container Apps, and the bundled CLI.

## Source of truth

- Local defaults: [`.env.example`](../.env.example)
- Local wiring: [`docker-compose.yml`](../docker-compose.yml)
- Azure runtime wiring: Terraform under [`infra/`](../infra/) and workflow scripts under [`scripts/gha/`](../scripts/gha/)
- CLI resolution rules: [`src/aca_cli/config.py`](../src/aca_cli/config.py)

## API key bootstrap and admin workflows

### Bootstrap key (Deploy workflow)

The Deploy workflow generates a bootstrap API key and stores it in Key Vault as `ApiKey`.

Example retrieval:

```bash
KV_NAME="<prefix>-kv"
API_KEY="$(az keyvault secret show --vault-name "$KV_NAME" --name ApiKey --query value -o tsv)"
```

If you receive `ForbiddenByRbac`, grant your identity `Key Vault Secrets User` on the vault scope. To manage persistent reader assignments through GitHub Actions and Terraform, use `ACA_KV_SECRET_READER_OBJECT_IDS_JSON`.

### Mint and revoke user keys

Admin endpoints:

- `POST /admin/api-keys`
- `GET /admin/api-keys`
- `POST /admin/api-keys/{key_hash}/revoke`

Admin auth behavior:

- `API_ADMIN_KEY` or `API_ADMIN_KEYS` defines explicit admin keys.
- If not set, the primary runtime `API_KEY` is treated as admin.

Example mint request:

```bash
curl -sS -X POST "${API_URL}/admin/api-keys" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"label":"analyst-a","read_rpm":600,"write_rpm":120}'
```

## Runtime configuration

### Authentication and API keys

- `ACA_API_KEY`: primary local key in `.env`; Docker Compose maps this to runtime `API_KEY`
- `API_KEY`: primary runtime key used by the API container
- `ACA_API_KEYS` / `API_KEYS`: optional comma-separated additional runtime keys
- `API_ADMIN_KEY`, `API_ADMIN_KEYS`: optional explicit admin keys
- `API_KEY_HEADER`: inbound header name expected by the API (default `X-API-Key`)
- `REQUIRE_API_KEY`: enforce auth on protected endpoints
- `API_KEY_STORE_ENABLED`: enable persisted API key storage
- `API_KEY_STORE_PARTITION`: table partition for stored API keys
- `REDIS_API_KEY_PREFIX`, `REDIS_API_KEY_INDEX_KEY`: Redis keys used by the API key store
- `API_KEY_MINT_PREFIX`, `API_KEY_MINT_BYTES`: minted key format and entropy settings

### Rate limiting

- `RATE_LIMIT_RPM`: base fallback rate limit
- `RATE_LIMIT_WRITE_RPM`: write endpoint limit (`POST /scan`, `POST /file/scan`, admin writes)
- `RATE_LIMIT_READ_RPM`: read endpoint limit (`GET /scan/{job_id}`, `GET /jobs`, streaming reads)
- `RATE_LIMIT_WINDOW_SECONDS`: fixed window size

### Queue, results, and shared artifact behavior

- `QUEUE_BACKEND`: `redis` (local) or `servicebus`
- `QUEUE_NAME`, `SCAN_QUEUE_NAME`: fetch and analyzer queue names
- `SERVICEBUS_CONN`: required when `QUEUE_BACKEND=servicebus`
- `RESULT_BACKEND`: `redis` (local) or `table`
- `RESULT_STORE_CONN`: required when `RESULT_BACKEND=table`; also used for Blob screenshots in Azure
- `RESULT_TABLE`: Table Storage table name (default `scanresults`)
- `RESULT_PARTITION`: result partition key (default `scan`)
- `REDIS_URL`: Redis endpoint used by queueing, result storage, and local live updates
- `REDIS_QUEUE_KEY`, `REDIS_SCAN_QUEUE_KEY`: Redis queue keys
- `REDIS_FETCHER_DLQ_KEY`, `REDIS_DLQ_KEY`: Redis dead-letter keys
- `REDIS_RESULT_PREFIX`, `REDIS_RESULT_TTL_SECONDS`: result record prefix and TTL
- `RESULT_DETAILS_MAX_BYTES`: Table Storage `details` truncation guard
- `WORKER_MODE`: selects the shared worker image role, `fetcher` or `analyzer`
- `ARTIFACT_DIR`: shared artifact directory between fetcher and analyzer
- `ARTIFACT_DELETE_ON_SUCCESS`: delete staged artifacts after successful analysis

### Consumer tuning

- `BATCH_SIZE`: messages consumed per batch
- `MAX_WAIT`: max seconds to wait for a batch
- `PREFETCH`: queue prefetch count
- `MAX_RETRIES`: retry count before dead-lettering

### URL dedupe, visibility, and fetch controls

- `URL_DEDUPE_TTL_SECONDS`: reuse completed shared URL scans within this TTL
- `URL_DEDUPE_IN_PROGRESS_TTL_SECONDS`: reuse in-flight shared URL scans within this TTL
- `URL_DEDUPE_SCOPE`: `global` or `apikey`
- `URL_DEDUPE_INDEX_PARTITION`: table partition prefix for dedupe entries
- `REDIS_URL_INDEX_PREFIX`: Redis key prefix for dedupe entries
- `URL_RESULT_VISIBILITY_DEFAULT`: default visibility for URL scans, `shared` or `private`
- `BLOCK_PRIVATE_NETWORKS`: reject localhost and non-public targets
- `REQUEST_TIMEOUT`: outbound fetch timeout in seconds
- `MAX_DOWNLOAD_BYTES`: max bytes fetched before analysis
- `MAX_REDIRECTS`: redirect hop limit

### Live updates and Web PubSub

- `LIVE_UPDATES_BACKEND`: `auto`, `webpubsub`, `redis_streams`, or `none`
- `WEBPUBSUB_CONNECTION_STRING` / `WEBPUBSUB_CONN`: Azure Web PubSub connection string
- `WEBPUBSUB_HUB`: hub name
- `WEBPUBSUB_TOKEN_TTL_MINUTES`: negotiate-token TTL
- `WEBPUBSUB_GROUP_PREFIX`: run-scoped group prefix
- `WEBPUBSUB_USER_GROUP_PREFIX`: user/API-key-scoped group prefix
- `REDIS_LIVE_UPDATES_STREAM_PREFIX`: Redis stream key prefix
- `REDIS_LIVE_UPDATES_MAXLEN`: max stream length
- `REDIS_LIVE_UPDATES_BLOCK_MS`: blocking read timeout in milliseconds

In `auto` mode, the runtime prefers Web PubSub when configured, falls back to Redis Streams when Redis is available, and otherwise disables live updates.

### OpenTelemetry and logging

- `LOG_FORMAT`: `json` for production-style logs or `pretty` for local development
- `OTEL_ENABLED`: explicit telemetry toggle; when unset, App Insights or OTLP exporter config can auto-enable tracing
- `OTEL_TRACES_SAMPLER_RATIO`: trace sampling ratio from `0.0` to `1.0`
- `OTEL_SERVICE_NAMESPACE`: service namespace tag (default `aca-urlscanner`)
- `OTEL_SERVICE_VERSION`: service version tag (default `1.0.0`)
- `OTEL_EXPORTER_OTLP_ENDPOINT`: base OTLP HTTP endpoint
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`: explicit trace endpoint override
- `OTEL_EXPORTER_OTLP_HEADERS`: comma-separated OTLP headers
- `APPINSIGHTS_CONN` / `APPLICATIONINSIGHTS_CONNECTION_STRING`: Azure Monitor exporter connection string

### Screenshot capture

- `CAPTURE_SCREENSHOTS`: enable Playwright screenshot capture in the analyzer
- `SCREENSHOT_FORMAT`: `jpeg` or other supported output type
- `SCREENSHOT_TIMEOUT_SECONDS`: page capture timeout
- `SCREENSHOT_VIEWPORT_WIDTH`, `SCREENSHOT_VIEWPORT_HEIGHT`: viewport dimensions
- `SCREENSHOT_FULL_PAGE`: capture the full page instead of the viewport only
- `SCREENSHOT_JPEG_QUALITY`: JPEG quality from `1` to `100`
- `SCREENSHOT_SETTLE_MS`: wait time after page load before capture
- `SCREENSHOT_LOCALE`: browser locale
- `SCREENSHOT_USER_AGENT`: optional browser user agent override
- `SCREENSHOT_REDIS_PREFIX`: Redis screenshot key prefix
- `SCREENSHOT_CONTAINER`: Blob container name in Azure
- `SCREENSHOT_TTL_SECONDS`: screenshot TTL for Redis-backed storage

### File scanning

- `CLAMAV_HOST`: ClamAV endpoint host (`clamav` in Compose, `127.0.0.1` in ACA sidecar mode)
- `CLAMAV_PORT`: ClamAV TCP port
- `CLAMAV_TIMEOUT_SECONDS`: ClamAV request timeout
- `FILE_SCAN_MAX_BYTES`: max upload or payload size
- `FILE_SCAN_INCLUDE_VERSION`: include ClamAV version metadata in responses

### Web analysis limits and data sources

- `WEB_YARA_RULES_PATH`: custom YARA rules path; defaults to the bundled `app/common/web_yara_rules.yar`
- `WEB_TRACKING_FILTERS_PATH`: custom tracking filter list; defaults to the bundled `app/common/tracking_filters.txt`
- `TLD_EXTRACT_CACHE_DIR`: local cache dir for `tldextract` public suffix parsing
- `WEB_MAX_HTML_BYTES`: max HTML bytes to analyze
- `WEB_MAX_INLINE_SCRIPT_CHARS`: max inline script characters to inspect
- `WEB_MAX_RESOURCES`: max extracted resource URLs
- `WEB_WHOIS_TIMEOUT_SECONDS`: WHOIS and RDAP lookup timeout
- `WEB_MAX_HEADERS`: max captured response headers
- `WEB_MAX_HEADER_VALUE_LEN`: max length per captured header value

### Dashboard

- `MAX_DASHBOARD_POLL_SECONDS`: upper bound for dashboard long-poll waits

## CLI configuration and context resolution

### Base URL, auth, and `.env` discovery

- `ACA_BASE_URL` / `API_URL`: default base URL for CLI requests
- `ACA_API_KEY` / `API_KEY`: default API key for the CLI
- `ACA_API_KEY_HEADER` / `API_KEY_HEADER`: override the auth header name the CLI sends
- `ACA_ENV_FILE`: explicit path to the `.env` file the CLI should load
- `ACA_API_HISTORY`: explicit path to the local history file
- `API_FQDN`: optional informational value surfaced by `aca env`

CLI precedence is:

- `--base-url`, then `ACA_BASE_URL`, then `API_URL`
- `--api-key`, then `ACA_API_KEY`, then `API_KEY`, then the resolved `.env`
- `--api-key-header`, then `ACA_API_KEY_HEADER`, then `API_KEY_HEADER`
- `--env-file`, then `ACA_ENV_FILE`, then current working directory `.env`, then repo `.env`

### Azure helper context

These are used by `aca az ...` and `aca env`:

- `ACA_RG`: resource group
- `ACA_API_APP`: API Container App name
- `ACA_KV`: Key Vault name
- `ACA_API_KEY_SECRET_NAME`: Key Vault secret name for the bootstrap API key (default `ApiKey`)

The `aca env` command exports `API_URL`, `API_KEY`, `ACA_BASE_URL`, `ACA_API_KEY`, and when available `API_FQDN`.

## Optional key rotation

To rotate the bootstrap API key managed by Terraform:

```bash
cd infra
terraform apply \
  -replace="random_password.api_key" \
  -var="create_apps=true" \
  -var="image_tag=<tag>"
```

## Intentionally internal variables

Implementation details such as `JOB_INDEX_PARTITION_PREFIX`, `REDIS_JOB_INDEX_ZSET_PREFIX`, and `REDIS_JOB_INDEX_HASH_PREFIX` are intentionally left undocumented here. They are not part of the supported public configuration contract.

## Related docs

- API examples and endpoint reference: [`docs/api-usage.md`](api-usage.md)
- CI/CD behavior and workflow gates: [`docs/cicd-workflows.md`](cicd-workflows.md)
- Local Terraform usage and state notes: [`docs/terraform-local.md`](terraform-local.md)
