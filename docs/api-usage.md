# API Usage

This page is the operator reference for the HTTP API and the bundled `aca` CLI.

## Base URLs

- Local: `http://localhost:8000`
- Azure: `https://<api-fqdn>`

## UI and OpenAPI

- `GET /` - dashboard UI
- `GET /file` - file scanner UI
- `GET /docs` - Swagger UI
- `GET /redoc` - ReDoc

## Endpoint reference

### Public and health endpoints

- `GET /` (no auth)
- `GET /file` (no auth)
- `GET /healthz` (no auth)
- `GET /docs` (no auth)
- `GET /redoc` (no auth)

### URL scan and job endpoints

- `POST /scan` (requires API key)
- `GET /jobs?limit=N&status=csv&type=url|file` (requires API key; lists jobs for your key)
- `DELETE /jobs?type=url|file` (requires API key; clears server-side history for your key)
- `GET /scan/{job_id}?view=summary|full` (requires API key)
- `GET /scan/{job_id}/screenshot` (requires API key; only when a screenshot exists)

### Realtime endpoints

- `POST /pubsub/negotiate` (requires API key; body `{"job_id":"<job_id>"}`; Web PubSub run-scoped token)
- `POST /pubsub/negotiate-user` (requires API key; Web PubSub dashboard/user token)
- `GET /events/stream?cursor=$&run_id=<run_id>` (requires API key; Redis Streams NDJSON feed)

`GET /events/stream` returns `501` when the active live-updates backend is not `redis_streams`. In Azure Web PubSub deployments, use the negotiate endpoints instead of the Redis stream endpoint.

### File scan endpoint

- `POST /file/scan` (requires API key; accepts either multipart `file=@...` or multipart `payload=...`)

### Admin API key endpoints

- `GET /admin/api-keys` (admin key)
- `POST /admin/api-keys` (admin key)
- `POST /admin/api-keys/{key_hash}/revoke` (admin key)

## URL scan request contract

`POST /scan` accepts JSON like:

```json
{
  "url": "https://example.com",
  "type": "url",
  "source": "triage",
  "metadata": {
    "ticket": "INC-1234",
    "env": "prod"
  },
  "force": false,
  "visibility": "shared"
}
```

Field behavior:

- `url`: required HTTPS URL. Non-public destinations, localhost, userinfo, and non-443 ports are rejected.
- `type`: keep as `url` or omit it. File scans use `POST /file/scan`.
- `source`: optional free-form label to preserve where the scan request came from.
- `metadata`: optional flat JSON object. String, number, boolean, and `null` values are accepted.
- `force`: when `true`, bypasses URL dedupe and always creates a fresh run.
- `visibility`: `shared` or `private`. `shared` allows cache reuse when URL dedupe is enabled; `private` always creates an isolated run and does not populate the shared cache.

## Scan lifecycle and identifiers

- `job_id`: the request-scoped identifier returned to the caller.
- `run_id`: the underlying execution identifier for the actual scan work.

Fresh vs deduped URL scans:

- Fresh URL scan: new `job_id`, new `run_id`, new pipeline execution.
- Deduped URL scan: new `job_id`, existing `run_id`, existing cached/shared execution reused.
- File scan: synchronous path; `job_id` and `scan_id` refer to the same completed operation.

Typical status flow from `GET /scan/{job_id}`:

- `pending`: no record found yet
- `queued`: accepted by API
- `fetching`: fetcher downloading target
- `queued_scan`: artifact queued for analyzer
- `retrying`: transient retry state
- `blocked`: terminal blocked result, typically due to upstream fetch restrictions or policy checks
- `completed`: terminal success
- `error`: terminal failure

Status writes are monotonic to prevent stale updates from moving state backward.

## Realtime behavior

- The CLI `watch` command first resolves the request `job_id` to its `run_id`, then follows the `run_id`.
- Redis Streams mode returns NDJSON lines shaped like `{"id":"<stream-id>","event":{...}}`.
- Web PubSub mode uses `POST /pubsub/negotiate` or `POST /pubsub/negotiate-user` to obtain a client URL/token.
- When live streaming is unavailable, the dashboard and CLI fall back to polling.

## Helper CLI (`scripts/aca`)

Optional install so you can run `aca` from anywhere:

```bash
pipx install .
# or: python3 -m pip install -e .
```

Common commands:

```bash
./scripts/aca health
./scripts/aca scan-url https://example.com --follow watch
./scripts/aca status <job_id>
./scripts/aca wait <job_id>
./scripts/aca watch <job_id>
./scripts/aca jobs --limit 20
./scripts/aca scan-file ./readme.md --follow watch
./scripts/aca scan-payload "hello world" --follow poll
./scripts/aca screenshot <job_id> --out-dir ./screenshots/
./scripts/aca history --format table --limit 10
./scripts/aca clear-history --yes
./scripts/aca clear-server-history --type url --yes
./scripts/aca doctor
./scripts/aca config show
./scripts/aca env
./scripts/aca --prompt scan-url
./scripts/aca --color never jobs --limit 20
```

Admin key management:

```bash
./scripts/aca admin-mint-key --label analyst-a --read-rpm 600 --write-rpm 120
./scripts/aca admin-list-keys --include-inactive
./scripts/aca admin-revoke-key <key_hash>
```

When to use which command:

- `status`: one-shot request for the current state of a job.
- `wait`: polling until a job reaches a terminal state.
- `watch`: live stream when available, with polling fallback.
- `doctor`: local diagnostics for Python, repo root, `.env`, history path, and resolved auth/base URL.
- `config show`: prints the resolved CLI config, masking secrets by default.
- `env`: resolves Azure context and prints shell exports for `API_URL`, `API_KEY`, `ACA_BASE_URL`, and `ACA_API_KEY`.
- `clear-history`: deletes the local `.aca_api_history` file only.
- `clear-server-history`: calls `DELETE /jobs` for the current API key.

### CLI config precedence and environment resolution

The CLI resolves configuration in this order:

- Base URL: `--base-url`, `ACA_BASE_URL`, `API_URL`, `http://localhost:8000`
- API key: `--api-key`, `ACA_API_KEY`, `API_KEY`, resolved `.env`
- Key header: `--api-key-header`, `ACA_API_KEY_HEADER`, `API_KEY_HEADER`, `X-API-Key`
- `.env` file: `--env-file`, `ACA_ENV_FILE`, current working directory `.env`, then repo `.env`
- History file: `--history`, `ACA_API_HISTORY`, repo `.aca_api_history` in a source checkout, else `~/.aca_api_history`

Azure context helpers:

- `aca az ...` resolves the API FQDN and bootstrap API key via `az`.
- `aca env` uses `ACA_RG`, `ACA_API_APP`, `ACA_KV`, and `ACA_API_KEY_SECRET_NAME`.
- `aca env --unset` prints shell `unset` commands instead of exports.

Compatibility entrypoint:

```bash
./scripts/aca_api.py scan-url https://example.com --wait
```

## curl examples

Submit a URL scan:

```bash
submit="$(curl -sS -X POST "${API_URL}/scan" \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url","source":"manual","visibility":"shared"}')"

JOB_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["job_id"])' <<<"$submit")"
echo "JOB_ID=$JOB_ID"
```

Poll status/result:

```bash
curl -sS "${API_URL}/scan/${JOB_ID}?view=summary" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
curl -sS "${API_URL}/scan/${JOB_ID}?view=full" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
```

Clear server-side history for the current API key:

```bash
curl -sS -X DELETE "${API_URL}/jobs?type=url" \
  -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
```

## File scanning examples (ClamAV)

Upload a file:

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "file=@./readme.md" | python3 -m json.tool
```

Scan plain text payload:

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "payload=hello world" | python3 -m json.tool
```

Scan base64 payload:

```bash
printf 'hello world' | base64 | tr -d '\n' | \
xargs -I{} curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "payload={}" \
  -F "payload_base64=true" | python3 -m json.tool
```

## Ownership and access model

- `GET /jobs` and `DELETE /jobs` are scoped to the calling API key.
- `GET /scan/{job_id}` and `GET /scan/{job_id}/screenshot` enforce owner protection by API key identity.
- `POST /pubsub/negotiate` validates that the referenced job belongs to the caller.
- When `REQUIRE_API_KEY=false`, ownership-sensitive endpoints still require a key so ownership checks can be enforced.

## Result storage notes

- Primary retrieval path is the API (`GET /scan/{job_id}`).
- Azure default backend is Table Storage; local default backend is Redis.
- Azure Table has per-property size limits, so large `details` payloads may be compacted or truncated (`_truncated` marker in `view=full`).

## Related docs

- Runtime and CLI env reference: [`docs/configuration-reference.md`](configuration-reference.md)
- Observability and runbook: [`docs/observability/README.md`](observability/README.md)
- Root onboarding and architecture snapshot: [`readme.md`](../readme.md)
