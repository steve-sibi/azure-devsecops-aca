# API Usage

This page is the API/operator reference for submitting scans, checking status, and managing API keys.

## Base URLs

- Local: `http://localhost:8000`
- Azure: `https://<api-fqdn>`

## UI and OpenAPI

- Dashboard: `GET /`
- File scanner UI: `GET /file`
- Swagger UI: `GET /docs`
- ReDoc: `GET /redoc`

## Endpoint reference

### Public/health endpoints

- `GET /` (no auth)
- `GET /healthz` (no auth)
- `GET /file` (no auth)

### Scan endpoints

- `POST /scan` (requires API key)
- `GET /jobs?limit=N&status=csv` (requires API key; lists jobs for your key)
- `GET /scan/{job_id}?view=summary|full` (requires API key)
- `GET /scan/{job_id}/screenshot` (requires API key; only when screenshot exists)

### Realtime negotiation endpoints

- `POST /pubsub/negotiate-user` (requires API key; dashboard path)
- `POST /pubsub/negotiate` (requires API key; run-scoped/testing)

### File scan endpoint

- `POST /file/scan` (requires API key; multipart file or payload)

### Admin API key endpoints

- `GET /admin/api-keys` (admin key)
- `POST /admin/api-keys` (admin key)
- `POST /admin/api-keys/{key_hash}/revoke` (admin key)

## Scan lifecycle and identifiers

- `job_id`: request identifier returned to the caller.
- `run_id`: underlying scan execution id (can be shared by deduped requests).

Typical status flow from `GET /scan/{job_id}`:

- `pending`: no record found yet
- `queued`: accepted by API
- `fetching`: fetcher downloading target
- `queued_scan`: artifact queued for analyzer
- `retrying`: transient retry state
- `completed`: terminal success
- `error`: terminal failure

Status writes are monotonic to prevent stale updates from moving state backward.

## Quick usage examples

### Option A: helper CLI (`scripts/aca_api.py`)

```bash
# Local default: http://localhost:8000
./scripts/aca_api.py scan-url https://example.com --wait
./scripts/aca_api.py jobs --limit 20
./scripts/aca_api.py scan-file ./readme.md
./scripts/aca_api.py screenshot <job_id> --out-dir ./screenshots/

# Admin key management
./scripts/aca_api.py admin-mint-key --label analyst-a --read-rpm 600 --write-rpm 120
./scripts/aca_api.py admin-list-keys --include-inactive
./scripts/aca_api.py admin-revoke-key <key_hash>

# Local client-side history
./scripts/aca_api.py history --limit 10
./scripts/aca_api.py clear-server-history
```

Azure example:

```bash
API_URL="https://<api-fqdn>" API_KEY="..." ./scripts/aca_api.py scan-url https://example.com --wait
```

### Option B: curl

Submit a URL scan:

```bash
submit="$(curl -sS -X POST "${API_URL}/scan" \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url"}')"

JOB_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["job_id"])' <<<"$submit")"
echo "JOB_ID=$JOB_ID"
```

Poll status/result:

```bash
curl -sS "${API_URL}/scan/${JOB_ID}?view=summary" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
curl -sS "${API_URL}/scan/${JOB_ID}?view=full" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
```

## File scanning examples (ClamAV)

Scan uploaded file:

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "file=@./readme.md" | python3 -m json.tool
```

Scan text payload:

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "payload=hello world" | python3 -m json.tool
```

## Ownership and access model

- `GET /jobs` is key-scoped to the caller.
- `GET /scan/{job_id}` and `GET /scan/{job_id}/screenshot` enforce owner protection by API key identity.
- When `REQUIRE_API_KEY=false`, ownership-sensitive endpoints still require a key so ownership can be enforced.

## Result storage notes

- Primary retrieval path is the API (`GET /scan/{job_id}`).
- Azure default backend is Table Storage; local default backend is Redis.
- Azure Table has per-property size limits, so large `details` payloads may be compacted/truncated (`_truncated` marker in `view=full`).

## Related docs

- Runtime/env configuration: [`docs/configuration-reference.md`](configuration-reference.md)
- Observability and runbook: [`docs/observability/README.md`](observability/README.md)
- Root onboarding and architecture snapshot: [`readme.md`](../readme.md)
