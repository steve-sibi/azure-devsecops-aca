# URL + File Scanner Pipeline on Azure (ACA)

[![CI](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/ci.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/ci.yml)
[![Deploy](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/deploy.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/deploy.yml)
[![App Deploy (CD)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/app-deploy.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/app-deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776ab.svg)](https://www.python.org/)
[![Terraform 1.6+](https://img.shields.io/badge/Terraform-1.6+-844fba.svg)](https://www.terraform.io/)
[![Azure Container Apps](https://img.shields.io/badge/Azure-Container%20Apps-0078d4.svg)](https://azure.microsoft.com/en-us/products/container-apps)

End-to-end, cloud-native **URL scanning pipeline** (two-stage fetch + analyze) plus optional **file scanning** on **Azure Container Apps (ACA)** using **Terraform** and **GitHub Actions (OIDC)**.

What this project demonstrates:

- **DevSecOps approach**: Focused on implementing infrastructure in an automated, shift-left manner
- **Secure API surface**: `X-API-Key` auth + per-key rate limiting + SSRF protections + URL canonicalization
- **Async job processing**: API enqueues scan jobs to **Service Bus** (or Redis locally), fetcher downloads artifacts, worker analyzes (KEDA autoscaling on Azure)
- **URL dedupe/cache**: Shared URL scan cache with configurable TTLs to avoid redundant work (based on canonical URLs)
- **Results + audit trail**: scan results stored in **Azure Table Storage** (`scanresults`) (or Redis locally); optional screenshots served at `GET /scan/{job_id}/screenshot`
- **Per-user job history**: API key-based job isolation with `GET /jobs` for viewing your submission history
- **Realtime status updates**: optional **Azure Web PubSub** integration for dashboard live updates (with polling fallback)
- **File scanning**: `/file/scan` scans an uploaded file/payload via **ClamAV** (sidecar in ACA; service in Docker Compose)
- **Web content analysis**: HTML parsing, resource classification, tracking detection (adblock filters), security headers, cookies, YARA rules, WHOIS/RDAP lookups
- **Structured logging**: JSON logs with correlation IDs for distributed tracing (Azure Monitor/App Insights compatible)
- **DevSecOps CI/CD**: Ruff/pytest + Terraform validate + Hadolint + Checkov + Trivy (SARIF uploads)
- **Cloud-native secrets**: **Key Vault** stores secrets, resolved by **UAMI** at deploy/runtime
- **Built-in UI**: dashboard at `/`, file scanner UI at `/file`, Swagger at `/docs`

> Shareable, reproducible, “nuke-and-recreate” project or starter for lightweight production.

## Contents
- [0) Quick demo](#0-quick-demo-local-2-minutes)
- [1) Architecture](#1-architecture)
- [2) What Terraform Deploys](#2-what-terraform-deploys)
- [3) Prerequisites](#3-prerequisites)
- [4) Repository layout](#4-repository-layout)
- [5) CI/CD workflow](#5-cicd-workflow)
- [6) First-run values (env)](#6-first-run-values-env)
- [7) Running it](#7-running-it)
- [8) Using the API](#8-using-the-api)
- [9) Observability & troubleshooting](#9-observability--troubleshooting)
- [10) Working with Terraform locally](#10-working-with-terraform-locally)
- [11) Costs & clean-up](#11-costs--clean-up)
- [12) Security notes](#12-security-notes)
- [13) How the app code works (quick tour)](#13-how-the-app-code-works-quick-tour)
- [14) Extending this project (future work)](#14-extending-this-project-future-work)
- [15) FAQ](#15-faq)

## 0) Quick demo (local, ~2 minutes)

Prereqs: Docker Desktop (or any Docker engine with Compose).

```bash
cp .env.example .env
docker compose up --build
```

In another terminal:

```bash
API_KEY=local-dev-key

curl -sS http://localhost:8000/healthz

SUBMIT="$(curl -sS -X POST http://localhost:8000/scan \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url"}')"
echo "${SUBMIT}"

JOB_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("job_id") or "")' <<<"${SUBMIT}")"
curl -sS "http://localhost:8000/scan/${JOB_ID}" -H "X-API-Key: ${API_KEY}"
```

SSRF protections (expected `400`):

```bash
curl -i -sS -X POST http://localhost:8000/scan \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://127.0.0.1","type":"url"}'
```

> Note: URL scanning runs built-in web analysis only. The dashboard provides external links to URLScan.io and VirusTotal for optional follow-up checks.
>
> Optional: screenshots are disabled by default in `docker-compose.yml` (`CAPTURE_SCREENSHOTS=false`). Set `CAPTURE_SCREENSHOTS=true` (and restart) to have the worker capture a first-party browser screenshot and show it in the dashboard (served from `GET /scan/{job_id}/screenshot` with the same API key auth). In Azure, this is controlled by the Terraform var `capture_screenshots` (default `true`).

## 1) Architecture

*High-Level Overview*

```
            ┌──────────────┐       (SAS conn string stored in Key Vault)
HTTP POST ─►│  FastAPI     │ ───────────────────────────────────────────────────┐
            │  /scan       │                                                    │
            └──────┬───────┘                                                    │
                   │ (send message)                                             │
                   ▼                                                            │
           ┌────────────────┐         KV ref ┌────────────────────┐             │
           │ Service Bus    │◄───────────────│ Azure Key Vault    │             │
           │ Queue (tasks)  │                │ secrets: sb-* + ApiKey           │
           └────────┬───────┘                └────────────────────┘             │
                    │ (scale trigger)                                           │
                    │ via KEDA                                                  │
                    ▼                                                           │
           ┌────────────────────┐         UAMI + KV ref                         │
           │ Fetcher (Container │◄──────────────────────────────────────────────┘
           │ Apps, min=0)       │
           └────────┬───────────┘
                    │ (download + store artifact)
                    ▼
          ┌─────────────────────┐
          │ Azure Files share   │
          │ (<prefix>-artifacts)│
          └────────┬────────────┘
                   │ (enqueue scan job)
                   ▼
          ┌─────────────────────┐
          │ Service Bus Queue   │
          │ (<tasks>-scan)      │
          └────────┬────────────┘
                   │ (scale trigger via KEDA)
                   ▼
          ┌────────────────────┐
          │ Worker (Container  │
          │ Apps, min=0)       │
          └────────┬───────────┘
                   │    (analyze artifact bytes:
                   ▼    reputation + content)
            ┌────────────────┐
            │ Azure Table    │
            │ scanresults    │
            └───────┬────────┘
                    │
                    ▼    (logs/metrics)
         ┌─────────────────────┐   
         │    Log Analytics    │  (optional traces to App Insights)
         └─────────────────────┘                   
```
*Runtime Sequence*

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant API as FastAPI (Container App)
  participant SB as Service Bus Queue (tasks)
  participant KEDA as KEDA Scaler
  participant F as Fetcher (Container App)
  participant FS as Azure Files (artifacts)
  participant SB2 as Service Bus Queue (tasks-scan)
  participant W as Worker (Container App)
  participant T as Azure Table Storage (scanresults)
  participant LA as Log Analytics

  Note over API,W: Secrets (Service Bus + ApiKey + results conn) are injected via Key Vault references resolved by the UAMI at deploy time (no runtime KV calls).

  C->>API: POST /scan {url}
  API->>T: Upsert status=queued
  API->>SB: Send message (SAS connection string)

  KEDA->>SB: Poll queue length
  SB-->>KEDA: messageCount
  KEDA-->>F: Scale out replicas (min 0..max 5)

	  F->>SB: Receive messages
	  F->>F: Download (SSRF protected)
	  F->>FS: Write artifact bytes
	  F->>T: Upsert status=queued_scan
	  F->>SB2: Send scan message (artifact ref)
	  F->>SB: Complete message

  KEDA->>SB2: Poll queue length
  SB2-->>KEDA: messageCount
  KEDA-->>W: Scale out replicas (min 0..max 5)

  W->>SB2: Receive messages
  W->>FS: Read artifact bytes
  W->>W: Analyze (reputation + content heuristics)
  W->>T: Upsert status=completed/error
  W->>SB2: Complete message
  W-->>LA: Console logs (processing info)

  C->>API: GET /scan/{job_id}
  API->>T: Read status
  API-->>C: JSON result
```
*Flow*
- Client calls `POST /scan` on the API → message goes to the Service Bus **fetch queue** (`tasks`)
- KEDA scales the **fetcher** based on fetch queue depth; fetcher downloads + writes artifacts to Azure Files
- Fetcher enqueues a second message to the Service Bus **scan queue** (`<tasks>-scan`)
- KEDA scales the **worker** based on scan queue depth; worker analyzes artifact bytes (reputation + content heuristics) and completes messages
- Results are written to **Table Storage** (`scanresults`) and can be fetched via `GET /scan/{job_id}`
- Logs land in **Log Analytics**; optional traces in **App Insights**

*Realtime update path (optional, Web PubSub)*
- API issues request-scoped IDs (`job_id`) and underlying scan-run IDs (`run_id`).
- Worker/fetcher publish status changes to Web PubSub groups:
  - `run:<run_id>` for run-level updates
  - `apikey:<api_key_hash>` for user-scoped updates
- Dashboard negotiates a user-scoped WebSocket (`POST /pubsub/negotiate-user`) and updates all visible jobs for that API key without per-row polling.
- If Web PubSub is unavailable, the dashboard automatically falls back to polling `GET /scan/{job_id}`.


## 2) What Terraform Deploys

- **Resource Group**: `rg-<prefix>` (created by workflow)
    
- **Log Analytics**: `<prefix>-la` (workspace)
    
- **Application Insights**: `<prefix>-appi` (workspace-based)

- **Observability (Terraform-managed)**:
    
    - Log Analytics saved searches for API 5xx, pipeline errors, queue backlog, DLQ growth, and stalled pipeline detection
    - Azure Monitor Action Group (email receivers via `monitor_action_group_email_receivers`)
    - Scheduled Query Alerts (v2) for API errors, pipeline errors, backlog, dead-letter growth, and stalled pipeline
    - Application Insights workbook (toggle via `monitor_workbook_enabled`)
    
- **Key Vault**: `<prefix>-kv` (secrets: Service Bus SAS, scan results conn, API key)
    
- **ACR**: `<prefix>acr`

- **Service Bus**:
    
    - Namespace: `<prefix>-sbns`
        
    - Queue: `tasks` (default; fetch queue)
    - Queue: `<tasks>-scan` (default; scan queue)
        
    - **Queue SAS rules** (least-privilege, queue-scoped):
        
        - Fetch queue (`tasks`): `api-send` (**Send**), `worker-listen` (**Listen**), `scale-manage` (**Manage**)
        - Scan queue (`<tasks>-scan`): `fetcher-send` (**Send**), `worker-scan-listen` (**Listen**), `scale-manage-scan` (**Manage**)

- **Web PubSub**:

    - Service: `<prefix>-wps` (Azure Web PubSub)
    - Hub: configurable (`webpubsub_hub_name`, default `scans`)
    - KV secret: `WebPubSubConn` (primary connection string used by API/fetcher/worker)
            
- **Storage (results)**:
    
    - Account: `<prefix>scan`
        
    - Table: `scanresults` (default)

    - Blob container: `screenshots` (default; configurable via Terraform var `screenshot_container`) for optional screenshots when `capture_screenshots=true`
        
    - KV secret: `ScanResultsConn` (table connection string for API/worker)
        
- **UAMI**: `<prefix>-uami` (granted ACR pull + KV secret read)
    
- **ACA Environment**: `<prefix>-acaenv`
    
- **Container Apps**:
    
    - `<prefix>-api` (FastAPI; ingress on `:8000`; includes a `clamav` sidecar container for `/file/scan`)
        
    - `<prefix>-fetcher` (KEDA scale rule on the fetch queue; min=0, max=5; downloads + writes artifacts; `WORKER_MODE=fetcher`)

    - `<prefix>-worker` (KEDA scale rule on the scan queue; min=0, max=5; analyzes artifact bytes; `WORKER_MODE=analyzer`)

    - Azure Files share: `<prefix>-artifacts` (fetched artifacts for scan handoff)

> The fetcher and worker run the same Docker image (`app/worker/Dockerfile.sidecar`); the entrypoint selects the mode via `WORKER_MODE`.

**Secrets (via Key Vault references, resolved by ACA):**

- API container env `SERVICEBUS_CONN` ← KV secret **(send to fetch queue)**, secretRef e.g. `sb-send`
- API container env `API_KEY` ← KV secret `ApiKey`, secretRef `api-key`
    
- Fetcher container env `SERVICEBUS_CONN` ← KV secret **(listen to fetch queue)**, secretRef e.g. `sb-listen`
- Fetcher container env `SERVICEBUS_SCAN_CONN` ← KV secret **(send to scan queue)**, secretRef e.g. `sb-scan-send`
    
- Worker container env `SERVICEBUS_CONN` ← KV secret **(listen to scan queue)**, secretRef e.g. `sb-scan-listen`
    
- KEDA scale rule auth uses KV secrets **(manage)**: `sb-manage` (fetch queue) + `sb-scan-manage` (scan queue) (not injected into container)
    
- API/worker env `RESULT_STORE_CONN` and `RESULT_TABLE` for scan status storage (from Storage Table)
- API/fetcher/worker env `WEBPUBSUB_CONNECTION_STRING` + `WEBPUBSUB_HUB` for realtime update publish/subscribe token negotiation

> The apps use connection strings for Service Bus auth in both Azure and local workflows.

## 3) Prerequisites

- **GitHub OIDC** wired to your Azure tenant/subscription (no secrets).
    
- **Repo secrets**:
    
    - `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
        
- **One-time role assignments** (run by a Subscription Owner):
    
    - Assign your GitHub OIDC app **Contributor** + **User Access Administrator** at the **subscription** scope.  
        This allows the workflows to **create the RG**, assign RG-scoped roles, and grant the **Storage Blob Data Contributor** role on the Terraform state account.
        

> The workflows create the **RG, ACR, KV, LA, TF state storage** if missing, and recover a **soft-deleted KV** automatically.

### One-time Azure provider registration (required for Web PubSub)

Web PubSub creation fails with `MissingSubscriptionRegistration` unless the provider is registered in your subscription.

```bash
az account show --query "{name:name,id:id,tenantId:tenantId}" -o table
az provider register --namespace Microsoft.SignalRService --wait
az provider show --namespace Microsoft.SignalRService --query registrationState -o tsv
```

Expected state: `Registered`.

### One-time setup (Azure + GitHub OIDC checklist)

1. Create an **Entra ID App Registration** (service principal) for GitHub Actions.
2. Add a **Federated Credential** to the app registration (no client secret):
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:<owner>/<repo>:ref:refs/heads/main`
   - Audience: `api://AzureADTokenExchange`
3. Assign the service principal:
   - `Contributor` (subscription scope)
   - `User Access Administrator` (subscription scope; needed so the workflow can create RBAC assignments for the TF state data plane)
4. Add GitHub repo secrets:
   - `AZURE_CLIENT_ID` (app/client id)
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`

## 4) Repository layout
```
azure-devsecops-aca/
├─ .github/
│  ├─ workflows/
│  │  ├─ ci.yml              # lint/test + security scans
│  │  ├─ deploy.yml          # infra bootstrap + build/push + deploy (infra-only mode supported)
│  │  ├─ app-deploy.yml      # fast container rollout to existing ACA apps
│  │  ├─ destroy.yml         # terraform destroy (+ RG delete)
│  │  └─ keda-scale-test.yml # validate KEDA scale-out
│  └─ scripts/
│     └─ format_aca_logs.py
├─ scripts/
│  ├─ gha/                # workflow bash logic (for readability)
│  │  ├─ deploy_infra_bootstrap.sh
│  │  ├─ deploy_create_apps_and_test.sh
│  │  └─ destroy.sh
│  ├─ aca_api.py          # helper CLI for calling the API
│  ├─ docker_cleanup.sh
│  ├─ keda_scale_test.sh
│  └─ send_servicebus_messages.py
├─ app/
│  ├─ common/             # shared helpers (validation + result storage)
│  │  ├─ tracking_filters.txt
│  │  └─ web_yara_rules.yar
│  ├─ api/                # FastAPI producer
│  │  ├─ Dockerfile
│  │  ├─ dashboard.html
│  │  ├─ file_scanner.html
│  │  ├─ main.py
│  │  └─ requirements.txt
│  ├─ clamav/             # ClamAV container config (used by the file scanner)
│  │  ├─ Dockerfile
│  │  ├─ clamd.compose.conf
│  │  ├─ clamd.sidecar.conf
│  │  ├─ freshclam.conf
│  │  ├─ freshclam-updater.sh
│  │  └─ healthcheck.sh
│  └─ worker/             # fetcher + analyzer (same image, different WORKER_MODE)
│     ├─ Dockerfile.sidecar
│     ├─ entrypoint.sidecar.sh
│     ├─ fetcher.py
│     ├─ screenshot_capture.py
│     ├─ worker.py
│     ├─ requirements.txt
│     └─ yara-rules/      # reserved (not used by URL scanner)
│        └─ default.yar
├─ infra/
│  ├─ backend.tf
│  ├─ main.tf             # providers + locals
│  ├─ core.tf             # core infra (SB, ACA env, etc.)
│  ├─ keyvault.tf         # KV perms + secrets
│  ├─ apps.tf             # Container Apps (create_apps)
│  ├─ outputs.tf
│  └─ variables.tf
├─ docs/
├─ tests/
├─ checkov.yml
└─ readme.md
```

## 5) CI/CD workflow
### CI (`.github/workflows/ci.yml`)

- Runs on PRs and pushes to `main` (docs-only changes are ignored).
- On `main` pushes with app changes, **CD runs only after CI succeeds** (CI calls `app-deploy.yml`).
- Python: Ruff (syntax) + `python -m compileall` + pytest
- Terraform: `terraform fmt` + `terraform validate`
- Containers: Hadolint (only for changed Dockerfiles)
- Security scans:
  - **Main**: Checkov + Trivy (SARIF uploads) run as part of CI.
  - **PRs**: Checkov/Trivy run **only** when `RUN_PR_SECURITY_SCANS=true` (repo variable).
- On `main`, CI now **builds & pushes images once** (API/worker/ClamAV) and passes tags to CD to avoid double builds.
	    

### Deploy (`.github/workflows/deploy.yml`)

- Bootstrap **RG + KV (recover if soft-deleted) + ACR + LA + TF state**
    
- Ensure CI has **Storage Blob Data Contributor** on TF state SA (AAD backend)
    
- Terraform **apply** core infra (SB, KV secrets, ACA env, UAMI, etc.)
    
- Build & push images to ACR (API, worker/fetcher, ClamAV; tagged with commit SHA)
    
- Terraform **apply** apps (pull from ACR; KV secret refs; UAMI-backed)
    
- Prints the public **FastAPI URL** as output

- Runs smoke tests:
    - `GET /healthz`
    - end-to-end scan: `POST /scan` then poll `GET /scan/{job_id}` until `completed`

> Docs-only changes (`**/*.md`, `docs/**`) do not trigger CI; Deploy is manual (`workflow_dispatch`).

### Infra Only (Deploy `mode=infra-only`)

Manual workflow for infrastructure updates without rolling new app images:

- Use `.github/workflows/deploy.yml` with `mode=infra-only`.
- Bootstraps foundation resources (RG/KV/ACR/LA/TF state).
- Runs Terraform apply for infra changes.
- Preserves existing apps when present (`create_apps` auto-detection in bootstrap script).
- Useful for changes like networking, queues, storage, Key Vault wiring, or Web PubSub resources/secrets.
- Optional: configure `ACA_KV_SECRET_READER_OBJECT_IDS_JSON` (repo variable or secret) as a JSON array (example: `["<entra-object-id>"]`) so deploy-time Terraform applies keep Key Vault reader assignments consistent.

### App Deploy (CD) (`.github/workflows/app-deploy.yml`)

Fast path for code changes **after the Azure environment already exists**:

- Trigger (automatic): invoked by CI after a successful `push` to `main` when app-related files change
- Trigger (manual): `workflow_dispatch`
- **Default (from CI):** images are already built in CI; CD **skips build** and only rolls out.
- **Manual runs:** can build & push images by setting `build_images=true` (default for manual).
- Only rolls out the containers that changed (API / Worker+Fetcher / ClamAV); manual runs can override with `deploy_api`, `deploy_worker`, `deploy_clamav`.
- Terraform ignores container image changes; **CD is the source of truth** for running image versions.
- Updates existing Container Apps in-place via `az containerapp update` (no Terraform):
  - `${prefix}-api` (`api` + `clamav` containers)
  - `${prefix}-fetcher` (`fetcher` container; uses worker image)
  - `${prefix}-worker` (`worker` container)
- Optional smoke test: `GET /healthz` (enabled by default; disable via `smoke_test=false`)

Configuration (recommended):

- Set GitHub Actions **Variables**:
  - `ACA_PREFIX` (e.g. `devsecopsaca`)
  - `ACA_RESOURCE_GROUP` (e.g. `rg-devsecops-aca`)
  - `ACA_DEPLOY_ENABLED` (`true` to allow CI to build/push + deploy; CI skips deploy when false)
  - `ACA_KV_SECRET_READER_OBJECT_IDS_JSON` (optional; JSON array of Entra object IDs for Key Vault secret readers used by the Deploy workflow)
  - `ACA_MONITOR_ACTION_GROUP_EMAIL_RECEIVERS_JSON` (optional; JSON array of email addresses for Azure Monitor Action Group, e.g. `["secops@example.com"]`)
  - `ACA_MONITOR_ALERTS_ENABLED` (optional; `true`/`false`, defaults to Terraform variable default)
  - `ACA_MONITOR_WORKBOOK_ENABLED` (optional; `true`/`false`, defaults to Terraform variable default)
  - `RUN_PR_SECURITY_SCANS` (optional, `true` to enable Checkov/Trivy on PRs)
- Secrets remain the same as Deploy: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`

### KEDA Scale Test (`.github/workflows/keda-scale-test.yml`)

Manual workflow (`workflow_dispatch`) to validate **KEDA scale-out**:

- Enqueues a burst of scan messages directly to **Service Bus** (bypasses API rate limiting).
- Polls worker replica count until it reaches `expected_min_replicas`.

You can run the same check locally:

```bash
python3 -m pip install "azure-servicebus~=7.12"
az login
bash scripts/keda_scale_test.sh --resource-group <rg> --prefix <prefix>
```


### Destroy (`.github/workflows/destroy.yml`)

- Terraform **destroy** all resources
    
- **Delete the entire RG** (async) to hit **$0**
    
- You can re-run **Deploy** anytime to fully recreate everything (including the RG)

## 6) First-run values (env)

### API key (required)

The **Deploy** workflow generates a bootstrap API key and stores it in **Key Vault** as the secret `ApiKey`.

- The deploy workflow uses this key for smoke/e2e tests, but **does not print it** to GitHub Actions logs.
- By default, this bootstrap key is also an admin key for API key management endpoints.

Retrieve it with Azure CLI (example):

```bash
KV_NAME="<prefix>-kv"
API_KEY="$(az keyvault secret show --vault-name "$KV_NAME" --name ApiKey --query value -o tsv)"
```

If you get `ForbiddenByRbac`, your identity doesn’t have Key Vault RBAC to read secrets.  
For a persistent fix, manage this in Terraform with `kv_secret_reader_object_ids` via the Deploy workflow variable `ACA_KV_SECRET_READER_OBJECT_IDS_JSON`.  
For a one-off fix, grant yourself the **Key Vault Secrets User** role on the vault (example):

```bash
RG="<resource-group>"
KV_NAME="<prefix>-kv"
KV_ID="$(az keyvault show -g "$RG" -n "$KV_NAME" --query id -o tsv)"
ME_OID="$(az ad signed-in-user show --query id -o tsv)"

az role assignment create \
  --assignee-object-id "$ME_OID" \
  --assignee-principal-type User \
  --role "Key Vault Secrets User" \
  --scope "$KV_ID"
```

Then wait ~30–60 seconds for RBAC propagation and retry.

Use it on requests:

`-H "X-API-Key: $API_KEY"`

#### Mint/revoke per-user API keys (admin)

The API supports persisted key management in the configured result backend (Table or Redis):

- `POST /admin/api-keys` mints a new API key (returned once in plaintext), with optional per-key `read_rpm`/`write_rpm` and TTL.
- `GET /admin/api-keys` lists stored keys and status.
- `POST /admin/api-keys/{key_hash}/revoke` revokes a key.

Admin auth:

- `API_ADMIN_KEY` / `API_ADMIN_KEYS` can define explicit admin keys.
- If unset, `API_KEY` is treated as admin by default.
- Stored keys can also be admin keys when minted with `"is_admin": true`.

Example (mint a key):

```bash
curl -sS -X POST "${API_URL}/admin/api-keys" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"label":"analyst-a","read_rpm":600,"write_rpm":120}'
```

#### Rotate the API key (optional)

If you want to rotate the shared key, replace the Terraform resource and apply again:

```bash
cd infra
terraform apply \
  -replace="random_password.api_key" \
  -var="create_apps=true" \
  -var="image_tag=<tag>"
```

### Security defaults

- **SSRF protection**: only `https://` targets on port **443**; blocks targets that resolve to non-public IP ranges.
- **Rate limiting** (per API key, configurable):
  - write endpoints (e.g. `POST /scan`): `RATE_LIMIT_WRITE_RPM` (defaults to `RATE_LIMIT_RPM`, `60`)
  - read endpoints (e.g. `GET /scan/{job_id}`, `GET /jobs`, `POST /pubsub/negotiate-user`): `RATE_LIMIT_READ_RPM` (defaults to `5x` write limit)
  - shared window: `RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- **Defense in depth**: the worker re-validates targets and validates every redirect hop.

### Live updates (Web PubSub, optional)

Enable real-time scan status updates (no polling) by setting:

- `WEBPUBSUB_CONNECTION_STRING`: Web PubSub connection string
- `WEBPUBSUB_HUB`: hub name (default `scans`)
- `WEBPUBSUB_TOKEN_TTL_MINUTES`: client token TTL (default `60`)
- `WEBPUBSUB_GROUP_PREFIX`: group prefix for run IDs (default `run`)
- `WEBPUBSUB_USER_GROUP_PREFIX`: group prefix for API-key-hash user groups (default `apikey`)

If `WEBPUBSUB_CONNECTION_STRING` is unset, the dashboard falls back to polling.

Realtime model notes:

- The API returns both:
  - `job_id`: request ID shown in history
  - `run_id`: underlying scan run ID (shared across deduped requests)
- Dashboard subscribes once per API key via `POST /pubsub/negotiate-user`.
- Worker/fetcher publish events to both `run:<run_id>` and `apikey:<api_key_hash>` groups so one socket can update all of a user’s jobs.

### URL dedupe / cache (optional)

To avoid wasting resources re-scanning the same URL, `POST /scan` maintains a **shared URL cache** keyed by the **canonical URL**. When a URL was scanned recently (or is still in progress), a new `POST /scan` request can reuse the existing underlying scan run instead of scanning again (but still returns a new `job_id` for the request). The URL canonicalization normalizes host casing, dot-segments, default ports, and strips fragments.

Configure with env vars (set TTLs to `0` to disable):

- `URL_DEDUPE_TTL_SECONDS`: cache window for `completed`/`error` jobs
- `URL_DEDUPE_IN_PROGRESS_TTL_SECONDS`: dedupe window for `queued`/`fetching`/`queued_scan`/`retrying`
- `URL_DEDUPE_SCOPE`: `global` (recommended for multi-user) or `apikey` (cache is isolated per API key)
- `URL_DEDUPE_INDEX_PARTITION`: Table Storage partition key for the URL index (default `urlidx`)
- `REDIS_URL_INDEX_PREFIX`: Redis key prefix for the URL index (default `urlidx:`)

URL scans also have a **visibility** setting:

- `URL_RESULT_VISIBILITY_DEFAULT`: `shared` (default) or `private`
- `POST /scan` body supports `"visibility": "shared" | "private"`

To force a re-scan, pass `"force": true` (or set `"visibility": "private"` to opt out of cache reuse and cache population).

### Per-user job history (API keys)

The API stores a lightweight job index keyed by a **hash of the caller’s API key**:

- `GET /jobs` lists only jobs created with *your* API key.
- `GET /scan/{job_id}` and `GET /scan/{job_id}/screenshot` are owner-protected (a different API key won’t be able to fetch another user’s request IDs).
- Per-key rate limits can be attached when minting keys via `POST /admin/api-keys`.

You can still use static env keys (`ACA_API_KEY`, `ACA_API_KEYS`) as bootstrap/fallback keys.

## 7) Running it

### Local (Docker Compose)

Prereqs: Docker Desktop (or any Docker engine with Compose).

```bash
cp .env.example .env  # optional: tweak defaults (API key, rate limits, etc.)
docker compose up --build
```

- API: `http://localhost:8000`
- Web UI: `http://localhost:8000/`
- Swagger: `http://localhost:8000/docs`

Default API key: `local-dev-key` (change via `.env` using `ACA_API_KEY`).

> Note: URL scanning runs built-in web analysis only. The dashboard provides external links to URLScan.io and VirusTotal for optional follow-up checks.

To verify realtime mode locally:

```bash
curl -s http://localhost:8000/ | rg WEBPUBSUB_ENABLED
```

- `true`: dashboard will use Web PubSub (if it can negotiate).
- `false`: dashboard will use polling only.

#### Local traces (no Azure) with Jaeger + sampler validation

Use the optional Compose profile to run Jaeger locally and validate `OTEL_TRACES_SAMPLER_RATIO`.

```bash
OTEL_ENABLED=true OTEL_TRACES_SAMPLER_RATIO=0.10 \
  docker compose --profile observability up --build -d
```

- Jaeger UI: `http://localhost:16686`
- API: `http://localhost:8000`
- OTLP collector ports (optional debug from host): `4318` (HTTP), `4317` (gRPC)

Run the local sampler validation:

```bash
python3 scripts/local/verify_trace_sampling.py \
  --api-url http://localhost:8000 \
  --api-key local-dev-key \
  --jaeger-url http://localhost:16686 \
  --expected-ratio 0.10 \
  --requests 80
```

Expected result:
- script exits `0`
- output ends with `PASS`
- observed ratio is close to expected ratio (within tolerance window)

#### Docker “\<none\>” images (dangling)

If you rebuild often, Docker will keep old, untagged images (shown as `\<none\>`) when a new build replaces the tag. They’re safe to delete.

- Remove dangling images: `bash scripts/docker_cleanup.sh`
- Also remove build cache (more aggressive): `PRUNE_BUILD_CACHE=true bash scripts/docker_cleanup.sh`

### Azure (Container Apps)
- Trigger the **Deploy** workflow manually (Actions tab → Deploy → Run workflow).
  - For forks: set a unique `PREFIX` and `TFSTATE_SA` via workflow inputs (storage account names are global).
    
- After **create-apps**, get the public API URL:

```bash
API_FQDN="$(az containerapp show -g rg-devsecops-aca -n devsecopsaca-api --query properties.configuration.ingress.fqdn -o tsv)"
API_URL="https://${API_FQDN}"
echo "$API_URL"
```

`infra/outputs.tf` also exposes a `fastapi_url` output if you run Terraform locally.

### Azure quickstart (user workflow)

1. Run **Deploy** from GitHub Actions (Actions tab → Deploy → Run workflow).
2. Get the API URL (output or `az containerapp show ...`).
3. Get the API key from Key Vault: `ApiKey`.
4. Open the web UI at `https://<api-fqdn>/` and paste the API key.
5. Submit a scan and watch status/results update in the UI.

Example CLI setup:

```bash
API_FQDN="$(az containerapp show -g rg-devsecops-aca -n devsecopsaca-api --query properties.configuration.ingress.fqdn -o tsv)"
API_URL="https://${API_FQDN}"
API_KEY="$(az keyvault secret show --vault-name devsecopsaca-kv --name ApiKey --query value -o tsv)"
```

## 8) Using the API

### GUI + Swagger

- Local Web UI: `http://localhost:8000/`
- Local Swagger: `http://localhost:8000/docs`
- Azure Web UI: `https://<api-fqdn>/`
- Azure Swagger: `https://<api-fqdn>/docs`
- Azure ReDoc: `https://<api-fqdn>/redoc`

### Endpoints

- `GET /` (no auth; dashboard UI)
- `GET /healthz` (no auth)
- `GET /file` (no auth; file scanner UI)
- `POST /scan` (requires API key)
- `GET /jobs?limit=N&status=csv` (requires API key; lists your recent jobs)
- `GET /scan/{job_id}?view=summary|full` (requires API key; `summary` is default)
- `GET /scan/{job_id}/screenshot` (requires API key; only if a screenshot was captured)
- `POST /pubsub/negotiate-user` (requires API key; dashboard live updates)
- `POST /pubsub/negotiate` (requires API key; run-scoped negotiation; mostly for direct/testing use)
- `POST /file/scan` (requires API key; ClamAV scan)
- `GET /admin/api-keys` (admin API key; list stored keys)
- `POST /admin/api-keys` (admin API key; mint key + optional quotas/TTL)
- `POST /admin/api-keys/{key_hash}/revoke` (admin API key; revoke key)

### Scan status lifecycle

`GET /scan/{job_id}` returns a `status`. When a job exists, statuses progress monotonically (out-of-order writes are ignored so status won’t go “backwards”).

- `pending`: no record found (unknown `job_id`)
- `queued`: job accepted and enqueued by the API
- `fetching`: fetcher is downloading (SSRF-protected) and preparing an artifact
- `queued_scan`: artifact is ready and the scan stage has been queued
- `retrying`: transient failure; will retry automatically (up to `MAX_RETRIES`)
- `completed`: finished; check `summary` (and `details` if `view=full`)
- `error`: failed; check `error` + `details`

### Try it (Option A: CLI Wrapper)

The included helper script (`scripts/aca_api.py`) wraps API calls and handles JSON parsing, headers, and polling. It works locally or on Azure.

```bash
# Local default: http://localhost:8000 (reads ACA_API_KEY or API_KEY from .env if present)
./scripts/aca_api.py scan-url https://example.com --wait
./scripts/aca_api.py jobs --limit 50
./scripts/aca_api.py scan-file ./readme.md
./scripts/aca_api.py screenshot <job_id> --out-dir ./screenshots/
./scripts/aca_api.py admin-mint-key --label analyst-a --read-rpm 600 --write-rpm 120
./scripts/aca_api.py admin-list-keys --include-inactive
./scripts/aca_api.py admin-revoke-key <key_hash>
./scripts/aca_api.py help               # show all commands + options
./scripts/aca_api.py help screenshot    # show options for one command

# Azure: set API_URL + API_KEY (see "Azure quickstart" above)
API_URL="https://<api-fqdn>" API_KEY="..." ./scripts/aca_api.py scan-url https://example.com --wait
```

The script also keeps a local job history (default `./.aca_api_history`) so you can list the most recent jobs you submitted from your machine:

```bash
./scripts/aca_api.py jobs --limit 20
./scripts/aca_api.py jobs --status queued,fetching,queued_scan,retrying --limit 50
./scripts/aca_api.py history --limit 10
./scripts/aca_api.py clear-server-history  # clears server-side /jobs history for your API key
```

### Try it (Option B: curl)

If you prefer standard tools, you can use `curl` directly.

**Submit a scan:**

```bash
submit="$(curl -sS -X POST "${API_URL}/scan" \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url"}')"

JOB_ID="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["job_id"])' <<<"$submit")"
echo "JOB_ID=$JOB_ID"
```

**Poll for status/result:**

```bash
curl -sS "${API_URL}/scan/${JOB_ID}?view=summary" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
curl -sS "${API_URL}/scan/${JOB_ID}?view=full" -H "X-API-Key: ${API_KEY}" | python3 -m json.tool
```

### File scanning (ClamAV)

- UI: `GET /file` (no auth)
- API: `POST /file/scan` (requires API key; accepts `file=@...` or a `payload` form field)

Example (scan a file):

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "file=@./readme.md" | python3 -m json.tool
```

Example (scan a text payload):

```bash
curl -sS -X POST "${API_URL}/file/scan" \
  -H "X-API-Key: ${API_KEY}" \
  -F "payload=hello world" | python3 -m json.tool
```

### Where are scan results stored?

- **Primary**: `GET /scan/{job_id}` (reads from the configured result backend: Azure Table Storage by default; Redis in `docker-compose.yml`)
- **Note**: Azure Table has a ~64KB per-property limit; large `details` payloads are compacted/truncated (look for `_truncated` in `view=full`). Tune with `RESULT_DETAILS_MAX_BYTES`. A `status_rank` field may also be stored to prevent status regression.
- **Screenshots (optional)**: `GET /scan/{job_id}/screenshot` (stored in the results storage account when using Table; stored in Redis when using Redis)
- **Local (optional)**: `docker compose exec redis redis-cli HGETALL "scan:<job_id>"`
- **GitHub Actions**: open the Deploy run and find the `job_id=...` line under “End-to-end scan test” (you can query it via the API afterwards)
- **Azure Portal (optional)**: Storage account `<prefix>scan` → Table service → `scanresults` (PartitionKey `scan`)

## 9) Observability & troubleshooting

### Logs (CLI)

- **API (console)**
    
    `az containerapp logs show -g rg-devsecops-aca -n devsecopsaca-api --type console --follow --container api`
    
- **Fetcher (console)**
    
    `az containerapp logs show -g rg-devsecops-aca -n devsecopsaca-fetcher --type console --follow --container fetcher`

- **Worker (console)**
    
    `az containerapp logs show -g rg-devsecops-aca -n devsecopsaca-worker --type console --follow --container worker`
    
- **System logs**
    
    `az containerapp logs show -g rg-devsecops-aca -n devsecopsaca-api --type system --follow`

### Query pack + runbook

- KQL query pack: `docs/observability/kql/`
- Incident runbook: `docs/observability/runbook.md`
- Logging/tracing guide: `docs/azure-logging-guide.md`

### App Insights tracing

- `api`, `fetcher`, and `worker` use OpenTelemetry trace context propagation (`traceparent`/`tracestate` in queue payloads).
- Use `correlation_id` in Log Analytics and `trace_id` to pivot to trace-level diagnostics in Application Insights.
- Jaeger/App Insights span tags include both identifiers for unambiguous filtering:
  - `app.request_id` = API `job_id` response field (per submission)
  - `app.run_id` = API `run_id` response field (pipeline execution)
  - `app.job_id` remains as a compatibility alias for `app.run_id`

### Terraform-managed alerts/workbook

- Monitoring resources are defined in `infra/monitoring.tf`.
- Key toggles/inputs:
  - `monitor_alerts_enabled`
  - `monitor_action_group_email_receivers`
  - `monitor_workbook_enabled`
  - threshold vars (`monitor_api_5xx_threshold`, `monitor_pipeline_error_threshold`, `monitor_queue_backlog_threshold`, `monitor_deadletter_threshold`)

### KEDA scaling

Fetcher and worker are configured:

- `min_replicas = 0`, `max_replicas = 5`
    
- 1 replica per **20 messages** (worker example):
```hcl
custom_scale_rule {
  name             = "sb-scaler"
  custom_rule_type = "azure-servicebus"
  metadata = {
    queueName    = local.scan_queue_name
    namespace    = "<service-bus-namespace>"
    messageCount = "20"
  }
  authentication {
    secret_name       = "sb-scan-manage"
    trigger_parameter = "connection"
  }
}
```
    

Verify replicas:

```bash
az containerapp replica list -g rg-devsecops-aca -n devsecopsaca-worker \
  --query "length(@)" -o tsv
```

Send a burst of messages to see it scale:

```bash
for i in {1..25}; do
  curl -sS -X POST "${API_URL}/scan" \
    -H "content-type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d '{"url":"https://example.com","type":"url"}' >/dev/null
done
```

Submit a scan job and poll for completion:

```bash
JOB_ID="$(curl -sS -X POST "${API_URL}/scan" \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://example.com","type":"url"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_id"])')"

curl -sS "${API_URL}/scan/${JOB_ID}" -H "X-API-Key: ${API_KEY}"
```

### Common errors & fixes

- **403 listing blobs during `terraform init`**  
    Make sure the CI principal has **Storage Blob Data Contributor** on the state **storage account**. The workflow grants it; allow 30–60s for RBAC to propagate.
    
- **Resource already exists — import required**  
    The workflow does imports before apply. If running locally:  
    `terraform import <addr> <id>` using the IDs echoed in the error.
    
- **`Failed to provision revision: '<secret>' unable to get value using Managed identity`**
    
    - In `azurerm_container_app.secret` blocks, ensure `identity` points at the **UAMI resource ID** (or `"System"` if you intentionally use system-assigned MI).
    - Ensure the app identity has **Key Vault Secrets User** on the vault (RBAC) so it can **Get/List** secrets.
        
    - Ensure the CI principal has **Key Vault Secrets Officer** on the vault (RBAC) so Terraform can **create/update** the secrets.
        
- **KEDA not scaling**
    
    - Ensure the scaler secrets `sb-manage` (fetch queue) and `sb-scan-manage` (scan queue) come from SAS rules that include **Manage**.
        
    - Queue name in the scaler metadata matches the actual queue.
    
    - `messageCount` is the target used in the scaling formula (`desiredReplicas = ceil(queueLength/messageCount)`); if queue length stays > 0 and replicas stay at 0, the scaler/auth is misconfigured.

- **Scan stays `queued` / `queued_scan`**
    - If it stays `queued`: the fetcher likely isn’t processing messages (check fetcher logs).
    - If it stays `queued_scan`: the worker likely isn’t processing messages (check worker logs).
        
- **Max delivery count / DLQ**  
    - Both fetcher/worker retry up to `MAX_RETRIES`; after that the message is dead-lettered (Service Bus) or moved to a DLQ list (Redis).
    - Check queue dead-letter count and logs for the `job_id`/`correlation_id`.

- **401/403 from the API**
    - Include `X-API-Key` on `/scan`, `/scan/{job_id}`, `/scan/{job_id}/screenshot`, and `/file/scan`.
    - Retrieve the key from Key Vault secret `ApiKey`.

- **503 from `/file/scan`**
    - ClamAV may still be starting (or downloading signatures). Check the `clamav` container logs in the API Container App (or the `clamav` service in Docker Compose):  
      `az containerapp logs show -g <rg> -n <prefix>-api --type console --follow --container clamav`

- **400 “URL resolves to a non-public IP address”**
    - SSRF protections block private/link-local/loopback destinations (intended).

## 10) Working with Terraform locally
If you want to inspect or modify:

```bash
cd infra
export ARM_SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
export TF_VAR_subscription_id="${ARM_SUBSCRIPTION_ID}"
terraform init \
  -backend-config="resource_group_name=rg-devsecops-aca" \
  -backend-config="storage_account_name=stdevsecopsacatfstate" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=devsecopsaca.tfstate" \
  -backend-config="use_azuread_auth=true"

terraform plan \
  -var="prefix=devsecopsaca" \
  -var="resource_group_name=rg-devsecops-aca" \
  -var="queue_name=tasks" \
  -var="create_apps=true" \
  -var="image_tag=<some-tag>"
```

To persist Key Vault read access for specific identities in CI/CD, set GitHub Actions variable `ACA_KV_SECRET_READER_OBJECT_IDS_JSON` to a JSON array, for example:

```json
["your-object-id-guid"]
```

> If you see a state **lease** error, break the stale lease:
> 
> ```bash
> az storage blob lease break \
>   --account-name stdevsecopsacatfstate \
>   --container-name tfstate \
>   --blob-name devsecopsaca.tfstate \
>   --auth-mode login
> ```

## 11) Costs & clean-up
- **Service Bus (Basic by default)**, **App Insights/Log Analytics**, and image storage can incur cost even when apps scale to zero.
    
- Easiest **stop** options:
    
    1. **Scale to zero** the API as well (set `min_replicas = 0`) or disable ingress.
        
    2. **Terraform destroy** (recommended; only removes Terraform-managed resources):
        
        ```bash
        cd infra
        terraform destroy \
          -var="prefix=devsecopsaca" \
          -var="resource_group_name=rg-devsecops-aca" \
          -var="queue_name=tasks" \
          -var="create_apps=true"
        ```
        
    3. As a last resort: delete the **resource group** (will also delete base resources you might want to keep).
        

To restart later, just re-run the **Deploy** workflow.

## 12) Security notes
- CI uses **OIDC** (no long-lived secrets).
    
- Terraform backend uses **AAD** for data-plane auth (no account keys).
    
- Secrets are in **Key Vault**; Container Apps read them via **managed identity** + **secret references**.
    
- Role assignments are minimal for runtime (ACR Pull, KV Read).

## 13) How the app code works (quick tour)
**API (`app/api/main.py`)**
    
- `POST /scan` -> requires `X-API-Key`, enforces SSRF protections, enqueues a scan job, and records a queued status in the configured result backend (`RESULT_BACKEND=table` on Azure; `RESULT_BACKEND=redis` locally).
    
- `GET /scan/{job_id}` -> reads the configured result backend and returns the current status and security analysis.

- `GET /scan/{job_id}/screenshot` -> serves an optional worker-captured screenshot (stored in Blob Storage when `RESULT_BACKEND=table`, or Redis when `RESULT_BACKEND=redis`).

- `POST /pubsub/negotiate-user` -> creates a user-scoped Web PubSub client token for the dashboard (`apikey:<api_key_hash>` group).

- `POST /file/scan` -> requires `X-API-Key`, scans an uploaded file or pasted payload with ClamAV, and returns an immediate verdict (UI at `/file`).

- `GET/POST /admin/api-keys*` -> admin-only API key lifecycle management (mint/list/revoke) with persisted key hashes and optional per-key quotas.
    
- `GET /healthz` -> basic health.
    

**Fetcher (`app/worker/fetcher.py`)**
- Receives `scan-v1` jobs from the **fetch queue** (`tasks` by default).
- Downloads bytes with SSRF protections, writes an artifact into `ARTIFACT_DIR` (Azure Files on ACA; a Docker volume locally), updates status (`fetching` → `queued_scan`), and forwards a `scan-artifact-v1` message to the **scan queue** (`<queue>-scan`).
- Publishes status updates to Web PubSub when configured.

**Analyzer/Worker (`app/worker/worker.py`)**
- Receives `scan-artifact-v1` jobs from the **scan queue** and reads the artifact bytes.
- Runs lightweight web analysis (HTML/resources/cookies/security headers/tracking/YARA rules) and writes the final `completed/error` result to the configured result backend; optionally captures a Playwright screenshot and stores it for `/scan/{job_id}/screenshot`.
- Web analysis rules live in `app/common/tracking_filters.txt` and `app/common/web_yara_rules.yar` (override via `WEB_TRACKING_FILTERS_PATH` / `WEB_YARA_RULES_PATH`).
- Publishes terminal and intermediate status updates to Web PubSub when configured.

## 14) Extending this project (future work)

- **Key governance hardening**: signed key-issuance events, approval workflows, and periodic key-usage anomaly detection.
- **Deepen scanning**: add more external reputation sources (Safe Browsing/VirusTotal), enrich redirect analysis, and add more HTML/JS heuristics.
- **Async file scanning pipeline**: move `/file/scan` into a queued workflow for larger inputs (store payloads in Blob/Azure Files) and run ClamAV/YARA in a dedicated worker.
- **Front the API**: add API Management / Front Door + WAF, request validation, and centralized auth.
- **DAST in CI**: run OWASP ZAP against the deployed `/scan` endpoint using a non-prod API key.
- **Supply-chain hardening**: SBOM generation (Syft), vulnerability gating (Grype), image signing (Cosign), and provenance.
- **Alerting**: create Log Analytics queries + Azure Monitor alerts for spikes in 4xx/5xx, queue depth, and worker DLQs.

## 15) FAQ

**Where is my API URL?**  
`az containerapp show -g rg-devsecops-aca -n devsecopsaca-api --query properties.configuration.ingress.fqdn -o tsv`

**How do I view the end-to-end scan test result?**  
Open the Deploy workflow logs → “End-to-end scan test” prints `job_id=...`. Query it with `GET /scan/{job_id}` (or use the web UI at `/`).

**How do I get an API key?**  
If you deployed your own instance, read Key Vault secret `ApiKey` (bootstrap admin key), then mint user keys with `POST /admin/api-keys`. Otherwise, ask the deployment owner for a key.

**How do I tail logs?**  
`az containerapp logs show -g <rg> -n <app> --type console --follow`

**Why did Terraform say “resource already exists”?**  
Because you pre-created it. Import it into state (the workflow does this automatically).

**Why can’t the app read secrets from Key Vault?**  
Make sure the `azurerm_container_app.secret` block uses the correct `identity` and that identity has Key Vault secret **Get/List**.

## License

MIT — see `LICENSE`.

## Contributing & security

See `CONTRIBUTING.md` and `SECURITY.md`.
