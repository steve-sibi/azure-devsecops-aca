# URL + File Scanner Pipeline on Azure (ACA)

[![CI](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/ci.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/ci.yml)
[![Deploy](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/deploy.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/deploy.yml)
[![App Deploy (CD)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/app-deploy.yml/badge.svg)](https://github.com/steve-sibi/azure-devsecops-aca/actions/workflows/app-deploy.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776ab.svg)](https://www.python.org/)
[![Terraform 1.6+](https://img.shields.io/badge/Terraform-1.6+-844fba.svg)](https://www.terraform.io/)
[![Azure Container Apps](https://img.shields.io/badge/Azure-Container%20Apps-0078d4.svg)](https://azure.microsoft.com/en-us/products/container-apps)

End-to-end, cloud-native URL and file scanning pipeline on Azure Container Apps, using Terraform and GitHub Actions (OIDC).

## What this project demonstrates

- Secure API surface: `X-API-Key`, per-key rate limits, SSRF protection, URL canonicalization
- Async pipeline: API -> fetch queue -> fetcher -> scan queue -> worker
- Cloud-native operations: KEDA autoscaling, structured logs, optional OpenTelemetry traces
- Realtime status updates: Azure Web PubSub or Redis Streams (Docker/local), with polling fallback
- DevSecOps workflow: CI quality/security gates, reusable app deploy flow, terraform-managed infra
- Runtime secrets posture: Key Vault secret references resolved with managed identity

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

SSRF protection check (expected `400`):

```bash
curl -i -sS -X POST http://localhost:8000/scan \
  -H "content-type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"url":"https://127.0.0.1","type":"url"}'
```

## 1) Architecture

### Runtime snapshot

```text
Client
  -> FastAPI (`/scan`)
  -> Service Bus queue (tasks)
  -> Fetcher (downloads artifact)
  -> Service Bus queue (tasks-scan)
  -> Worker (analysis + optional screenshot)
  -> Result backend (Table Storage on Azure, Redis locally)
```

### Key design points

- Two-stage queue design separates network fetch from analysis work.
- Fetcher and worker scale independently on queue depth (KEDA).
- `job_id` identifies a request; `run_id` identifies underlying scan execution.
- Realtime backend is configurable via `LIVE_UPDATES_BACKEND` (`auto`, `webpubsub`, `redis_streams`, `none`).

For deeper design rationale and threat boundaries:

- `docs/adr/0001-design-decisions.md`
- `docs/threat-model.md`

## 2) What Terraform Deploys

Core resources (names use `<prefix>`):

- Resource group, Log Analytics, App Insights, Key Vault, ACR
- Service Bus namespace + fetch/scan queues + least-privilege SAS rules
- Storage account + `scanresults` table + optional screenshot container
- User-assigned managed identity (UAMI)
- ACA environment + `api`, `fetcher`, `worker` apps
- Monitoring assets (saved queries, alerts, optional workbook)

Full workflow and deployment behavior details are documented in `docs/cicd-workflows.md`.

## 3) Prerequisites

- GitHub OIDC configured for your Azure tenant/subscription
- Repository secrets set:
  - `AZURE_CLIENT_ID`
  - `AZURE_TENANT_ID`
  - `AZURE_SUBSCRIPTION_ID`
- Subscription-level permissions for the OIDC principal:
  - `Contributor`
  - `User Access Administrator`

One-time provider registration for Web PubSub:

```bash
az provider register --namespace Microsoft.SignalRService --wait
az provider show --namespace Microsoft.SignalRService --query registrationState -o tsv
```

Expected state: `Registered`.

## 4) Repository layout

```text
azure-devsecops-aca/
├─ .github/workflows/      # CI/CD workflows
├─ app/
│  ├─ api/                 # FastAPI app and UI
│  ├─ worker/              # fetcher + analyzer runtime
│  ├─ clamav/              # ClamAV container config
│  └─ common/              # shared helpers and rules
├─ infra/                  # Terraform
├─ docs/                   # deep-dive documentation
├─ scripts/                # helper CLIs and workflow scripts
└─ tests/
```

### Docs map

- [`docs/README.md`](docs/README.md) - full docs index by use case
- [`docs/cicd-workflows.md`](docs/cicd-workflows.md) - workflow behavior and gates
- [`docs/configuration-reference.md`](docs/configuration-reference.md) - env/runtime configuration
- [`docs/api-usage.md`](docs/api-usage.md) - endpoint reference and usage examples
- [`docs/observability/README.md`](docs/observability/README.md) - KQL and runbook index
- [`docs/terraform-local.md`](docs/terraform-local.md) - local Terraform workflow

## 5) CI/CD workflow

Detailed CI/CD docs moved to `docs/cicd-workflows.md`.

## 6) First-run values (env)

Environment and key-management reference moved to `docs/configuration-reference.md`.

## 7) Running it

### Local (Docker Compose)

```bash
cp .env.example .env
docker compose up --build
```

- API: `http://localhost:8000`
- Dashboard: `http://localhost:8000/`
- Swagger: `http://localhost:8000/docs`

Default key: `local-dev-key` (change `ACA_API_KEY` in `.env`).

Local realtime note:

- Docker defaults to Redis live updates (`redis_streams`) with authenticated NDJSON streaming (`GET /events/stream`).
- If realtime negotiation/streaming is unavailable, dashboard and CLI fall back to polling.

### Azure quickstart

1. Run `Deploy` from GitHub Actions.
2. Get API URL:

```bash
API_FQDN="$(az containerapp show -g <resource-group> -n <prefix>-api --query properties.configuration.ingress.fqdn -o tsv)"
API_URL="https://${API_FQDN}"
```

3. Get bootstrap key:

```bash
API_KEY="$(az keyvault secret show --vault-name <prefix>-kv --name ApiKey --query value -o tsv)"
```

4. Open `https://<api-fqdn>/`, paste API key, submit a scan.

## 8) Using the API

Endpoint reference and examples moved to `docs/api-usage.md`.

## 9) Observability & troubleshooting

Observability docs moved to:

- `docs/observability/README.md`
- `docs/observability/runbook.md`
- `docs/azure-logging-guide.md`

## 10) Working with Terraform locally

Local Terraform workflow moved to `docs/terraform-local.md`.

## 11) Costs & clean-up

Persistent costs may come from Service Bus, monitoring resources, and stored images/artifacts.

Cleanup options:

1. Scale workloads down where appropriate.
2. Run `Destroy` workflow (preferred for full teardown).
3. Delete the resource group as last resort.

## 12) Security notes

- OIDC-based Azure auth in CI/CD (no long-lived cloud credentials)
- Key Vault secret references + managed identity at runtime
- SSRF protection at API boundary and worker redirect checks
- Container/IaC scanning in CI (Trivy and Checkov)

Security policy and reporting:

- `SECURITY.md`
- `docs/threat-model.md`

## 13) How the app code works (quick tour)

- `app/api/main.py`
  - validates request + auth
  - enqueues scan jobs
  - serves dashboard/API responses
- `app/worker/fetcher.py`
  - fetch stage with SSRF-aware controls
  - artifact handoff to scan queue
- `app/worker/worker.py`
  - analysis stage + result persistence
  - optional screenshot capture and publish

## 14) Extending this project (future work)

- Private networking and edge hardening (Front Door/WAF/Private Link)
- Richer scoring and reputation integrations
- Deeper supply-chain controls (SBOM/signing/provenance)
- Queued large-file scanning workflows

## 15) FAQ

**Where is my API URL?**

```bash
az containerapp show -g <resource-group> -n <prefix>-api --query properties.configuration.ingress.fqdn -o tsv
```

**How do I get an API key?**

Read Key Vault secret `ApiKey` in your deployment, or ask the deployment owner.

**Where do I troubleshoot stuck jobs?**

Use `docs/observability/runbook.md` and the queries under `docs/observability/kql/`.

## License

MIT - see `LICENSE`.

## Contributing & security

- Contributing guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
