# CI/CD Workflows

This page documents the deployment and release automation used in this repository.

## At a glance

| Workflow | File | Trigger | Primary purpose |
| --- | --- | --- | --- |
| CI | `.github/workflows/ci.yml` | `pull_request`, `push` to `main` | Quality gates, selective security scans, optional image build/push, CD handoff |
| Deploy | `.github/workflows/deploy.yml` | `workflow_dispatch` | Bootstrap or update Azure infrastructure; optional full app rollout |
| App Deploy (CD) | `.github/workflows/app-deploy.yml` | `workflow_call`, `workflow_dispatch` | Fast rollout for app image updates to existing ACA apps |
| Destroy | `.github/workflows/destroy.yml` | `workflow_dispatch` | Terraform destroy and resource-group deletion |
| KEDA Scale Test | `.github/workflows/keda-scale-test.yml` | `workflow_dispatch` | Validate queue-driven scale behavior |

## CI (`.github/workflows/ci.yml`)

### Trigger and scope

- CI runs on every PR and on every push to `main`.
- A `changes` job uses `dorny/paths-filter` to detect which areas changed (`api`, `worker`, `clamav`, `infra`, `python`).
- Downstream jobs run only when needed. Example: `python-quality` runs only when Python-related files changed.

This means docs-only changes still trigger the workflow, but most heavyweight jobs may be skipped.

### Main CI jobs

1. `changes`
- Detects change scope and publishes outputs used by all other jobs.
- Exposes `RUN_PR_SECURITY_SCANS` behavior for PR security scan opt-in.

2. `actionlint`
- Lints GitHub workflow files.

3. `deploy-gate` (push to `main` only)
- Checks whether auto-deploy is allowed (`ACA_DEPLOY_ENABLED=true`) and whether the target Azure environment exists.
- Prevents build/deploy when required Azure secrets or infrastructure are missing.

4. `python-quality`
- Ruff, docs consistency check, telemetry dependency contract check, Python compile check, pytest.
- Runs only when Python-related files changed.

5. `iac-and-docker-lint`
- Terraform `fmt`, `init` (backend disabled), `validate`.
- Hadolint for changed Dockerfiles.
- Checkov SARIF upload on `main` pushes, or on PRs only when `RUN_PR_SECURITY_SCANS=true`.

6. `build-and-scan` (PR opt-in)
- Builds and Trivy-scans changed images on PRs when `RUN_PR_SECURITY_SCANS=true`.

7. `build-and-push` (push to `main` only)
- Builds and pushes changed images to ACR when app files changed and `deploy-gate` allows deployment.
- Uploads Trivy SARIF for image scans.

8. `app-deploy` (reusable workflow call)
- Runs after successful `build-and-push`.
- Calls `.github/workflows/app-deploy.yml` with `build_images=false` and explicit image references so images are built once.

## Deploy (`.github/workflows/deploy.yml`)

Manual workflow for infrastructure and optional full rollout.

### Inputs

Key inputs include:

- `mode`: `full` or `infra-only`
- `region`, `prefix`, `resource_group`
- Terraform state settings: `tfstate_sa`, `tfstate_container`, `tfstate_key`
- Queue settings: `queue_name`, optional `scan_queue_name`
- `apply_requires_approval`: optional environment approval gate

### Execution flow

1. `infra-plan`
- Azure login via OIDC.
- Terraform bootstrap + plan.
- Uploads plan artifacts and summary.

2. `infra-apply-auto` or `infra-apply-approved`
- Applies the saved plan, with optional GitHub Environment approval.

3. `build-and-push` (skipped when `mode=infra-only`)
- Builds and pushes API, worker, and ClamAV images.

4. `create-apps-and-test` (skipped when `mode=infra-only`)
- Applies app resources.
- Runs smoke and end-to-end checks (`/healthz`, submit/poll scan).

### Infra-only mode

Use `mode=infra-only` for infrastructure updates without changing running app images.

Typical use cases:

- Service Bus / storage / Key Vault changes
- Monitoring and alerting updates
- Identity and access wiring changes

## App Deploy (CD) (`.github/workflows/app-deploy.yml`)

Reusable/manual workflow for rolling updated containers to existing apps.

### Behavior

- Supports both `workflow_call` (from CI) and `workflow_dispatch` (manual).
- Can build/push images (`build_images=true`) or reuse provided image refs (`build_images=false`).
- Can deploy specific components only: `deploy_api`, `deploy_worker`, `deploy_clamav`.
- Updates existing ACA apps in place via `az containerapp update`.
- Optional smoke test (`GET /healthz`).

## Destroy (`.github/workflows/destroy.yml`)

Manual teardown workflow.

- Requires explicit `confirm_destroy=DESTROY`.
- Runs Terraform destroy and then deletes the resource group.
- Uses same core inputs as Deploy to avoid drift.

## Required secrets and recommended variables

### Secrets

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

### Recommended variables

- `ACA_DEPLOY_ENABLED`
- `ACA_PREFIX`
- `ACA_RESOURCE_GROUP`
- `RUN_PR_SECURITY_SCANS`
- `ACA_KV_SECRET_READER_OBJECT_IDS_JSON`
- `ACA_MONITOR_ACTION_GROUP_EMAIL_RECEIVERS_JSON`
- `ACA_MONITOR_ALERTS_ENABLED`
- `ACA_MONITOR_WORKBOOK_ENABLED`
- `ACA_E2E_SCAN_URL`
- `ACA_OBS_VERIFY_ATTEMPTS`
- `ACA_OBS_VERIFY_SLEEP_SECONDS`
- `ACA_OBS_VERIFY_LOOKBACK_MINUTES`
- `ACA_OTEL_TRACES_SAMPLER_RATIO`

## Related docs

- Root onboarding: [`readme.md`](../readme.md)
- Configuration/env reference: [`docs/configuration-reference.md`](configuration-reference.md)
- Local Terraform workflow: [`docs/terraform-local.md`](terraform-local.md)
