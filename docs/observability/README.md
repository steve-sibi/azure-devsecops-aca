# Observability Assets

This folder contains reusable observability artifacts:

- `kql/`: Log Analytics queries for day-2 operations.
- `runbook.md`: triage guide for common incidents.

Recommended usage:
1. Apply Terraform monitoring resources in `infra/monitoring.tf`.
2. Open Log Analytics and run the relevant query from `kql/`.
3. Follow `runbook.md` for diagnosis and remediation paths.
