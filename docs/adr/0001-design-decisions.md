# ADR 0001: Design decisions

## Context

This project is meant to be a “nuke-and-recreate” portfolio demo that highlights DevSecOps, cloud-native patterns, and security controls without turning into a full production platform.

## Decisions

### Azure Container Apps (ACA)

- Chosen for a clean container-to-cloud path with managed ingress, scaling, and a simple operational story for a demo.

### Service Bus + KEDA scaling

- Service Bus provides durable async processing and clear separation between the API and worker.
- KEDA provides queue-depth-based scaling (including scale-to-zero) to demonstrate event-driven compute.

### Table Storage for results

- Table Storage is cheap, simple, and sufficient for “job status + details” in a demo.
- Local development uses Redis to keep the local loop fast.

### Key Vault secret references + UAMI

- Secrets are managed in Key Vault, referenced by Container Apps, and resolved using a user-assigned managed identity.
- This avoids embedding secrets in app config or requiring runtime calls to Key Vault.

### Defense-in-depth for SSRF

- Validation happens both at the API boundary and in the worker (including redirects) to show layered controls.

## Consequences

- The repo stays approachable and reproducible, but it deliberately avoids some production features (private networking, per-user auth, signing/provenance enforcement).

