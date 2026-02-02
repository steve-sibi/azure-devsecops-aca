# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |

Only the latest version on the `main` branch is actively maintained.

## Reporting a Vulnerability

If you believe you've found a security vulnerability, please do not open a public issue.

**Preferred**: Open a private [GitHub Security Advisory](https://github.com/YOUR_USERNAME/azure-devsecops-aca/security/advisories/new) for this repository.

If that's not available, contact the maintainer directly.

### What to include

- A clear description of the issue and potential impact
- Reproduction steps (proof-of-concept if possible)
- Affected files/paths and any relevant logs
- Your suggested fix (optional but appreciated)

### Response timeline

- **Acknowledgment**: Within 48 hours (I'll try)
- **Initial assessment**: Within 7 days
- **Resolution target**: Depends on severity; critical issues within 30 days

## Security Features

This project implements several security controls:

- **SSRF protection**: Only HTTPS URLs on port 443; blocks private/loopback/link-local IPs
- **API key authentication**: Required for scan endpoints; per-key rate limiting
- **Secrets management**: Azure Key Vault with managed identity; no hardcoded secrets
- **CI/CD security**: GitHub OIDC (no long-lived credentials); AAD backend for Terraform state
- **Container scanning**: Trivy + Checkov in CI pipeline
- **Input validation**: URL and payload size limits; request schema validation

## Safe Use Disclaimer

This project downloads and scans remote content. Only scan URLs you own or are authorized to test. The author(s) are not responsible for misuse.

