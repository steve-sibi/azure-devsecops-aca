# Threat model (portfolio notes)

This is a demo project, but it intentionally implements a few “real-world” controls to show security thinking.

## Assets

- API surface (public ingress) and API keys
- Service Bus queue messages (scan jobs)
- Scan results (Table Storage or Redis locally)
- Fetched artifacts (Azure Files share; Docker volume locally)
- Container images + build pipeline

## Trust boundaries

- Public internet → API (`POST /scan`)
- API → queue backend (Service Bus / Redis)
- Fetcher → public internet (downloads URLs)
- Fetcher/Worker → artifacts share (Azure Files / Docker volume)
- Apps → result store (Table Storage / Redis)
- GitHub Actions → Azure (OIDC) → Terraform / deployments

## Main threats & mitigations

### SSRF / internal network access

- Only `https://` URLs allowed; only port `443`; blocks localhost and non-public IP ranges (`app/common/url_validation.py`).
- Worker re-validates every redirect hop before downloading (defense in depth).

### Malicious content / decompression bombs / large payloads

- Download is streamed with a hard size cap (`MAX_DOWNLOAD_BYTES`) and timeouts (`REQUEST_TIMEOUT`).
- Scanning is done on the downloaded bytes (URL/domain reputation + lightweight content heuristics) without executing content.

### Abuse / DoS of the API

- API key required by default and per-key rate limiting is enforced in the API (`RATE_LIMIT_RPM`).
- Worker is event-driven and scales via KEDA on queue depth in Azure.

### Secrets leakage

- Azure path stores secrets in Key Vault; Container Apps use Key Vault secret references resolved via UAMI (no secrets in the repo).
- Deploy workflow uses GitHub OIDC (no long-lived cloud credentials).

### Supply chain / image vulnerabilities

- CI runs Checkov (IaC) and Trivy (container images) and uploads SARIF to GitHub Security.
- Dockerfiles run as non-root where possible.

## YARA-based web content analysis

The web analysis pipeline applies YARA rules to inline script content extracted from fetched HTML pages. This provides lightweight heuristic detection without requiring a full malware sandbox.

### Bundled rules (`app/common/web_yara_rules.yar`)

| Rule | Severity | Detects |
|------|----------|--------|
| `Web_Suspicious_JS_MEDIUM` | Medium | ActiveX, WScript, PowerShell references, obfuscation patterns (eval + fromCharCode combos) |
| `Web_Fingerprinting_INFO` | Info | FingerprintJS, AudioContext/WebGL/Canvas fingerprinting APIs |
| `Web_Eval_Usage_INFO` | Info | `eval()` and `new Function()` usage |
| `Web_InnerHTML_Usage_INFO` | Info | `innerHTML`/`outerHTML` usage |
| `Web_Tracking_Inline_INFO` | Info | Inline tracking calls (`gtag`, `ga`, `fbq`, `dataLayer`) |

### Customization

Set `WEB_YARA_RULES_PATH` to point to a custom `.yar` file to replace the bundled rules. The rules file is compiled once at startup and cached.

## Non-goals (v1)

- Private networking / Private Link / WAF
- Full identity-based multi-tenant auth (beyond API key ownership and per-key controls)
- Sandbox detonation of payloads
