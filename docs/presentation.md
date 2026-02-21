# Presentation + Screenshot/GIF Guide

This repo is already “portfolio-shaped” (README, threat model, ADR, CI/CD, IaC). This doc is a **runbook** for turning it into a smooth presentation with the right screenshots/GIFs and a reliable demo.

## 1) Pick the format (so you don’t over-demo)

Choose one:

- **5–7 min (screenshots + 1 short demo):** focus on architecture + security controls + a 30s UI demo.
- **10–15 min (recommended):** architecture + CI/CD DevSecOps + Azure runtime + a 2–3 min demo.
- **30 min (deep dive):** add Terraform module walkthrough + Kusto queries + scaling test.

## 2) The story to tell (one sentence per slide)

Use this narrative (it maps to the README sections):

1. **Problem:** “How do we scan URLs/files safely without turning the scanner into an SSRF / malware execution risk?”
2. **Solution:** Async two-stage pipeline on **Azure Container Apps** (API → fetcher → worker) + **DevSecOps** gates.
3. **Security posture:** SSRF protections, API-key auth + per-key rate limit, secrets via Key Vault refs + UAMI, supply-chain scanning.
4. **Cloud-native ops:** event-driven scaling (KEDA on Service Bus), log correlation, nuke-and-recreate deployments.
5. **Demo:** submit scan, show progress/status, show screenshot retrieval (optional), show file scan (ClamAV).
6. **Takeaways + next steps:** private networking/WAF, multi-tenant auth, stronger sandboxing, richer scoring.

## 3) Slide-by-slide checklist (what to cover + what to capture)

### Slide 1 — Title + value proposition (static)
- One screenshot: none required (title slide).
- Talk track: “URL + file scanner pipeline on Azure (ACA) with security gates and reproducible infra.”

### Slide 2 — Architecture (static screenshot)
- Capture: the architecture diagram from `readme.md` (high-level) or render the Mermaid sequence diagram.
- Filename: `screenshots/01-architecture.png`
- Talk track: two-stage pipeline, queues, scale-to-zero, results store, optional screenshots.

### Slide 3 — “What Terraform deploys” (static screenshot)
- Capture: a single slide/table listing the deployed resources (RG, ACR, SB, KV, Storage, ACA env, apps).
- Suggested source: README section **“What Terraform Deploys”**.
- Filename: `screenshots/02-terraform-resources.png`

### Slide 4 — CI/CD and security gates (static screenshots)
- Capture: GitHub Actions **CI** workflow summary (jobs list + green checks).
- Capture: GitHub **Security** tab (SARIF results from Checkov/Trivy).
- Filenames:
  - `screenshots/03-actions-ci.png`
  - `screenshots/04-security-sarif.png`
- Talk track: shift-left checks (lint/test + IaC scan + container scan) and “no long-lived Azure creds” via OIDC.

### Slide 5 — Secrets & identity (static screenshot)
- Capture: Key Vault + Container Apps secrets referencing KV (show names, **never secret values**).
- Filename: `screenshots/05-keyvault-refs.png`
- Talk track: KV secret refs resolved by UAMI; deploy uses GitHub OIDC.

### Slide 6 — App surface area (static screenshots)
- Capture: Swagger UI at `/docs`.
- Capture: dashboard at `/` showing completed scan details.
- Filenames:
  - `screenshots/06-swagger.png`
  - `screenshots/07-dashboard.png`
- Talk track: API key header, rate limiting, SSRF validation, results endpoints.

### Slide 7 — Security behaviors (short GIFs)
Use GIFs only for “time-based” behavior:

- **GIF A (recommended):** submit a URL scan in the dashboard and show status transitions (`queued → fetching → queued_scan → completed`).
  - Filename: `screenshots/08-ui-scan-flow.gif`
- **GIF B (optional):** screenshot viewer loads at the end (`GET /scan/{job_id}/screenshot`).
  - Filename: `screenshots/09-ui-screenshot.gif`
- Talk track: async processing; worker-only screenshot capture; API owner-protection on job IDs.

### Slide 8 — File scanning (short GIF or screenshot)
- Best: GIF showing upload → ClamAV result (it’s a satisfying “moment”).
  - Filename: `screenshots/10-file-scan.gif`
- Backup: static screenshot of the result table in `/file`.
  - Filename: `screenshots/10-file-scan.png`
- Demo input: EICAR test string/file (safe) to reliably trigger a “malicious” verdict from ClamAV.

### Slide 9 — Observability (static screenshot)
- Capture: Log Analytics query showing correlated logs across services (`api`, `fetcher`, `worker`) for one `correlation_id` or `job_id`.
- Filename: `screenshots/11-log-analytics.png`
- Talk track: structured JSON logs, correlation IDs, troubleshooting queued jobs.

### Slide 10 — Scaling (GIF, if you can capture it cleanly)
- Capture: KEDA scale-out (worker replicas go from 0 → N) after sending a burst of messages.
- Filename: `screenshots/12-keda-scale.gif`
- Talk track: event-driven scaling based on Service Bus queue depth; min=0; quick cost/ops benefits.

### Slide 11 — Cost & cleanup (static screenshot)
- Capture: Destroy workflow run summary and/or RG deletion.
- Filename: `screenshots/13-destroy.png`
- Talk track: “nuke and recreate” for demos; explain cost controls.

### Slide 12 — Wrap-up + roadmap (static)
- No screenshot needed.
- Talk track: improvements (Private Link/WAF, per-user auth, stronger content analysis).

## 4) What should be a screenshot vs a GIF?

Rule of thumb:

- Use **screenshots** for: architecture, resource lists, GitHub Actions summaries, Security/SARIF, Swagger, Key Vault/ACA config, Kusto query results.
- Use **GIFs** for: “submit → progress → done”, “scale out happens”, “upload file → scan result appears”.

Keep GIFs to **5–12 seconds** and avoid scrolling.

## 5) Capturing clean visuals (prep checklist)

Before you capture anything:

- Use a **clean browser profile** (no personal bookmarks/extensions) and **incognito** for Azure Portal.
- Set a consistent window size (e.g., 1440×900), browser zoom 100–110%.
- Hide or redact: API keys, connection strings, subscription IDs, tenant IDs, emails.
- Prefer dark mode (the UI supports it) for consistent visuals.

## 6) Tools to record GIFs (Mac-first)

### Option A (easiest): Kap (macOS)
Use Kap to record a region and export as GIF/MP4. Recommended for README-quality GIFs.

### Option B (built-in): macOS screen recording → convert to GIF
1. Press `⇧⌘5` → “Record Selected Portion”.
2. Record 5–10 seconds → stop (saves a `.mov`).
3. Convert to GIF with `ffmpeg`:

```bash
ffmpeg -i input.mov -vf "fps=12,scale=1200:-1:flags=lanczos" -loop 0 output.gif
```

Optional optimization (if you have `gifsicle`):

```bash
gifsicle -O3 output.gif -o output.gif
```

### Option C (cross-platform): ScreenToGif / LICEcap
- Windows: ScreenToGif
- Cross-platform: LICEcap (simple, but lower quality)

## 7) How to show GIFs (README vs slides)

### In the GitHub README
- Store assets under `docs/screenshots/` in the repo.
- In root `readme.md`, reference assets with repo-root paths such as `docs/screenshots/...`.
- In files under `docs/`, use doc-local paths such as `screenshots/...`.
- Example image embed in root `readme.md`:

```html
<img src="docs/screenshots/08-ui-scan-flow.gif" alt="UI scan flow" />
```

Keep GIFs small (aim for **<10 MB** each).

### In Keynote / PowerPoint
- Prefer **MP4** over GIF for quality + file size.
- Insert the MP4 and set it to loop (Keynote: Format → Movie → “Loop”).
- If you must use a GIF, drag it onto the slide (it will animate during presentation mode).

## 8) Demo script (local) — reliable 2–3 minutes

1. Start services:
   - `cp .env.example .env`
   - `docker compose up --build`
2. Open the dashboard: `http://localhost:8000/` (API key: `local-dev-key` by default).
3. Submit a safe scan: `https://example.com` → show status updates → open details.
4. Show SSRF protection quickly:
   - Try scanning `https://127.0.0.1` and point out it is blocked.
5. File scan demo:
   - Open `/file`
   - Upload a file containing the EICAR test string (or paste via “payload” option).

Optional: enable first-party screenshots locally (disabled by default):

- Set `CAPTURE_SCREENSHOTS=true` in `docker-compose.yml` (or your env) and restart.
- Then, after a scan completes, show the screenshot rendered in the dashboard (served from `GET /scan/{job_id}/screenshot`).

EICAR helper (safe test pattern) to generate a file:

```bash
EICAR='X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf "%s" "$EICAR" > eicar.txt
```

Optional CLI demo (nice for terminal-oriented audiences):

```bash
python3 scripts/aca_api.py --api-key local-dev-key scan-url https://example.com --wait
python3 scripts/aca_api.py --api-key local-dev-key jobs --limit 5
```

## 9) Demo script (Azure) — what to show in the portal

If you demo the cloud runtime, keep it short:

1. GitHub Actions: show a successful `Deploy` run (OIDC → terraform → build/push → deploy).
2. Azure Portal: Container Apps environment → show `api`, `fetcher`, `worker`.
3. Submit a scan in the UI → watch logs in Container Apps / Log Analytics.
4. (Optional) KEDA scale: run the scale test workflow or burst-submit scans and show replicas increase.

## 10) Where to put assets + naming

- Use `docs/screenshots/NN-name.ext` so README images stay ordered.
- Put GIFs next to screenshots (same folder) so links are stable.
