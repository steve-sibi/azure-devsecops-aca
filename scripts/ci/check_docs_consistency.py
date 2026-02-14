#!/usr/bin/env python3
"""Validate docs/examples against implemented observability/runtime behavior."""

from __future__ import annotations

import sys
from pathlib import Path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    errors: list[str] = []

    readme = repo_root / "readme.md"
    if not readme.exists():
        readme = repo_root / "README.md"
    runbook = repo_root / "docs" / "observability" / "runbook.md"
    logging_guide = repo_root / "docs" / "azure-logging-guide.md"
    deploy_summary = repo_root / ".github" / "scripts" / "deploy_summary.py"
    obs_verify = repo_root / "scripts" / "gha" / "verify_observability.sh"
    api_main = repo_root / "app" / "api" / "main.py"

    unsupported_tokens = ("USE_MANAGED_IDENTITY", "SERVICEBUS_FQDN")
    for doc_path in (readme, runbook, logging_guide):
        text = _read(doc_path)
        for token in unsupported_tokens:
            if token in text:
                errors.append(f"{doc_path}: contains unsupported token `{token}`")

    summary_text = _read(deploy_summary)
    if "/dashboard" in summary_text:
        errors.append(
            f"{deploy_summary}: deploy summary still references `/dashboard` instead of `/`"
        )

    obs_text = _read(obs_verify)
    if "az monitor log-analytics query" not in obs_text:
        errors.append(
            f"{obs_verify}: missing Log Analytics query command for log verification"
        )
    if "az monitor app-insights query" not in obs_text:
        errors.append(
            f"{obs_verify}: missing App Insights query command for trace ingestion verification"
        )
    if "ContainerAppConsoleLogs_CL" not in obs_text:
        errors.append(
            f"{obs_verify}: missing ContainerAppConsoleLogs_CL query used for log verification"
        )
    if "query_appi_traces" not in obs_text:
        errors.append(
            f"{obs_verify}: missing explicit App Insights traces query definition"
        )

    api_text = _read(api_main)
    if '@app.get("/", response_class=HTMLResponse' not in api_text:
        errors.append(
            f"{api_main}: expected dashboard route `GET /` was not found"
        )

    if errors:
        print("[docs-check] FAIL")
        for item in errors:
            print(f"- {item}")
        return 1

    print("[docs-check] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
