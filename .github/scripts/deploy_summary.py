#!/usr/bin/env python3
"""
Generate rich markdown summaries for the deploy workflow.

This script is called by the deploy.yml workflow to produce GitHub Step Summary
output with Azure Portal links, status badges, resource tables, and troubleshooting info.

Usage:
    python deploy_summary.py <command> [options]

Commands:
    infra-bootstrap   Generate summary for infrastructure bootstrap job
    build-push        Generate summary for container image build/push job
    create-apps       Generate summary for app deployment and E2E tests
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Azure Portal URL builders
# ---------------------------------------------------------------------------

AZURE_PORTAL = "https://portal.azure.com"


def portal_resource_group_url(subscription_id: str, rg: str) -> str:
    """Direct link to a Resource Group in Azure Portal."""
    return (
        f"{AZURE_PORTAL}/#@/resource/subscriptions/{subscription_id}"
        f"/resourceGroups/{rg}/overview"
    )


def portal_container_app_url(subscription_id: str, rg: str, app_name: str) -> str:
    """Direct link to a Container App in Azure Portal."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.App/containerApps/{app_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/containerapp"


def portal_container_app_logs_url(subscription_id: str, rg: str, app_name: str) -> str:
    """Direct link to Container App log stream."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.App/containerApps/{app_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/logStream"


def portal_acr_url(subscription_id: str, rg: str, acr_name: str) -> str:
    """Direct link to Azure Container Registry."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.ContainerRegistry/registries/{acr_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/overview"


def portal_service_bus_url(subscription_id: str, rg: str, ns_name: str) -> str:
    """Direct link to Service Bus namespace."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.ServiceBus/namespaces/{ns_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/overview"


def portal_app_insights_url(subscription_id: str, rg: str, appi_name: str) -> str:
    """Direct link to Application Insights."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.Insights/components/{appi_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/overview"


def portal_key_vault_url(subscription_id: str, rg: str, kv_name: str) -> str:
    """Direct link to Key Vault."""
    resource_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        f"/providers/Microsoft.KeyVault/vaults/{kv_name}"
    )
    return f"{AZURE_PORTAL}/#@/resource{resource_id}/overview"


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------


def status_icon(status: str) -> str:
    """Map status strings to ASCII icons."""
    mapping = {
        "success": "[PASS]",
        "completed": "[PASS]",
        "healthy": "[PASS]",
        "running": "[RUN]",
        "pending": "[WAIT]",
        "queued": "[WAIT]",
        "in_progress": "[...]",
        "failure": "[FAIL]",
        "error": "[FAIL]",
        "failed": "[FAIL]",
        "cancelled": "[SKIP]",
        "skipped": "[SKIP]",
        "unknown": "[?]",
    }
    return mapping.get(status.lower().replace("-", "_"), "[?]")


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    """Generate a markdown table."""
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return "\n".join(lines)


def md_collapsible(title: str, content: str) -> str:
    """Wrap content in a collapsible details block."""
    return f"<details>\n<summary>{title}</summary>\n\n{content}\n\n</details>"


def md_code_block(content: str, lang: str = "") -> str:
    """Wrap content in a fenced code block."""
    return f"```{lang}\n{content}\n```"


def md_link(text: str, url: str) -> str:
    """Create a markdown link."""
    return f"[{text}]({url})"


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------


def get_env(name: str, default: str = "") -> str:
    """Get environment variable with default."""
    return os.environ.get(name, default)


def get_env_json(name: str) -> Any:
    """Parse environment variable as JSON."""
    raw = get_env(name, "{}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# Summary generators
# ---------------------------------------------------------------------------


@dataclass
class DeployContext:
    """Common deployment context from environment."""

    subscription_id: str
    resource_group: str
    prefix: str
    region: str
    image_tag: str
    run_id: str
    run_url: str
    actor: str
    sha: str

    @classmethod
    def from_env(cls) -> "DeployContext":
        return cls(
            subscription_id=get_env(
                "AZURE_SUBSCRIPTION_ID", get_env("ARM_SUBSCRIPTION_ID")
            ),
            resource_group=get_env("RG"),
            prefix=get_env("PREFIX"),
            region=get_env("REGION"),
            image_tag=get_env("IMAGE_TAG", get_env("GITHUB_SHA", "dev")[:7]),
            run_id=get_env("GITHUB_RUN_ID"),
            run_url=f"{get_env('GITHUB_SERVER_URL')}/{get_env('GITHUB_REPOSITORY')}/actions/runs/{get_env('GITHUB_RUN_ID')}",
            actor=get_env("GITHUB_ACTOR"),
            sha=get_env("GITHUB_SHA", "")[:7],
        )


def generate_infra_bootstrap_summary() -> str:
    """Generate summary for infra-bootstrap job."""
    ctx = DeployContext.from_env()

    # Resource names
    kv_name = f"{ctx.prefix}-kv"
    acr_name = f"{ctx.prefix}acr"
    la_name = f"{ctx.prefix}-la"
    sbns_name = f"{ctx.prefix}-sbns"
    tfstate_sa = get_env("TFSTATE_SA")

    lines = [
        "## Infrastructure Bootstrap",
        "",
        f"**Timestamp:** {get_timestamp()}",
        "",
        "### Deployment Configuration",
        "",
    ]

    # Config table
    config_rows = [
        ["Region", f"`{ctx.region}`"],
        ["Resource Group", f"`{ctx.resource_group}`"],
        ["Prefix", f"`{ctx.prefix}`"],
        [
            "Terraform State",
            f"`{tfstate_sa}/{get_env('TFSTATE_CONTAINER')}/{get_env('TFSTATE_KEY')}`",
        ],
    ]
    lines.append(md_table(["Property", "Value"], config_rows))

    lines.append("")
    lines.append("### Resources Created/Verified")
    lines.append("")

    # Resources with portal links
    if ctx.subscription_id:
        resource_rows = [
            [
                "Key Vault",
                f"`{kv_name}`",
                md_link(
                    "Portal",
                    portal_key_vault_url(
                        ctx.subscription_id, ctx.resource_group, kv_name
                    ),
                ),
            ],
            [
                "Container Registry",
                f"`{acr_name}`",
                md_link(
                    "Portal",
                    portal_acr_url(ctx.subscription_id, ctx.resource_group, acr_name),
                ),
            ],
            ["Log Analytics", f"`{la_name}`", "--"],
            ["Terraform State SA", f"`{tfstate_sa}`", "--"],
        ]
        lines.append(md_table(["Resource", "Name", "Link"], resource_rows))
    else:
        lines.append("_Subscription ID not available for Portal links._")

    lines.append("")
    lines.append("### Next Steps")
    lines.append("")
    lines.append(
        "The `build-and-push` job will now build container images and push to ACR."
    )

    return "\n".join(lines)


def generate_build_push_summary() -> str:
    """Generate summary for build-and-push job."""
    ctx = DeployContext.from_env()

    acr_login_server = get_env("ACR_LOGIN_SERVER")
    api_image = get_env("API_IMAGE")
    worker_image = get_env("WORKER_IMAGE")
    clamav_image = get_env("CLAMAV_IMAGE")

    lines = [
        "## Container Images Built",
        "",
        f"**Timestamp:** {get_timestamp()}",
        "",
        "### Images Pushed to ACR",
        "",
    ]

    image_rows = [
        ["API", f"`{api_image}`"],
        ["Worker", f"`{worker_image}`"],
        ["ClamAV", f"`{clamav_image}`"],
    ]
    lines.append(md_table(["Component", "Image Tag"], image_rows))

    lines.append("")
    lines.append("### Build Details")
    lines.append("")

    acr_name = (
        acr_login_server.split(".")[0] if acr_login_server else f"{ctx.prefix}acr"
    )
    details_rows = [
        ["ACR", f"`{acr_login_server}`"],
        ["Image Tag", f"`{ctx.image_tag}`"],
        ["Git SHA", f"`{ctx.sha}`"],
    ]
    lines.append(md_table(["Property", "Value"], details_rows))

    if ctx.subscription_id:
        lines.append("")
        lines.append(
            md_link(
                "View images in Azure Portal",
                portal_acr_url(ctx.subscription_id, ctx.resource_group, acr_name),
            )
        )

    lines.append("")
    lines.append("### Next Steps")
    lines.append("")
    lines.append("The `create-apps` job will deploy these images to Container Apps.")

    return "\n".join(lines)


def generate_create_apps_summary() -> str:
    """Generate summary for create-apps job with E2E test results."""
    ctx = DeployContext.from_env()

    # Get test results from environment (set by deploy script)
    api_url = get_env("API_URL")
    health_status = get_env("HEALTH_STATUS", "unknown")
    e2e_status = get_env("E2E_STATUS", "unknown")
    e2e_job_id = get_env("E2E_JOB_ID", "")
    e2e_duration = get_env("E2E_DURATION_SECONDS", "")

    # Queue depths (set by deploy script)
    tasks_queue_active = get_env("TASKS_QUEUE_ACTIVE", "—")
    tasks_queue_dead = get_env("TASKS_QUEUE_DEAD", "—")
    scan_queue_active = get_env("SCAN_QUEUE_ACTIVE", "—")
    scan_queue_dead = get_env("SCAN_QUEUE_DEAD", "—")

    # Replica counts
    api_replicas = get_env("API_REPLICAS", "—")
    fetcher_replicas = get_env("FETCHER_REPLICAS", "—")
    worker_replicas = get_env("WORKER_REPLICAS", "—")

    lines = [
        "## Deployment Complete",
        "",
        f"**Timestamp:** {get_timestamp()}",
        "",
    ]

    # Overall status banner
    all_success = health_status == "healthy" and e2e_status == "completed"
    if all_success:
        lines.append(
            "> **[PASS] All checks passed** -- API is healthy and E2E scan completed successfully."
        )
    elif health_status == "healthy":
        lines.append(
            f"> **[WARN] Partial success** -- API is healthy but E2E test status: `{e2e_status}`"
        )
    else:
        lines.append(
            f"> **[FAIL] Issues detected** -- Health: `{health_status}`, E2E: `{e2e_status}`"
        )

    lines.append("")
    lines.append("### Deployment Configuration")
    lines.append("")

    config_rows = [
        ["Region", f"`{ctx.region}`"],
        ["Resource Group", f"`{ctx.resource_group}`"],
        ["Prefix", f"`{ctx.prefix}`"],
        ["Image Tag", f"`{ctx.sha}`"],
    ]
    lines.append(md_table(["Property", "Value"], config_rows))

    # API Endpoint
    lines.append("")
    lines.append("### API Endpoint")
    lines.append("")
    if api_url:
        lines.append(f"**URL:** {api_url}")
        lines.append("")
        lines.append(f"- Health check: `GET {api_url}/healthz`")
        lines.append(f"- Submit scan: `POST {api_url}/scan`")
        lines.append(f"- Dashboard: `{api_url}/dashboard`")
    else:
        lines.append("_API URL not available._")

    # Test Results
    lines.append("")
    lines.append("### Test Results")
    lines.append("")

    test_rows = [
        [f"{status_icon(health_status)} Health Check", health_status.title()],
        [f"{status_icon(e2e_status)} E2E Scan Test", e2e_status.title()],
    ]
    if e2e_job_id:
        test_rows.append(["Job ID", f"`{e2e_job_id}`"])
    if e2e_duration:
        test_rows.append(["Duration", f"{e2e_duration}s"])
    lines.append(md_table(["Check", "Status"], test_rows))

    # Container Apps Status
    lines.append("")
    lines.append("### Container Apps")
    lines.append("")

    api_name = f"{ctx.prefix}-api"
    fetcher_name = f"{ctx.prefix}-fetcher"
    worker_name = f"{ctx.prefix}-worker"

    if ctx.subscription_id:
        apps_rows = [
            [
                "API",
                api_replicas,
                md_link(
                    "Portal",
                    portal_container_app_url(
                        ctx.subscription_id, ctx.resource_group, api_name
                    ),
                ),
                md_link(
                    "Logs",
                    portal_container_app_logs_url(
                        ctx.subscription_id, ctx.resource_group, api_name
                    ),
                ),
            ],
            [
                "Fetcher",
                fetcher_replicas,
                md_link(
                    "Portal",
                    portal_container_app_url(
                        ctx.subscription_id, ctx.resource_group, fetcher_name
                    ),
                ),
                md_link(
                    "Logs",
                    portal_container_app_logs_url(
                        ctx.subscription_id, ctx.resource_group, fetcher_name
                    ),
                ),
            ],
            [
                "Worker",
                worker_replicas,
                md_link(
                    "Portal",
                    portal_container_app_url(
                        ctx.subscription_id, ctx.resource_group, worker_name
                    ),
                ),
                md_link(
                    "Logs",
                    portal_container_app_logs_url(
                        ctx.subscription_id, ctx.resource_group, worker_name
                    ),
                ),
            ],
        ]
        lines.append(md_table(["App", "Replicas", "Portal", "Logs"], apps_rows))
    else:
        apps_rows = [
            ["API", api_replicas],
            ["Fetcher", fetcher_replicas],
            ["Worker", worker_replicas],
        ]
        lines.append(md_table(["App", "Replicas"], apps_rows))

    # Queue Status
    lines.append("")
    lines.append("### Service Bus Queues")
    lines.append("")

    queue_rows = [
        ["tasks (fetch)", tasks_queue_active, tasks_queue_dead],
        ["tasks-scan (analyze)", scan_queue_active, scan_queue_dead],
    ]
    lines.append(md_table(["Queue", "Active", "Dead Letter"], queue_rows))

    # Portal Quick Links
    if ctx.subscription_id:
        lines.append("")
        lines.append("### Azure Portal Quick Links")
        lines.append("")
        lines.append(
            f"- {md_link('Resource Group', portal_resource_group_url(ctx.subscription_id, ctx.resource_group))}"
        )
        lines.append(
            f"- {md_link('Application Insights', portal_app_insights_url(ctx.subscription_id, ctx.resource_group, f'{ctx.prefix}-appi'))}"
        )
        lines.append(
            f"- {md_link('Service Bus', portal_service_bus_url(ctx.subscription_id, ctx.resource_group, f'{ctx.prefix}-sbns'))}"
        )
        lines.append(
            f"- {md_link('Key Vault', portal_key_vault_url(ctx.subscription_id, ctx.resource_group, f'{ctx.prefix}-kv'))}"
        )

    # Troubleshooting section (if issues)
    if not all_success:
        lines.append("")
        lines.append("### Troubleshooting")
        lines.append("")
        lines.append("If the deployment failed, try these commands locally:")
        lines.append("")

        troubleshooting = f"""# Check container app status
az containerapp show -g {ctx.resource_group} -n {api_name} -o table

# View recent logs
az containerapp logs show -g {ctx.resource_group} -n {api_name} --type console --tail 100

# Check revisions
az containerapp revision list -g {ctx.resource_group} -n {api_name} -o table

# Check Service Bus queue depth
az servicebus queue show -g {ctx.resource_group} --namespace-name {ctx.prefix}-sbns -n tasks \\
  --query "{{active:countDetails.activeMessageCount, dead:countDetails.deadLetterMessageCount}}"
"""
        lines.append(md_code_block(troubleshooting.strip(), "bash"))

    # Quick test commands
    lines.append("")
    lines.append("### Quick Test Commands")
    lines.append("")

    if api_url:
        test_commands = f"""# Get API key from Key Vault
API_KEY=$(az keyvault secret show --vault-name {ctx.prefix}-kv --name ApiKey --query value -o tsv)

# Health check
curl -s {api_url}/healthz | jq

# Submit a scan
curl -s -X POST {api_url}/scan \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $API_KEY" \\
  -d '{{"url": "https://example.com", "type": "url"}}' | jq

# Check scan result (replace JOB_ID)
curl -s {api_url}/scan/JOB_ID -H "X-API-Key: $API_KEY" | jq
"""
        lines.append(md_code_block(test_commands.strip(), "bash"))
    else:
        lines.append("_API URL not available for test commands._")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deploy workflow summaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "command",
        choices=["infra-bootstrap", "build-push", "create-apps"],
        help="Which summary to generate.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path (default: stdout, or GITHUB_STEP_SUMMARY if set).",
    )

    args = parser.parse_args()

    # Generate the appropriate summary
    if args.command == "infra-bootstrap":
        summary = generate_infra_bootstrap_summary()
    elif args.command == "build-push":
        summary = generate_build_push_summary()
    elif args.command == "create-apps":
        summary = generate_create_apps_summary()
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1

    # Output to file or stdout
    output_path = args.output or get_env("GITHUB_STEP_SUMMARY")
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(summary)
            f.write("\n")
    else:
        print(summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
