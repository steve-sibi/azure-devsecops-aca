#!/usr/bin/env python3
"""Validate documentation stays aligned with the supported public surface."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

HTTP_METHODS = {"get", "post", "delete", "put", "patch"}
AUTO_DOC_ROUTES = {
    ("GET", "/docs"),
    ("GET", "/redoc"),
}
IGNORED_PUBLIC_ROUTES = {
    ("GET", "/favicon.ico"),
}
REQUIRED_CLI_COMMANDS = {
    "health",
    "scan-url",
    "status",
    "wait",
    "watch",
    "jobs",
    "history",
    "clear-history",
    "clear-server-history",
    "screenshot",
    "scan-file",
    "scan-payload",
    "admin-list-keys",
    "admin-mint-key",
    "admin-revoke-key",
    "env",
    "doctor",
    "config show",
}
REQUIRED_API_USAGE_CLI_ENV_VARS = {
    "ACA_BASE_URL",
    "API_URL",
    "ACA_API_KEY_HEADER",
    "API_KEY_HEADER",
    "ACA_ENV_FILE",
    "ACA_API_HISTORY",
    "ACA_RG",
    "ACA_API_APP",
    "ACA_KV",
    "ACA_API_KEY_SECRET_NAME",
}
SUPPORTED_CONFIG_VARS = {
    "ACA_API_APP",
    "ACA_API_HISTORY",
    "ACA_API_KEY",
    "ACA_API_KEYS",
    "ACA_API_KEY_HEADER",
    "ACA_API_KEY_SECRET_NAME",
    "ACA_BASE_URL",
    "ACA_ENV_FILE",
    "ACA_KV",
    "ACA_RG",
    "API_ADMIN_KEY",
    "API_ADMIN_KEYS",
    "API_FQDN",
    "API_KEY",
    "API_KEYS",
    "API_KEY_HEADER",
    "API_KEY_MINT_BYTES",
    "API_KEY_MINT_PREFIX",
    "API_KEY_STORE_ENABLED",
    "API_KEY_STORE_PARTITION",
    "API_URL",
    "APPINSIGHTS_CONN",
    "APPLICATIONINSIGHTS_CONNECTION_STRING",
    "ARTIFACT_DELETE_ON_SUCCESS",
    "ARTIFACT_DIR",
    "BATCH_SIZE",
    "BLOCK_PRIVATE_NETWORKS",
    "CAPTURE_SCREENSHOTS",
    "CLAMAV_HOST",
    "CLAMAV_PORT",
    "CLAMAV_TIMEOUT_SECONDS",
    "FILE_SCAN_INCLUDE_VERSION",
    "FILE_SCAN_MAX_BYTES",
    "LIVE_UPDATES_BACKEND",
    "LOG_FORMAT",
    "MAX_DASHBOARD_POLL_SECONDS",
    "MAX_DOWNLOAD_BYTES",
    "MAX_REDIRECTS",
    "MAX_RETRIES",
    "MAX_WAIT",
    "OTEL_ENABLED",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_SERVICE_NAMESPACE",
    "OTEL_SERVICE_VERSION",
    "OTEL_TRACES_SAMPLER_RATIO",
    "PREFETCH",
    "QUEUE_BACKEND",
    "QUEUE_NAME",
    "RATE_LIMIT_READ_RPM",
    "RATE_LIMIT_RPM",
    "RATE_LIMIT_WINDOW_SECONDS",
    "RATE_LIMIT_WRITE_RPM",
    "REDIS_API_KEY_INDEX_KEY",
    "REDIS_API_KEY_PREFIX",
    "REDIS_DLQ_KEY",
    "REDIS_FETCHER_DLQ_KEY",
    "REDIS_LIVE_UPDATES_BLOCK_MS",
    "REDIS_LIVE_UPDATES_MAXLEN",
    "REDIS_LIVE_UPDATES_STREAM_PREFIX",
    "REDIS_QUEUE_KEY",
    "REDIS_RESULT_PREFIX",
    "REDIS_RESULT_TTL_SECONDS",
    "REDIS_SCAN_QUEUE_KEY",
    "REDIS_URL",
    "REDIS_URL_INDEX_PREFIX",
    "REQUEST_TIMEOUT",
    "REQUIRE_API_KEY",
    "RESULT_BACKEND",
    "RESULT_DETAILS_MAX_BYTES",
    "RESULT_PARTITION",
    "RESULT_STORE_CONN",
    "RESULT_TABLE",
    "SCAN_QUEUE_NAME",
    "SCREENSHOT_CONTAINER",
    "SCREENSHOT_FORMAT",
    "SCREENSHOT_FULL_PAGE",
    "SCREENSHOT_JPEG_QUALITY",
    "SCREENSHOT_LOCALE",
    "SCREENSHOT_REDIS_PREFIX",
    "SCREENSHOT_SETTLE_MS",
    "SCREENSHOT_TIMEOUT_SECONDS",
    "SCREENSHOT_TTL_SECONDS",
    "SCREENSHOT_USER_AGENT",
    "SCREENSHOT_VIEWPORT_HEIGHT",
    "SCREENSHOT_VIEWPORT_WIDTH",
    "SERVICEBUS_CONN",
    "TLD_EXTRACT_CACHE_DIR",
    "URL_DEDUPE_INDEX_PARTITION",
    "URL_DEDUPE_IN_PROGRESS_TTL_SECONDS",
    "URL_DEDUPE_SCOPE",
    "URL_DEDUPE_TTL_SECONDS",
    "URL_RESULT_VISIBILITY_DEFAULT",
    "WEBPUBSUB_CONNECTION_STRING",
    "WEBPUBSUB_CONN",
    "WEBPUBSUB_GROUP_PREFIX",
    "WEBPUBSUB_HUB",
    "WEBPUBSUB_TOKEN_TTL_MINUTES",
    "WEBPUBSUB_USER_GROUP_PREFIX",
    "WEB_MAX_HEADERS",
    "WEB_MAX_HEADER_VALUE_LEN",
    "WEB_MAX_HTML_BYTES",
    "WEB_MAX_INLINE_SCRIPT_CHARS",
    "WEB_MAX_RESOURCES",
    "WEB_TRACKING_FILTERS_PATH",
    "WEB_WHOIS_TIMEOUT_SECONDS",
    "WEB_YARA_RULES_PATH",
    "WORKER_MODE",
}
INTERNAL_CONFIG_VARS = {
    "JOB_INDEX_PARTITION_PREFIX",
    "PORT",
    "REDIS_JOB_INDEX_HASH_PREFIX",
    "REDIS_JOB_INDEX_ZSET_PREFIX",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_literal_assignment(path: Path, name: str):
    tree = ast.parse(_read(path), filename=str(path))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                return ast.literal_eval(value)
    raise ValueError(f"{path}: assignment for {name} not found")


def _extract_public_routes(paths: list[Path]) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for path in paths:
        tree = ast.parse(_read(path), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                func = deco.func
                if not isinstance(func, ast.Attribute):
                    continue
                if func.attr not in HTTP_METHODS:
                    continue
                if not isinstance(func.value, ast.Name) or func.value.id not in {
                    "app",
                    "router",
                }:
                    continue
                if not deco.args:
                    continue
                arg = deco.args[0]
                if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                    continue
                routes.add((func.attr.upper(), arg.value.split("?", 1)[0].strip()))
    return routes


def _extract_doc_routes(text: str) -> set[tuple[str, str]]:
    out = set()
    for method, path in re.findall(r"`(GET|POST|DELETE|PUT|PATCH)\s+([^`]+)`", text):
        out.add((method.upper(), path.split("?", 1)[0].strip()))
    return out


def _extract_env_names(paths: list[Path]) -> set[str]:
    out: set[str] = set()
    patterns = (
        r'os\.getenv\("([A-Z0-9_]+)"',
        r'os\.environ\.get\("([A-Z0-9_]+)"',
        r'env_map\.get\("([A-Z0-9_]+)"',
        r'_env_(?:int|float|bool)\("([A-Z0-9_]+)"',
        r'_env_flag\("([A-Z0-9_]+)"',
        r'_parse_int\("([A-Z0-9_]+)"',
        r'\$\{([A-Z0-9_]+):-[^}]*\}',
    )
    for path in paths:
        text = _read(path)
        for pattern in patterns:
            out.update(re.findall(pattern, text))
    return out


def _extract_doc_vars(text: str) -> set[str]:
    return set(re.findall(r"`([A-Z0-9_]+)`", text))


def _extract_cli_commands(text: str) -> set[str]:
    return set(re.findall(r'cmd_parsers\["([^"]+)"\]\s*=', text))


def _doc_mentions_command(text: str, command: str) -> bool:
    return any(
        pattern in text
        for pattern in (
            f"./scripts/aca {command}",
            f"aca {command}",
            f"`{command}`",
        )
    )


def _sorted_routes(routes: set[tuple[str, str]]) -> list[str]:
    return [f"{method} {path}" for method, path in sorted(routes)]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    errors: list[str] = []

    readme = repo_root / "readme.md"
    if not readme.exists():
        readme = repo_root / "README.md"
    api_usage = repo_root / "docs" / "api-usage.md"
    config_ref = repo_root / "docs" / "configuration-reference.md"
    runbook = repo_root / "docs" / "observability" / "runbook.md"
    logging_guide = repo_root / "docs" / "structured-logging-and-tracing.md"
    deploy_summary = repo_root / ".github" / "scripts" / "deploy_summary.py"
    obs_verify = repo_root / "scripts" / "gha" / "verify_observability.sh"
    docker_cleanup = repo_root / "scripts" / "docker_cleanup.sh"
    api_main = repo_root / "app" / "api" / "main.py"
    parser_path = repo_root / "src" / "aca_cli" / "parser.py"
    cli_core = repo_root / "src" / "aca_cli" / "core.py"
    status_path = repo_root / "app" / "common" / "statuses.py"

    unsupported_tokens = ("USE_MANAGED_IDENTITY", "SERVICEBUS_FQDN")
    for doc_path in (readme, runbook, logging_guide, api_usage, config_ref):
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
        errors.append(f"{api_main}: expected dashboard route `GET /` was not found")

    readme_text = _read(readme)
    docker_cleanup_text = _read(docker_cleanup)
    if (
        "PRUNE_BUILD_CACHE" in readme_text
        and "PRUNE_BUILD_CACHE" not in docker_cleanup_text
    ):
        errors.append(
            f"{readme}: references `PRUNE_BUILD_CACHE`, but {docker_cleanup} does not support it"
        )
    if "--keep-images" in readme_text and "--keep-images" not in docker_cleanup_text:
        errors.append(
            f"{readme}: references `--keep-images`, but {docker_cleanup} does not support it"
        )
    if "--profile observability" not in docker_cleanup_text:
        errors.append(
            f"{docker_cleanup}: missing `--profile observability` flag (jaeger cleanup)"
        )

    route_paths = [
        repo_root / "app" / "api" / "main.py",
        repo_root / "app" / "api" / "routes" / "scan.py",
        repo_root / "app" / "api" / "routes" / "file_scan.py",
        repo_root / "app" / "api" / "routes" / "admin.py",
        repo_root / "app" / "api" / "routes" / "realtime.py",
    ]
    actual_routes = (
        _extract_public_routes(route_paths) | AUTO_DOC_ROUTES
    ) - IGNORED_PUBLIC_ROUTES
    documented_routes = _extract_doc_routes(_read(api_usage))
    missing_routes = actual_routes - documented_routes
    extra_routes = documented_routes - actual_routes
    if missing_routes:
        errors.append(
            f"{api_usage}: missing documented routes: {', '.join(_sorted_routes(missing_routes))}"
        )
    if extra_routes:
        errors.append(
            f"{api_usage}: documents routes not found in app: {', '.join(_sorted_routes(extra_routes))}"
        )

    try:
        status_choices = set(_load_literal_assignment(cli_core, "SCAN_STATUS_CHOICES"))
    except Exception as exc:
        errors.append(f"{cli_core}: {exc}")
        status_choices = set()
    api_usage_text = _read(api_usage)
    missing_statuses = sorted(
        status for status in status_choices if f"`{status}`" not in api_usage_text
    )
    if missing_statuses:
        errors.append(
            f"{api_usage}: missing documented statuses: {', '.join(missing_statuses)}"
        )

    parser_text = _read(parser_path)
    parser_commands = _extract_cli_commands(parser_text)
    missing_parser_commands = sorted(
        cmd for cmd in REQUIRED_CLI_COMMANDS if cmd not in parser_commands
    )
    if missing_parser_commands:
        errors.append(
            f"{parser_path}: missing required CLI command definitions: {', '.join(missing_parser_commands)}"
        )
    undocumented_commands = sorted(
        cmd for cmd in REQUIRED_CLI_COMMANDS if not _doc_mentions_command(api_usage_text, cmd)
    )
    if undocumented_commands:
        errors.append(
            f"{api_usage}: missing CLI command docs for: {', '.join(undocumented_commands)}"
        )

    api_usage_vars = _extract_doc_vars(api_usage_text)
    missing_api_usage_cli_vars = sorted(REQUIRED_API_USAGE_CLI_ENV_VARS - api_usage_vars)
    if missing_api_usage_cli_vars:
        errors.append(
            f"{api_usage}: missing CLI env/context docs for: {', '.join(missing_api_usage_cli_vars)}"
        )

    config_source_paths = [
        repo_root / "docker-compose.yml",
        repo_root / "app" / "api" / "settings.py",
        repo_root / "app" / "common" / "api_keys.py",
        repo_root / "app" / "common" / "config.py",
        repo_root / "app" / "common" / "job_index.py",
        repo_root / "app" / "common" / "limits.py",
        repo_root / "app" / "common" / "live_updates.py",
        repo_root / "app" / "common" / "logging_config.py",
        repo_root / "app" / "common" / "telemetry.py",
        repo_root / "app" / "common" / "url_dedupe.py",
        repo_root / "app" / "common" / "web_analysis.py",
        repo_root / "app" / "common" / "webpubsub.py",
        repo_root / "app" / "worker" / "entrypoint.sidecar.sh",
        repo_root / "app" / "worker" / "screenshot_capture.py",
        repo_root / "src" / "aca_cli" / "config.py",
    ]
    source_env_vars = _extract_env_names(config_source_paths)
    undocumented_public_vars = sorted(
        var for var in SUPPORTED_CONFIG_VARS if var not in _extract_doc_vars(_read(config_ref))
    )
    if undocumented_public_vars:
        errors.append(
            f"{config_ref}: missing supported config vars: {', '.join(undocumented_public_vars)}"
        )

    unknown_source_vars = sorted(
        source_env_vars - SUPPORTED_CONFIG_VARS - INTERNAL_CONFIG_VARS
    )
    if unknown_source_vars:
        errors.append(
            "config allowlist missing source vars: "
            + ", ".join(unknown_source_vars)
        )

    stale_supported_vars = sorted(SUPPORTED_CONFIG_VARS - source_env_vars)
    if stale_supported_vars:
        errors.append(
            "supported config allowlist includes vars not found in source: "
            + ", ".join(stale_supported_vars)
        )

    try:
        server_terminal = set(_load_literal_assignment(status_path, "TERMINAL_STATUSES"))
        cli_terminal = set(_load_literal_assignment(cli_core, "TERMINAL_STATUSES"))
        if server_terminal != cli_terminal:
            errors.append(
                f"terminal status mismatch: app/common={sorted(server_terminal)} src/aca_cli={sorted(cli_terminal)}"
            )
    except Exception as exc:
        errors.append(f"status constant load failed: {exc}")

    if errors:
        print("[docs-check] FAIL")
        for item in errors:
            print(f"- {item}")
        return 1

    print("[docs-check] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
