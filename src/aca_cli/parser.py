from __future__ import annotations

import argparse

from .core import RESULT_VIEW_CHOICES, SCAN_STATUS_CHOICES, __version__

def build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    epilog = """\
Examples:
  ./scripts/aca scan-url https://example.com --follow watch
  ./scripts/aca scan-file ./readme.md --follow watch
  ./scripts/aca watch <job_id>
  ./scripts/aca jobs --limit 50
  ./scripts/aca history --limit 10 --format table
  ./scripts/aca --color never jobs --limit 10
  ./scripts/aca --prompt scan-url
  ./scripts/aca doctor
  ./scripts/aca config show
  ./scripts/aca env
  ./scripts/aca az scan-url https://example.com --wait

Compatibility:
  ./scripts/aca_api.py scan-url https://example.com --wait

Configuration precedence (highest first):
  Base URL:   --base-url,  ACA_BASE_URL,  API_URL,  http://localhost:8000
  API key:    --api-key,   ACA_API_KEY,   API_KEY,  --env-file / ACA_ENV_FILE / .env (ACA_API_KEY/API_KEY)
  Key header: --api-key-header, ACA_API_KEY_HEADER, API_KEY_HEADER, X-API-Key
  .env file:  --env-file,  ACA_ENV_FILE,  cwd .env,  repo .env (source checkout only)
  History:    --history,   ACA_API_HISTORY, <repo>/.aca_api_history (source) or ~/.aca_api_history (installed)

Scan status lifecycle:
  pending, queued, fetching, queued_scan, retrying, blocked, completed, error
"""

    parser = argparse.ArgumentParser(
        description="CLI helper for the FastAPI scanner service.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument(
        "--context",
        choices=["local", "az"],
        default="local",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-b",
        "--base-url",
        help="Base API URL (or ACA_BASE_URL / API_URL; default: http://localhost:8000)",
    )
    parser.add_argument(
        "-k",
        "--api-key",
        help="API key (or ACA_API_KEY / API_KEY; also read from resolved .env file)",
    )
    parser.add_argument(
        "--api-key-header",
        help="API key header (or ACA_API_KEY_HEADER / API_KEY_HEADER; default: X-API-Key)",
    )
    parser.add_argument(
        "--env-file",
        help="Path to .env file (or ACA_ENV_FILE; default: cwd .env, then repo .env in source checkout)",
    )
    parser.add_argument(
        "--history",
        help="Local history file (or ACA_API_HISTORY; default: <repo>/.aca_api_history in source checkout, else ~/.aca_api_history)",
    )
    parser.add_argument("--raw", action="store_true", help="Print raw response (no pretty-print)")
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Print JSON output (default is a human-friendly CLI layout)",
    )
    parser.add_argument(
        "--spinner",
        dest="spinner",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show a spinner for long-running wait/watch operations in interactive terminals (default: true)",
    )
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="Color output mode (default: auto; honors NO_COLOR when auto)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Extra progress output")
    parser.add_argument(
        "--prompt",
        action="store_true",
        help="Interactively prompt for missing inputs (TTY only)",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Disable prompting (useful to force non-interactive behavior in a TTY)",
    )

    subparsers = parser.add_subparsers(dest="command", title="Commands", metavar="")
    subparsers.required = True

    cmd_parsers: dict[str, argparse.ArgumentParser] = {}

    def _add_follow_args(p: argparse.ArgumentParser, *, prefix: str = "When following") -> None:
        p.add_argument(
            "--wait",
            action="store_true",
            help="Wait for completion and print final result (compat alias for --follow poll)",
        )
        p.add_argument(
            "--follow",
            choices=["none", "poll", "watch"],
            help="Follow the job after submit (none, poll, or live watch with polling fallback)",
        )
        p.add_argument(
            "--interval",
            type=int,
            default=2,
            help=f"{prefix}, poll interval in seconds (default: 2)",
        )
        p.add_argument(
            "--timeout",
            type=int,
            default=120,
            help=f"{prefix}, timeout in seconds (0 = no timeout; default: 120)",
        )
        p.add_argument(
            "--view",
            default="summary",
            choices=list(RESULT_VIEW_CHOICES),
            help="Result view (summary is smaller; full includes details)",
        )

    cmd_parsers["health"] = subparsers.add_parser("health", help="Check API health (no auth)")

    p_scan = subparsers.add_parser("scan-url", help="Scan a URL")
    cmd_parsers["scan-url"] = p_scan
    p_scan.add_argument("url", nargs="?", help="URL to scan")
    p_scan.add_argument("--source", help="Optional source identifier (free-form)")
    p_scan.add_argument(
        "--meta",
        action="append",
        help="Metadata key=value (repeatable; merged into metadata object)",
        default=[],
    )
    p_scan.add_argument(
        "--meta-json",
        help='Metadata JSON object (merged with --meta), e.g. \'{"env":"dev"}\'',
    )
    p_scan.add_argument("--force", action="store_true", help="Force a new scan")
    _add_follow_args(p_scan, prefix="When following")

    p_status = subparsers.add_parser("status", help="Get job status")
    cmd_parsers["status"] = p_status
    p_status.add_argument("job_id", nargs="?", help="Job ID")
    p_status.add_argument(
        "--view",
        default="summary",
        choices=list(RESULT_VIEW_CHOICES),
        help="Result view (summary is smaller; full includes details)",
    )

    p_wait = subparsers.add_parser("wait", help="Wait for job")
    cmd_parsers["wait"] = p_wait
    p_wait.add_argument("job_id", nargs="?", help="Job ID")
    p_wait.add_argument("--interval", type=int, default=2, help="Poll interval (s)")
    p_wait.add_argument("--timeout", type=int, default=120, help="Timeout (s); 0 = no timeout")
    p_wait.add_argument(
        "--view",
        default="summary",
        choices=list(RESULT_VIEW_CHOICES),
        help="Result view (summary is smaller; full includes details)",
    )

    p_watch = subparsers.add_parser(
        "watch", help="Watch a job via live stream (with optional polling fallback)"
    )
    cmd_parsers["watch"] = p_watch
    p_watch.add_argument("job_id", nargs="?", help="Job ID")
    p_watch.add_argument(
        "--cursor",
        default="$",
        help="Stream cursor ('$' for latest, or '<ms>-<seq>' for resume)",
    )
    p_watch.add_argument(
        "--read-timeout",
        type=int,
        default=30,
        help="Socket read timeout in seconds for the live stream (default: 30)",
    )
    p_watch.add_argument(
        "--fallback-poll",
        dest="fallback_poll",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fallback to polling when live stream is unavailable (default: true)",
    )
    p_watch.add_argument(
        "--interval",
        type=int,
        default=2,
        help="Polling interval in seconds when fallback is used (default: 2)",
    )
    p_watch.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Overall timeout in seconds (0 = no timeout; default: 120)",
    )
    p_watch.add_argument(
        "--view",
        default="summary",
        choices=list(RESULT_VIEW_CHOICES),
        help="Result view (summary is smaller; full includes details)",
    )

    p_jobs = subparsers.add_parser("jobs", help="List jobs")
    cmd_parsers["jobs"] = p_jobs
    p_jobs.add_argument("--limit", type=int, default=20, help="Max jobs to return")
    p_jobs.add_argument(
        "--status",
        help=f"Comma-separated statuses (choices: {', '.join(SCAN_STATUS_CHOICES)})",
    )
    p_jobs.add_argument(
        "--type",
        dest="scan_type",
        choices=["url", "file"],
        help="Filter by scan type (default: show both)",
    )
    p_jobs.add_argument(
        "--format",
        default="table",
        choices=["table", "lines", "json"],
        help="Output format (table is human-readable; json is machine-readable; lines accepted for compatibility)",
    )

    p_hist = subparsers.add_parser("history", help="Show local history (most recent jobs submitted)")
    cmd_parsers["history"] = p_hist
    p_hist.add_argument("--limit", type=int, default=0, help="Max lines (0 = all)")
    p_hist.add_argument(
        "--format",
        default="table",
        choices=["table", "tsv", "json"],
        help="Output format (default: table; tsv preserves raw history lines)",
    )

    p_clear_history = subparsers.add_parser("clear-history", help="Clear local history")
    cmd_parsers["clear-history"] = p_clear_history
    p_clear_history.add_argument("--yes", action="store_true", help="Confirm deletion without prompting")

    p_clear_server = subparsers.add_parser(
        "clear-server-history", help="Clear server history (for API key)"
    )
    cmd_parsers["clear-server-history"] = p_clear_server
    p_clear_server.add_argument(
        "--type",
        dest="scan_type",
        choices=["url", "file"],
        help="Which jobs to clear (default: all)",
    )
    p_clear_server.add_argument("--yes", action="store_true", help="Confirm deletion without prompting")

    p_screen = subparsers.add_parser("screenshot", help="Download screenshot")
    cmd_parsers["screenshot"] = p_screen
    p_screen.add_argument("job_id", nargs="?", help="Job ID")
    out_group = p_screen.add_mutually_exclusive_group()
    out_group.add_argument(
        "-o",
        "--out",
        help="Output file path or directory (default: ./<job_id>.png|.jpg based on Content-Type)",
    )
    out_group.add_argument(
        "--out-dir",
        help="Output directory (filename auto-generated as <job_id>.png|.jpg based on Content-Type)",
    )

    p_file = subparsers.add_parser("scan-file", help="Scan a file (multipart)")
    cmd_parsers["scan-file"] = p_file
    p_file.add_argument("path", nargs="?", help="File path to upload to /file/scan")
    _add_follow_args(p_file, prefix="When following")

    p_payload = subparsers.add_parser("scan-payload", help="Scan text payload")
    cmd_parsers["scan-payload"] = p_payload
    p_payload.add_argument("text", nargs="?", help="Text payload to send as multipart form field")
    p_payload.add_argument(
        "--base64",
        action="store_true",
        help="Indicate payload is base64 encoded (sets payload_base64=true)",
    )
    _add_follow_args(p_payload, prefix="When following")

    p_admin_list = subparsers.add_parser("admin-list-keys", help="Admin: list stored API keys")
    cmd_parsers["admin-list-keys"] = p_admin_list
    p_admin_list.add_argument("--limit", type=int, default=100, help="Max keys to return (default: 100)")
    p_admin_list.add_argument(
        "--include-inactive",
        action="store_true",
        help="Include revoked or expired keys",
    )

    p_admin_mint = subparsers.add_parser("admin-mint-key", help="Admin: mint a new API key")
    cmd_parsers["admin-mint-key"] = p_admin_mint
    p_admin_mint.add_argument("--label", help="Optional label for the key")
    p_admin_mint.add_argument("--read-rpm", type=int, help="Optional per-key read RPM limit")
    p_admin_mint.add_argument("--write-rpm", type=int, help="Optional per-key write RPM limit")
    p_admin_mint.add_argument("--ttl-days", type=int, help="Optional expiration (days)")
    p_admin_mint.add_argument(
        "--is-admin",
        action="store_true",
        help="Mint an admin key (can call /admin/api-keys*)",
    )

    p_admin_revoke = subparsers.add_parser("admin-revoke-key", help="Admin: revoke an API key")
    cmd_parsers["admin-revoke-key"] = p_admin_revoke
    p_admin_revoke.add_argument("key_hash", help="SHA256 hash of the key to revoke")

    p_env = subparsers.add_parser("env", help="Print shell exports for the resolved context")
    cmd_parsers["env"] = p_env
    p_env.add_argument("--unset", action="store_true", help="Print shell unsets instead of exports")

    p_doctor = subparsers.add_parser("doctor", help="Show local CLI diagnostics")
    cmd_parsers["doctor"] = p_doctor

    p_config = subparsers.add_parser("config", help="Show CLI configuration details")
    cmd_parsers["config"] = p_config
    config_subparsers = p_config.add_subparsers(dest="config_command", metavar="")
    config_subparsers.required = True
    p_config_show = config_subparsers.add_parser("show", help="Show resolved CLI configuration")
    cmd_parsers["config show"] = p_config_show
    p_config_show.add_argument(
        "--show-secrets",
        action="store_true",
        help="Include API key value in output (default: masked)",
    )

    p_help = subparsers.add_parser("help", help="Show detailed help for all commands or one command")
    cmd_parsers["help"] = p_help
    p_help.add_argument(
        "topic",
        nargs="*",
        help="Optional command to show help for (e.g. scan-url, screenshot, config show)",
    )

    return parser, cmd_parsers
