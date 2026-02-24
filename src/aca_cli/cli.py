#!/usr/bin/env python3
"""
aca_api.py

Interact with the FastAPI scanner service.

Dependencies:
    Python 3.11+ (standard library; optionally uses `rich` for enhanced terminal UX)

Configuration precedence (highest first):
  - API key:
      1) --api-key
      2) environment: ACA_API_KEY, else API_KEY
      3) .env file (--env-file / ACA_ENV_FILE / cwd .env / repo .env): ACA_API_KEY, else API_KEY
  - Base URL:
      1) --base-url
      2) environment: ACA_BASE_URL, else API_URL
      3) default: http://localhost:8000
"""

import argparse
import dataclasses
import itertools
import json
import mimetypes
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, NoReturn, Tuple, Union

from . import ui_console, ui_live, ui_render

__version__ = "1.0.0"

# --- Configuration & Helpers ---

SCAN_STATUS_CHOICES = (
    "pending",
    "queued",
    "fetching",
    "queued_scan",
    "retrying",
    "blocked",
    "completed",
    "error",
)
RESULT_VIEW_CHOICES = ("summary", "full")


def load_dotenv(path: Path) -> dict:
    """Simple .env parser to match bash script behavior."""
    env_vars = {}
    if not path.exists():
        return env_vars

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Remove 'export ' prefix
            if line.startswith("export "):
                line = line[7:].strip()

            if "=" not in line:
                continue

            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()

            # Remove quotes if present around the whole value
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]

            env_vars[key] = val
    return env_vars


def find_repo_root(start: Path | None = None) -> Path | None:
    """Best-effort repo root discovery when running from a source checkout."""
    current = (start or Path(__file__)).resolve()
    if current.is_file():
        current = current.parent
    for candidate in [current, *current.parents]:
        if (
            (candidate / "scripts" / "aca").exists()
            and (candidate / "app").is_dir()
            and (candidate / "tests").is_dir()
        ):
            return candidate
    return None


def get_repo_root() -> Path:
    """Return repo root when available; otherwise use current working directory."""
    return find_repo_root() or Path.cwd()


def resolve_dotenv_path(
    args: argparse.Namespace | None, env: Mapping[str, str] | None, repo_root: Path | None
) -> Path | None:
    env_map = dict(env or os.environ)
    cli_path = str(getattr(args, "env_file", "") or "").strip() if args else ""
    env_file_path = cli_path or str(env_map.get("ACA_ENV_FILE") or "").strip()
    if env_file_path:
        return Path(env_file_path).expanduser()

    cwd_dotenv = Path.cwd() / ".env"
    if cwd_dotenv.exists():
        return cwd_dotenv

    if repo_root is not None:
        repo_dotenv = repo_root / ".env"
        if repo_dotenv.exists():
            return repo_dotenv
    return None


def default_history_path(repo_root: Path | None) -> Path:
    if repo_root is not None:
        return repo_root / ".aca_api_history"
    try:
        return Path.home() / ".aca_api_history"
    except Exception:
        return Path.cwd() / ".aca_api_history"


class Config:
    """
    Configuration handling class.

    Loads configuration from CLI arguments, environment variables, and .env files
    with specific precedence rules.
    """

    def __init__(self, args):
        self.repo_root = find_repo_root()
        self.dotenv_path = resolve_dotenv_path(args, os.environ, self.repo_root)
        self.dotenv = load_dotenv(self.dotenv_path) if self.dotenv_path else {}
        self.context = str(getattr(args, "context", "local") or "local").strip().lower()
        if (
            self.context == "az"
            and str(getattr(args, "command", "") or "") == "env"
            and bool(getattr(args, "unset", False))
        ):
            resolved_context = ResolvedContext(context="az")
        else:
            resolved_context = resolve_context(self.context, os.environ, args)
        self.resolved_context = resolved_context

        # Base URL
        self.base_url = (
            args.base_url
            or resolved_context.base_url
            or "http://localhost:8000"
        ).rstrip("/")

        # API Key
        self.api_key = (
            args.api_key
            or resolved_context.api_key
            or self.dotenv.get("ACA_API_KEY")
            or self.dotenv.get("API_KEY")
            or ""
        )

        # API Key Header
        self.api_key_header = (
            args.api_key_header
            or os.environ.get("ACA_API_KEY_HEADER")
            or os.environ.get("API_KEY_HEADER")
            or "X-API-Key"
        )

        # History Path
        history_path_str = args.history or os.environ.get("ACA_API_HISTORY")
        if history_path_str:
            self.history_path = Path(history_path_str).expanduser()
        else:
            self.history_path = default_history_path(self.repo_root)

        self.raw = args.raw
        self.json_output = bool(getattr(args, "json_output", False))
        self.verbose = args.verbose
        self.prompt = bool(getattr(args, "prompt", False))
        self.no_prompt = bool(getattr(args, "no_prompt", False))
        self.color = ui_console.resolve_color_mode(getattr(args, "color", "auto"), os.environ)
        self.stdin_tty = bool(sys.stdin.isatty())
        self.stdout_tty = bool(sys.stdout.isatty())
        self.stderr_tty = bool(sys.stderr.isatty())
        self.is_tty = self.stdin_tty and self.stdout_tty
        self.spinner = bool(getattr(args, "spinner", True)) and self.stderr_tty

        bundle = ui_console.build_console_bundle(
            color_mode=self.color,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
        self.stdout_console = bundle.stdout
        self.stderr_console = bundle.stderr
        self.rich_stdout = bundle.rich_stdout
        self.rich_stderr = bundle.rich_stderr
        self.unicode_symbols = bundle.unicode_symbols

    def require_api_key(self):
        """
        Ensure an API key is present. Exits if missing.
        """
        if not self.api_key:
            die(
                "Missing API key. Set --api-key, ACA_API_KEY, API_KEY, or add API_KEY to .env."
            )


@dataclasses.dataclass(slots=True)
class ResolvedContext:
    context: str
    base_url: str = ""
    api_key: str = ""
    api_key_header: str = "X-API-Key"
    api_fqdn: str = ""
    source_details: dict[str, str] = dataclasses.field(default_factory=dict)


def die(msg: str) -> NoReturn:
    """Print error message to stderr and exit with status 1."""
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg):
    """Print message to stderr."""
    print(msg, file=sys.stderr)


def shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _run_az_tsv(args: list[str]) -> str:
    try:
        proc = subprocess.run(
            ["az", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        die("'az' (Azure CLI) not found in PATH")
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        if stderr:
            log(stderr)
        die(f"az {' '.join(args[:2])} failed")
    return str(proc.stdout or "").replace("\r", "").strip()


def resolve_azure_env(
    env: Mapping[str, str] | None = None,
    *,
    api_key_header: str = "X-API-Key",
) -> ResolvedContext:
    env_map = dict(env or os.environ)
    aca_rg = str(env_map.get("ACA_RG") or "rg-devsecops-aca").strip()
    aca_api_app = str(env_map.get("ACA_API_APP") or "devsecopsaca-api").strip()
    aca_kv = str(env_map.get("ACA_KV") or "devsecopsaca-kv").strip()
    aca_api_key_secret_name = str(env_map.get("ACA_API_KEY_SECRET_NAME") or "ApiKey").strip()

    api_fqdn = _run_az_tsv(
        [
            "containerapp",
            "show",
            "-g",
            aca_rg,
            "-n",
            aca_api_app,
            "--query",
            "properties.configuration.ingress.fqdn",
            "-o",
            "tsv",
        ]
    )
    api_fqdn = " ".join(api_fqdn.split())
    if not api_fqdn:
        die("API_FQDN is empty (check ACA_RG/ACA_API_APP and 'az login' / subscription)")

    api_key = _run_az_tsv(
        [
            "keyvault",
            "secret",
            "show",
            "--vault-name",
            aca_kv,
            "--name",
            aca_api_key_secret_name,
            "--query",
            "value",
            "-o",
            "tsv",
        ]
    )
    if not api_key:
        die(
            "API_KEY is empty (check ACA_KV/ACA_API_KEY_SECRET_NAME and Key Vault permissions)"
        )

    return ResolvedContext(
        context="az",
        base_url=f"https://{api_fqdn}",
        api_key=api_key,
        api_key_header=api_key_header,
        api_fqdn=api_fqdn,
        source_details={
            "ACA_RG": aca_rg,
            "ACA_API_APP": aca_api_app,
            "ACA_KV": aca_kv,
            "ACA_API_KEY_SECRET_NAME": aca_api_key_secret_name,
        },
    )


def resolve_context(
    context: str,
    env: Mapping[str, str] | None = None,
    args: argparse.Namespace | None = None,
) -> ResolvedContext:
    env_map = dict(env or os.environ)
    api_key_header = (
        getattr(args, "api_key_header", None)
        or env_map.get("ACA_API_KEY_HEADER")
        or env_map.get("API_KEY_HEADER")
        or "X-API-Key"
    )
    ctx = str(context or "local").strip().lower()
    if ctx == "az":
        return resolve_azure_env(env_map, api_key_header=api_key_header)

    return ResolvedContext(
        context="local",
        base_url=(
            env_map.get("ACA_BASE_URL")
            or env_map.get("API_URL")
            or "http://localhost:8000"
        ).rstrip("/"),
        api_key=(env_map.get("ACA_API_KEY") or env_map.get("API_KEY") or ""),
        api_key_header=api_key_header,
        api_fqdn=env_map.get("API_FQDN", ""),
        source_details={
            "ACA_BASE_URL": str(env_map.get("ACA_BASE_URL") or ""),
            "API_URL": str(env_map.get("API_URL") or ""),
            "ACA_API_KEY": "<set>" if env_map.get("ACA_API_KEY") else "",
            "API_KEY": "<set>" if env_map.get("API_KEY") else "",
        },
    )


def emit_shell_exports(resolved: ResolvedContext, *, unset: bool = False) -> str:
    if unset:
        return "unset API_FQDN API_URL API_KEY ACA_BASE_URL ACA_API_KEY"
    lines = []
    if resolved.api_fqdn:
        lines.append(f"export API_FQDN={shell_quote(resolved.api_fqdn)}")
    lines.append(f"export API_URL={shell_quote(resolved.base_url)}")
    lines.append(f"export API_KEY={shell_quote(resolved.api_key)}")
    lines.append(f"export ACA_BASE_URL={shell_quote(resolved.base_url)}")
    lines.append(f"export ACA_API_KEY={shell_quote(resolved.api_key)}")
    return "\n".join(lines)


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]}"


# --- HTTP Client ---


def make_request(
    config: Config, method: str, path: str, data=None, headers=None, stream=False
) -> Tuple[int, Any, Union[str, bytes]]:
    """
    Execute an HTTP request using the standard library.

    Args:
        config: Configuration object containing base_url and api_key.
        method: HTTP method (GET, POST, DELETE, etc.).
        path: API endpoint path.
        data: Request body (dict, str, or bytes).
        headers: Optional dictionary of headers.
        stream: If True, returns raw bytes for body; otherwise decodes UTF-8.

    Returns:
        Tuple containing (status_code, headers, body).
    """
    if headers is None:
        headers = {}

    url = f"{config.base_url}{path}"

    # Default headers
    if "accept" not in headers:
        headers["accept"] = "application/json"

    # Auth header (if key/header is set, though some endpoints usually don't need it, we can just send it)
    if config.api_key:
        headers[config.api_key_header] = config.api_key

    # Body handling
    encoded_data = None
    if data is not None:
        if isinstance(data, dict):
            encoded_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(data, str):
            encoded_data = data.encode("utf-8")
        elif isinstance(data, bytes):
            encoded_data = data
        else:
            raise ValueError(f"Unknown data type: {type(data)}")

    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
            if stream:
                # Return headers and content separately for binary downloads
                return status, response.headers, response.read()

            body = response.read().decode("utf-8")
            return status, response.headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        if config.verbose:
            log(f"HTTP {e.code}: {body}")

        # Return the error body as result, but we might want to fail?
        # The bash script printed invalid statuses and exited 1 usually,
        # but sometimes printed the error body.
        # We'll mimic: Print body to stderr if present, then die/raise.
        if body:
            print(body, file=sys.stderr)
        die(f"HTTP {e.code}")
    except urllib.error.URLError as e:
        die(f"Connection failed to {url}: {e.reason}")


def open_ndjson_stream(
    config: Config, path: str, *, headers=None, timeout_seconds: int = 30
):
    if headers is None:
        headers = {}

    url = f"{config.base_url}{path}"
    if "accept" not in headers:
        headers["accept"] = "application/x-ndjson, application/json"
    if config.api_key:
        headers[config.api_key_header] = config.api_key

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        return urllib.request.urlopen(req, timeout=max(1, int(timeout_seconds or 1)))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        if body:
            print(body, file=sys.stderr)
        raise


def emit_json(output, config: Config, *, kind: str | None = None):
    """
    Print CLI output.
    Default is a human-friendly layout for JSON responses.
    Use --json for JSON output or --raw for passthrough.
    """
    if config.raw:
        if isinstance(output, str):
            print(output)
        else:
            print(json.dumps(output))
        return

    if isinstance(output, str):
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            print(output)
            return
    else:
        parsed = output

    if config.json_output:
        print(json.dumps(parsed, indent=2))
        return

    if ui_render.render_output(parsed, config, kind=kind):
        return

    _emit_human(parsed)


class Spinner:
    def __init__(self, enabled: bool):
        self.enabled = bool(enabled)
        self._frames = itertools.cycle(["|", "/", "-", "\\"])
        self._last_len = 0
        self._active = False

    def tick(self, message: str) -> None:
        if not self.enabled:
            return
        frame = next(self._frames)
        text = f"\r{frame} {message}"
        pad = ""
        if self._last_len > len(text):
            pad = " " * (self._last_len - len(text))
        sys.stderr.write(text + pad)
        sys.stderr.flush()
        self._last_len = len(text)
        self._active = True

    def clear(self) -> None:
        if not self.enabled or not self._active:
            return
        sys.stderr.write("\r" + (" " * self._last_len) + "\r")
        sys.stderr.flush()
        self._active = False
        self._last_len = 0

    def done(self, message: str | None = None) -> None:
        if not self.enabled:
            return
        if message:
            self.clear()
            sys.stderr.write(f"{message}\n")
            sys.stderr.flush()
        else:
            self.clear()


def _format_scalar(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _print_kv(title: str | None, items: list[tuple[str, Any]]) -> None:
    if title:
        print(title)
    if not items:
        if title:
            print("  (none)")
        return
    width = max(len(k) for k, _ in items)
    for key, value in items:
        print(f"{key:<{width}} : {_format_scalar(value)}")


def _emit_human(data: Any, *, indent: int = 0) -> None:
    prefix = " " * indent

    if isinstance(data, dict):
        if indent == 0 and ("job_id" in data or "status" in data):
            _emit_human_scan_result(data)
            return

        scalar_items: list[tuple[str, Any]] = []
        nested_items: list[tuple[str, Any]] = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                nested_items.append((str(key), value))
            else:
                scalar_items.append((str(key), value))

        if scalar_items:
            if indent == 0:
                _print_kv(None, scalar_items)
            else:
                width = max(len(k) for k, _ in scalar_items)
                for key, value in scalar_items:
                    print(f"{prefix}{key:<{width}} : {_format_scalar(value)}")

        for key, value in nested_items:
            if scalar_items or indent == 0:
                print("")
            print(f"{prefix}{key}:")
            _emit_human(value, indent=indent + 2)
        if not scalar_items and not nested_items:
            print(f"{prefix}(empty)")
        return

    if isinstance(data, list):
        if not data:
            print(f"{prefix}(empty)")
            return
        for idx, item in enumerate(data, start=1):
            if isinstance(item, (dict, list)):
                print(f"{prefix}- [{idx}]")
                _emit_human(item, indent=indent + 2)
            else:
                print(f"{prefix}- {_format_scalar(item)}")
        return

    print(f"{prefix}{_format_scalar(data)}")


def _emit_human_scan_result(data: dict[str, Any]) -> None:
    ordered_keys = [
        "status",
        "job_id",
        "run_id",
        "type",
        "url",
        "filename",
        "verdict",
        "deduped",
        "submitted_at",
        "scanned_at",
        "error",
    ]
    scalar_items: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for key in ordered_keys:
        if key in data and not isinstance(data[key], (dict, list)):
            scalar_items.append((key, data[key]))
            seen.add(key)
    for key, value in data.items():
        if key in seen or isinstance(value, (dict, list)):
            continue
        scalar_items.append((str(key), value))

    _print_kv("Result", scalar_items)

    for key in ("summary", "metadata", "details"):
        if key in data and data[key] not in (None, {}, []):
            print("")
            print(f"{key}:")
            _emit_human(data[key], indent=2)

    for key, value in data.items():
        if key in seen or key in {"summary", "metadata", "details"}:
            continue
        if isinstance(value, (dict, list)):
            print("")
            print(f"{key}:")
            _emit_human(value, indent=2)


# --- History ---


def append_history(config: Config, job_id, url):
    """
    Append a job to the local history file.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{ts}\t{job_id}\t{url}\t{config.base_url}\n"
    try:
        config.history_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config.history_path, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception as e:
        if config.verbose:
            log(f"Failed to write history: {e}")


def read_history(config: Config, limit=0):
    """
    Read and print lines from the local history file.
    """
    if not config.history_path.exists():
        return

    with open(config.history_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    if limit > 0:
        lines = lines[-limit:]

    for line in lines:
        sys.stdout.write(line)


def parse_history_entries(config: Config, limit: int = 20) -> list[dict[str, str]]:
    if not config.history_path.exists():
        return []
    entries: list[dict[str, str]] = []
    try:
        with open(config.history_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return []
    if limit > 0:
        lines = lines[-limit:]
    for raw in reversed(lines):
        raw = raw.rstrip("\n")
        parts = raw.split("\t")
        if len(parts) < 4:
            continue
        ts, job_id, url, base_url = parts[0], parts[1], parts[2], parts[3]
        entries.append(
            {
                "timestamp": ts,
                "job_id": job_id,
                "url": url,
                "base_url": base_url,
            }
        )
    return entries


def _prompt_input(prompt: str, *, default: str | None = None) -> str:
    suffix = ""
    if default not in (None, ""):
        suffix = f" [{default}]"
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default or ""
    if not value and default is not None:
        return str(default)
    return value


def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    default_hint = "Y/n" if default else "y/N"
    while True:
        answer = _prompt_input(f"{prompt} ({default_hint})")
        if not answer:
            return default
        lowered = answer.strip().lower()
        if lowered in ("y", "yes"):
            return True
        if lowered in ("n", "no"):
            return False
        print("Please answer yes or no.", file=sys.stderr)


def _prompt_choice(prompt: str, options: list[str], *, default: str | None = None) -> str:
    if not options:
        return ""
    normalized = {str(i + 1): opt for i, opt in enumerate(options)}
    while True:
        print(prompt, file=sys.stderr)
        for i, opt in enumerate(options, start=1):
            marker = " (default)" if default and opt == default else ""
            print(f"  {i}) {opt}{marker}", file=sys.stderr)
        raw = _prompt_input("Choose", default=str(options.index(default) + 1) if default in options else None)
        if raw in normalized:
            return normalized[raw]
        if raw in options:
            return raw
        print("Invalid choice.", file=sys.stderr)


def _is_prompt_enabled(config: Config, args) -> bool:
    prompt = bool(getattr(args, "prompt", False))
    no_prompt = bool(getattr(args, "no_prompt", False))
    if prompt and no_prompt:
        die("Use only one of --prompt or --no-prompt")
    if not prompt:
        return False
    if not config.is_tty:
        die("--prompt requires an interactive TTY")
    return True


def _prompt_job_id(config: Config) -> str:
    entries = parse_history_entries(config, limit=10)
    if entries:
        print("Recent jobs:", file=sys.stderr)
        for idx, item in enumerate(entries, start=1):
            url = item["url"]
            if len(url) > 60:
                url = url[:57] + "..."
            print(
                f"  {idx}) {item['job_id']}  {item['timestamp']}  {url}",
                file=sys.stderr,
            )
        raw = _prompt_input("Select job number or paste job_id")
        if raw.isdigit():
            pos = int(raw)
            if 1 <= pos <= len(entries):
                return entries[pos - 1]["job_id"]
        if raw:
            return raw
    return _prompt_input("Job ID")


def maybe_prompt_for_missing_args(command: str, args, config: Config):
    if not _is_prompt_enabled(config, args):
        return args

    if command == "scan-url":
        if not getattr(args, "url", None):
            args.url = _prompt_input("URL to scan")
        if getattr(args, "source", None) is None:
            source = _prompt_input("Source label (optional)")
            if source:
                args.source = source
        if not getattr(args, "meta", None) and not getattr(args, "meta_json", None):
            meta_raw = _prompt_input("Metadata key=value (optional, comma-separated)")
            if meta_raw:
                args.meta = [part.strip() for part in meta_raw.split(",") if part.strip()]

        if getattr(args, "follow", None) is None and not getattr(args, "wait", False):
            follow = _prompt_choice(
                "Follow scan after submit?",
                ["none", "poll", "watch"],
                default="poll",
            )
            args.follow = follow

    elif command in {"status", "wait", "watch", "screenshot"}:
        if not getattr(args, "job_id", None):
            args.job_id = _prompt_job_id(config)
        if command == "screenshot" and not getattr(args, "out", None) and not getattr(
            args, "out_dir", None
        ):
            out = _prompt_input("Output path or directory (optional)")
            if out:
                args.out = out

    elif command == "scan-file":
        if not getattr(args, "path", None):
            args.path = _prompt_input("File path")
    elif command == "scan-payload":
        if not getattr(args, "text", None):
            args.text = _prompt_input("Text payload")

    return args


def ensure_required_command_args(command: str, args):
    required = {
        "scan-url": [("url", "URL")],
        "status": [("job_id", "job ID")],
        "wait": [("job_id", "job ID")],
        "watch": [("job_id", "job ID")],
        "screenshot": [("job_id", "job ID")],
        "scan-file": [("path", "file path")],
        "scan-payload": [("text", "text payload")],
    }
    for attr, label in required.get(command, []):
        value = getattr(args, attr, None)
        if value is None or str(value).strip() == "":
            die(f"Missing required {label}. Provide it as an argument or use --prompt.")


def confirm_or_die(config: Config, args, prompt: str):
    if bool(getattr(args, "yes", False)):
        return
    if not _is_prompt_enabled(config, args):
        die(f"{prompt} Pass --yes to confirm, or use --prompt for an interactive confirmation.")
    if not _prompt_yes_no(prompt, default=False):
        die("Cancelled")


def _follow_mode_from_submit_args(args) -> str:
    follow_mode = getattr(args, "follow", None)
    wait_flag = bool(getattr(args, "wait", False))
    if wait_flag and follow_mode not in (None, "", "poll"):
        die("--wait is only compatible with --follow poll (or omit --follow)")
    if follow_mode is None:
        return "poll" if wait_flag else "none"
    return str(follow_mode or "none").strip().lower() or "none"


def _follow_submitted_job(config: Config, args, job_id: str) -> None:
    follow_mode = _follow_mode_from_submit_args(args)
    if follow_mode == "none":
        return

    if config.verbose:
        log(f"JOB_ID={job_id}")

    if follow_mode == "watch":
        watch_args = argparse.Namespace(
            job_id=job_id,
            cursor="$",
            read_timeout=30,
            fallback_poll=True,
            interval=int(getattr(args, "interval", 2)),
            timeout=int(getattr(args, "timeout", 120)),
            view=str(getattr(args, "view", "summary") or "summary"),
        )
        cmd_watch(config, watch_args)
        return

    wait_args = argparse.Namespace(
        job_id=job_id,
        interval=int(getattr(args, "interval", 2)),
        timeout=int(getattr(args, "timeout", 120)),
        view=str(getattr(args, "view", "summary") or "summary"),
    )
    cmd_wait(config, wait_args)


def _default_history_target_for_submit(kind: str, args) -> str:
    kind_norm = str(kind or "url").strip().lower()
    if kind_norm == "file":
        path = Path(str(getattr(args, "path", "") or ""))
        name = path.name or str(path or "file")
        return f"file://{name}"
    if kind_norm == "payload":
        text = str(getattr(args, "text", "") or "")
        base64_flag = bool(getattr(args, "base64", False))
        prefix = "payload+b64" if base64_flag else "payload"
        return f"{prefix}://{len(text)}-chars"
    return str(getattr(args, "url", "") or "")


def _handle_submit_response(
    config: Config,
    args,
    body: str,
    *,
    history_target: str | None = None,
) -> None:
    try:
        resp_json = json.loads(body)
    except json.JSONDecodeError:
        log("Submit response (no job_id found):")
        log(body)
        die("Submit succeeded but response did not include job_id")

    if not isinstance(resp_json, dict):
        emit_json(resp_json, config)
        return

    job_id = str(resp_json.get("job_id") or "").strip()
    if not job_id:
        log("Submit response (no job_id found):")
        emit_json(resp_json, config)
        die("Submit succeeded but response did not include job_id")

    target = history_target
    if target is None:
        target = _default_history_target_for_submit(str(getattr(args, "command", "url")), args)
    if target:
        append_history(config, job_id, target)

    follow_mode = _follow_mode_from_submit_args(args)
    if follow_mode == "none":
        emit_json(resp_json, config, kind="scan_result")
        return
    _follow_submitted_job(config, args, job_id)


# --- Commands ---


def cmd_health(config: Config, args):
    """Handler for 'health' command."""
    status, _, body = make_request(config, "GET", "/healthz")
    emit_json(body, config)


def cmd_scan_url(config: Config, args):
    """Handler for 'scan-url' command."""
    config.require_api_key()
    if not args.url:
        die("Missing URL. Provide a URL argument or use --prompt.")

    payload = {"url": args.url, "type": "url"}
    if args.source:
        payload["source"] = args.source
    if args.force:
        payload["force"] = True

    meta = {}
    if args.meta_json:
        try:
            meta.update(json.loads(args.meta_json))
        except json.JSONDecodeError as e:
            die(f"invalid --meta-json: {e}")

    if args.meta:
        for item in args.meta:
            if "=" not in item:
                die("--meta must be key=value")
            k, v = item.split("=", 1)
            if not k.strip():
                die("--meta key cannot be empty")
            meta[k.strip()] = v.strip()

    if meta:
        payload["metadata"] = meta

    _, _, body = make_request(config, "POST", "/scan", data=payload)
    _handle_submit_response(config, args, body, history_target=str(args.url))


def cmd_status(config: Config, args):
    """Handler for 'status' command."""
    config.require_api_key()
    path = f"/scan/{args.job_id}?view={args.view}"
    status, _, body = make_request(config, "GET", path)
    emit_json(body, config, kind="scan_result")


def cmd_wait(config: Config, args):
    """Handler for 'wait' command."""
    config.require_api_key()
    start_time = time.time()
    last_status = None
    live = ui_live.RichLiveReporter.from_config(config)
    live.start(f"Waiting for {args.job_id}")
    spinner = Spinner(config.spinner and not live.active)

    while True:
        path = f"/scan/{args.job_id}?view={args.view}"
        _, _, body = make_request(config, "GET", path)

        try:
            data = json.loads(body)
            status = data.get("status")
        except json.JSONDecodeError:
            status = None
            data = {}

        status_changed = bool(status and status != last_status)

        if config.verbose and status_changed:
            spinner.clear()
            log(f"status={status}")

        if status_changed:
            live.transition(
                str(status),
                error=str(data.get("error") or "") or None,
                duration_ms=data.get("duration_ms"),
                size_bytes=data.get("size_bytes"),
            )
            last_status = status
        msg = f"Waiting for {args.job_id} ({status or 'unknown'})"
        spinner.tick(msg)
        live.update(msg)

        if status == "completed":
            spinner.done()
            live.done()
            emit_json(data, config, kind="scan_result")
            return
        if status == "error" or status == "blocked":
            spinner.done()
            live.done()
            emit_json(data, config, kind="scan_result")
            sys.exit(1)

        if args.timeout > 0:
            if time.time() - start_time >= args.timeout:
                spinner.done()
                live.done()
                die(
                    f"Timed out after {args.timeout}s waiting for job {args.job_id} (last status: {status or 'unknown'})"
                )

        time.sleep(args.interval)


def cmd_watch(config: Config, args):
    """Handler for 'watch' command (NDJSON live stream with polling fallback)."""
    config.require_api_key()
    start_time = time.time()
    live = ui_live.RichLiveReporter.from_config(config)
    live.start(f"Connecting live stream for {args.job_id}")
    spinner = Spinner(config.spinner and not live.active)

    # Resolve run_id from the request-scoped job record.
    status_path = f"/scan/{args.job_id}?view=summary"
    _, _, body = make_request(config, "GET", status_path)
    try:
        status_doc = json.loads(body)
    except json.JSONDecodeError:
        die("status response is not JSON")

    status_value = str(status_doc.get("status") or "").strip().lower()
    run_id = str(status_doc.get("run_id") or "").strip() or str(args.job_id)
    if status_value:
        live.transition(
            status_value,
            error=str(status_doc.get("error") or "") or None,
            duration_ms=status_doc.get("duration_ms"),
            size_bytes=status_doc.get("size_bytes"),
        )

    # If already terminal, return immediately with requested view.
    if status_value in ("completed", "error", "blocked"):
        _, _, final_body = make_request(
            config, "GET", f"/scan/{args.job_id}?view={args.view}"
        )
        spinner.done()
        live.done()
        emit_json(final_body, config, kind="scan_result")
        if status_value != "completed":
            sys.exit(1)
        return

    cursor = str(args.cursor or "$").strip() or "$"
    params = [("cursor", cursor), ("run_id", run_id)]
    stream_path = "/events/stream?" + urllib.parse.urlencode(params)

    if config.verbose:
        log(f"watching run_id={run_id} via {stream_path}")

    try:
        spinner.tick(f"Connecting live stream for {args.job_id}")
        live.update(f"Connecting live stream for {args.job_id}")
        with open_ndjson_stream(
            config,
            stream_path,
            timeout_seconds=max(1, int(args.read_timeout or 30)),
        ) as stream:
            while True:
                if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                    spinner.done()
                    raise TimeoutError(
                        f"Timed out after {args.timeout}s waiting for job {args.job_id}"
                    )
                try:
                    raw = stream.readline()
                except socket.timeout:
                    msg = f"Watching {args.job_id} ({status_value or 'waiting'})"
                    spinner.tick(msg)
                    live.update(msg)
                    continue

                if not raw:
                    spinner.done()
                    live.done()
                    raise ConnectionError("live stream closed")

                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue

                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(packet, dict):
                    continue

                packet_id = str(packet.get("id") or "").strip()
                if packet_id:
                    cursor = packet_id
                event = packet.get("event")
                if not isinstance(event, dict):
                    continue

                event_status = str(event.get("status") or "").strip().lower()
                event_stage = str(event.get("stage") or "").strip().lower() or None
                event_error = str(event.get("error") or "").strip() or None
                if config.verbose and event_status:
                    spinner.clear()
                    log(f"status={event_status}")
                if event_status:
                    status_value = event_status
                    live.transition(
                        event_status,
                        stage=event_stage,
                        error=event_error,
                        duration_ms=event.get("duration_ms"),
                        size_bytes=event.get("size_bytes"),
                    )
                    msg = f"Watching {args.job_id} ({event_status})"
                    spinner.tick(msg)
                    live.update(msg)

                if event_status in ("completed", "error", "blocked"):
                    _, _, final_body = make_request(
                        config, "GET", f"/scan/{args.job_id}?view={args.view}"
                    )
                    spinner.done()
                    live.done()
                    emit_json(final_body, config, kind="scan_result")
                    if event_status != "completed":
                        sys.exit(1)
                    return
    except urllib.error.HTTPError as e:
        spinner.done()
        live.done()
        if not args.fallback_poll:
            die(f"Live stream failed with HTTP {e.code}")
    except Exception as e:
        spinner.done()
        live.done()
        if not args.fallback_poll:
            die(str(e))

    if not args.fallback_poll:
        return

    if config.verbose:
        log("falling back to polling")
    live.fallback_notice()
    remaining_timeout = int(args.timeout)
    if remaining_timeout > 0:
        elapsed = int(time.time() - start_time)
        remaining_timeout = max(1, remaining_timeout - elapsed)
    wait_args = argparse.Namespace(
        job_id=args.job_id,
        interval=args.interval,
        timeout=remaining_timeout,
        view=args.view,
    )
    cmd_wait(config, wait_args)


def cmd_jobs(config: Config, args):
    """Handler for 'jobs' command."""
    config.require_api_key()
    if config.json_output and getattr(args, "format", "table") in ("table", "lines"):
        args.format = "json"

    if args.status:
        statuses = [s.strip() for s in str(args.status).split(",") if s.strip()]
        invalid = sorted(set(statuses) - set(SCAN_STATUS_CHOICES))
        if invalid:
            die(
                f"--status contains invalid value(s): {', '.join(invalid)}; choices: {', '.join(SCAN_STATUS_CHOICES)}"
            )
        args.status = ",".join(statuses)

    def _fetch_jobs(scan_type: str) -> list[dict]:
        params = [f"limit={args.limit}"]
        if args.status:
            params.append(f"status={args.status}")
        if scan_type and scan_type != "all":
            params.append(f"type={scan_type}")
        path = f"/jobs?{'&'.join(params)}"
        _, _, body = make_request(config, "GET", path)

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            die("/jobs did not return JSON.")

        jobs = data.get("jobs")
        if not isinstance(jobs, list):
            die("unexpected /jobs response shape (missing 'jobs' list)")
        return [j for j in jobs if isinstance(j, dict)]

    def _print_url_jobs(jobs: list[dict]) -> None:
        print(
            f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  url"
        )
        for j in jobs:
            jid = str(j.get("job_id") or "")
            jst = str(j.get("status") or "")
            sub = str(j.get("submitted_at") or "")
            scan = str(j.get("scanned_at") or "")
            url = str(j.get("url") or "")
            if len(url) > 80:
                url = url[:77] + "..."
            print(f"{jid:36}  {jst:12}  {sub[:20]:20}  {scan[:20]:20}  {url}")

    def _print_file_jobs(jobs: list[dict]) -> None:
        print(
            f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  {'verdict':10}  {'sha256':12}  filename"
        )
        for j in jobs:
            jid = str(j.get("job_id") or "")
            jst = str(j.get("status") or "")
            sub = str(j.get("submitted_at") or "")
            scan = str(j.get("scanned_at") or "")
            verdict = str(j.get("verdict") or "")
            sha = str(j.get("sha256") or "")
            sha_short = sha[:12] if sha else ""
            filename = str(j.get("filename") or "")
            if len(filename) > 60:
                filename = filename[:57] + "..."
            print(
                f"{jid:36}  {jst:12}  {sub[:20]:20}  {scan[:20]:20}  {verdict[:10]:10}  {sha_short:12}  {filename}"
            )

    scan_type = getattr(args, "scan_type", None)
    if scan_type is not None:
        scan_type = str(scan_type).strip().lower()
        if scan_type not in ("url", "file"):
            die("--type must be one of: url, file")

    out_format = str(getattr(args, "format", "table") or "table").strip().lower()
    if out_format == "json":
        if scan_type is None:
            out = {
                "url_jobs": _fetch_jobs("url"),
                "file_jobs": _fetch_jobs("file"),
            }
            print(json.dumps(out, indent=2))
            return
        out = {"jobs": _fetch_jobs(scan_type)}
        print(json.dumps(out, indent=2))
        return

    # Table/lines format
    if scan_type is None:
        url_jobs = _fetch_jobs("url")
        file_jobs = _fetch_jobs("file")

        if out_format in ("table", "lines") and ui_render.render_jobs(
            [("URL scans", "url", url_jobs), ("File scans", "file", file_jobs)],
            config,
        ):
            return

        print("URL scans:")
        _print_url_jobs(url_jobs)
        print("")
        print("File scans:")
        _print_file_jobs(file_jobs)
        return

    jobs = _fetch_jobs(scan_type)
    if out_format in ("table", "lines") and ui_render.render_jobs(
        [(f"{scan_type.upper()} scans", scan_type, jobs)],
        config,
    ):
        return
    if scan_type == "file":
        _print_file_jobs(jobs)
    else:
        _print_url_jobs(jobs)


def cmd_history(config: Config, args):
    """Handler for 'history' command."""
    if not config.history_path.exists():
        log(f"No history yet at: {config.history_path}")
        return
    out_format = str(getattr(args, "format", "table") or "table").strip().lower()
    if config.json_output and out_format == "table":
        out_format = "json"
    limit = int(getattr(args, "limit", 0) or 0)

    if out_format == "tsv":
        read_history(config, limit)
        return

    entries = parse_history_entries(config, limit=limit)
    if out_format == "json":
        print(json.dumps(entries, indent=2))
        return

    if ui_render.render_history(entries, config):
        return

    print(f"{'timestamp':24}  {'job_id':36}  {'target':50}  base_url")
    for item in entries:
        ts = str(item.get("timestamp") or "")[:24]
        job_id = str(item.get("job_id") or "")[:36]
        target = str(item.get("url") or "")
        if len(target) > 50:
            target = target[:47] + "..."
        base_url = str(item.get("base_url") or "")
        print(f"{ts:24}  {job_id:36}  {target:50}  {base_url}")


def cmd_clear_history(config: Config, args):
    """Handler for 'clear-history' command."""
    confirm_or_die(config, args, f"Clear local history file at {config.history_path}?")
    if config.history_path.exists():
        config.history_path.unlink()
    log(f"Cleared history: {config.history_path}")


def cmd_clear_server_history(config: Config, args):
    """Handler for 'clear-server-history' command."""
    config.require_api_key()
    scan_type = getattr(args, "scan_type", None)
    if scan_type is not None:
        scan_type = str(scan_type).strip().lower()
        if scan_type not in ("url", "file"):
            die("--type must be one of: url, file")
    confirm_or_die(
        config,
        args,
        (
            f"Delete server job history for type={scan_type}?"
            if scan_type is not None
            else "Delete all server job history for this API key?"
        ),
    )

    path = "/jobs"
    if scan_type is not None:
        path = f"{path}?type={scan_type}"
    status, _, body = make_request(config, "DELETE", path)
    emit_json(body, config)


def cmd_screenshot(config: Config, args):
    """Handler for 'screenshot' command."""
    config.require_api_key()

    status_code, headers, body_bytes = make_request(
        config, "GET", f"/scan/{args.job_id}/screenshot", stream=True
    )

    if not isinstance(body_bytes, bytes):
        die("Expected bytes response for screenshot")

    ctype = headers.get("Content-Type", "")
    ext = "bin"
    if "image/jpeg" in ctype:
        ext = "jpg"
    elif "image/png" in ctype:
        ext = "png"

    default_name = f"{args.job_id}.{ext}"

    out_path = args.out
    if out_path:
        out_path_obj = Path(out_path)
        # Allow `--out` to be a directory (existing directory or a path ending in a separator).
        if out_path_obj.exists() and out_path_obj.is_dir():
            out_path_obj = out_path_obj / default_name
        elif str(out_path).endswith(("/", "\\")):
            out_path_obj = out_path_obj / default_name
        out_path = str(out_path_obj)
    elif args.out_dir:
        out_path = str(Path(args.out_dir) / default_name)
    else:
        out_path = f"./{default_name}"

    try:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(body_bytes)
        print(out_path)
    except Exception as e:
        die(f"Failed to write screenshot to {out_path}: {e}")


def cmd_scan_file(config: Config, args):
    """Handler for 'scan-file' command (multipart upload)."""
    config.require_api_key()
    file_path = Path(args.path)
    if not file_path.exists():
        die(f"File not found: {file_path}")

    # Multipart upload manually strictly with standard library is painful.
    # We will construct the body manually.
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    dash_boundary = f"--{boundary}".encode("utf-8")

    lines = []

    # File part
    filename = file_path.name
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    lines.append(dash_boundary)
    lines.append(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode(
            "utf-8"
        )
    )
    lines.append(f"Content-Type: {mime_type}".encode("utf-8"))
    lines.append(crlf)

    with open(file_path, "rb") as f:
        file_content = f.read()

    body = b"".join([*lines, file_content, crlf, dash_boundary + b"--" + crlf])

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }

    _, _, resp_body = make_request(
        config, "POST", "/file/scan", data=body, headers=headers
    )
    _handle_submit_response(config, args, resp_body, history_target=f"file://{filename}")


def cmd_scan_payload(config: Config, args):
    """Handler for 'scan-payload' command (multipart upload of text)."""
    config.require_api_key()

    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    dash_boundary = f"--{boundary}".encode("utf-8")

    parts = []

    # payload_base64
    if args.base64:
        parts.append(("payload_base64", "true"))

    # payload
    parts.append(("payload", args.text))

    body_parts = []
    for name, value in parts:
        body_parts.append(dash_boundary)
        body_parts.append(
            f'Content-Disposition: form-data; name="{name}"'.encode("utf-8")
        )
        body_parts.append(crlf)  # Empty header line
        body_parts.append(value.encode("utf-8"))
        body_parts.append(crlf)

    body_parts.append(dash_boundary + b"--" + crlf)

    full_body = b"".join(body_parts)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(full_body)),
    }

    _, _, resp_body = make_request(
        config, "POST", "/file/scan", data=full_body, headers=headers
    )
    target = _default_history_target_for_submit("payload", args)
    _handle_submit_response(config, args, resp_body, history_target=target)


def cmd_admin_list_api_keys(config: Config, args):
    """Handler for 'admin-list-keys' command."""
    config.require_api_key()
    params = [f"limit={args.limit}"]
    if args.include_inactive:
        params.append("include_inactive=true")
    path = f"/admin/api-keys?{'&'.join(params)}"
    status, _, body = make_request(config, "GET", path)
    emit_json(body, config)


def cmd_admin_mint_api_key(config: Config, args):
    """Handler for 'admin-mint-key' command."""
    config.require_api_key()
    payload: dict[str, Any] = {}
    if args.label:
        payload["label"] = args.label
    if args.read_rpm is not None:
        payload["read_rpm"] = args.read_rpm
    if args.write_rpm is not None:
        payload["write_rpm"] = args.write_rpm
    if args.ttl_days is not None:
        payload["ttl_days"] = args.ttl_days
    if args.is_admin:
        payload["is_admin"] = True
    status, _, body = make_request(config, "POST", "/admin/api-keys", data=payload)
    emit_json(body, config)


def cmd_admin_revoke_api_key(config: Config, args):
    """Handler for 'admin-revoke-key' command."""
    config.require_api_key()
    key_hash = str(args.key_hash or "").strip().lower()
    if len(key_hash) != 64 or any(c not in "0123456789abcdef" for c in key_hash):
        die("key_hash must be a 64-character sha256 hex digest")
    path = f"/admin/api-keys/{key_hash}/revoke"
    status, _, body = make_request(config, "POST", path)
    emit_json(body, config)


def cmd_env(config: Config, args):
    unset = bool(getattr(args, "unset", False))
    print(emit_shell_exports(config.resolved_context, unset=unset))


def cmd_config_show(config: Config, args):
    show_secrets = bool(getattr(args, "show_secrets", False))
    out = {
        "context": config.context,
        "base_url": config.base_url,
        "api_key_header": config.api_key_header,
        "api_key_present": bool(config.api_key),
        "api_key": config.api_key if show_secrets else _mask_secret(config.api_key),
        "api_fqdn": config.resolved_context.api_fqdn,
        "history_path": str(config.history_path),
        "dotenv_path": str(config.dotenv_path) if config.dotenv_path else "",
        "repo_root": str(config.repo_root) if config.repo_root else "",
        "is_tty": config.is_tty,
        "source_details": config.resolved_context.source_details,
    }
    emit_json(out, config, kind="config")


def cmd_doctor(config: Config, args):
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    add("python", True, sys.executable)
    add(
        "repo_root",
        bool(config.repo_root and config.repo_root.exists()),
        str(config.repo_root) if config.repo_root else "not a source checkout",
    )
    add(
        "dotenv_path",
        bool(config.dotenv_path and config.dotenv_path.exists()),
        str(config.dotenv_path) if config.dotenv_path else "not found",
    )
    add("history_parent", config.history_path.parent.exists(), str(config.history_path.parent))
    add("base_url", bool(config.base_url), config.base_url or "<empty>")
    add("api_key", bool(config.api_key), "present" if config.api_key else "missing")
    if config.context == "az":
        add("az_cli", shutil.which("az") is not None, shutil.which("az") or "not found")
        add(
            "azure_context",
            bool(config.resolved_context.api_fqdn and config.resolved_context.api_key),
            config.resolved_context.api_fqdn or "resolution failed",
        )
    else:
        add("az_cli", shutil.which("az") is not None, shutil.which("az") or "not found")

    out = {
        "context": config.context,
        "base_url": config.base_url,
        "api_key_header": config.api_key_header,
        "api_key_present": bool(config.api_key),
        "history_path": str(config.history_path),
        "dotenv_path": str(config.dotenv_path) if config.dotenv_path else "",
        "checks": checks,
    }
    emit_json(out, config, kind="doctor")


# --- Main ---


def build_parser() -> argparse.ArgumentParser:
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

    parser._cmd_parsers = cmd_parsers  # type: ignore[attr-defined]
    return parser


def _resolved_command_name(args) -> str:
    if getattr(args, "command", None) == "config":
        sub = str(getattr(args, "config_command", "") or "").strip()
        if sub:
            return f"config {sub}"
    return str(getattr(args, "command", "") or "")


def _print_help_topic(parser: argparse.ArgumentParser, args) -> int:
    cmd_parsers = getattr(parser, "_cmd_parsers", {})
    topic_tokens = [str(t).strip() for t in (getattr(args, "topic", None) or []) if str(t).strip()]
    topic = " ".join(topic_tokens)
    if topic:
        if topic not in cmd_parsers:
            die(
                f"Unknown help topic: {topic}. Try one of: {', '.join(sorted(cmd_parsers.keys()))}"
            )
        print(cmd_parsers[topic].format_help().rstrip())
        return 0

    print(parser.format_help().rstrip())
    print("\n---\n")
    for name in sorted(k for k in cmd_parsers.keys() if k != "help"):
        print(cmd_parsers[name].format_help().rstrip())
        print("\n---\n")
    return 0


def _dispatch_command(config: Config, args) -> int:
    cmd_map = {
        "health": cmd_health,
        "scan-url": cmd_scan_url,
        "status": cmd_status,
        "wait": cmd_wait,
        "watch": cmd_watch,
        "jobs": cmd_jobs,
        "history": cmd_history,
        "clear-history": cmd_clear_history,
        "clear-server-history": cmd_clear_server_history,
        "screenshot": cmd_screenshot,
        "scan-file": cmd_scan_file,
        "scan-payload": cmd_scan_payload,
        "admin-list-keys": cmd_admin_list_api_keys,
        "admin-mint-key": cmd_admin_mint_api_key,
        "admin-revoke-key": cmd_admin_revoke_api_key,
        "env": cmd_env,
        "doctor": cmd_doctor,
        "config show": cmd_config_show,
    }
    command_name = _resolved_command_name(args)
    handler = cmd_map.get(command_name)
    if not handler:
        return 0

    if command_name not in {"env", "doctor", "config show"}:
        maybe_prompt_for_missing_args(command_name, args, config)
        ensure_required_command_args(command_name, args)
    handler(config, args)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "help":
        return _print_help_topic(parser, args)

    config = Config(args)
    return _dispatch_command(config, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
