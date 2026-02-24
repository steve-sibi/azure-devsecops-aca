from __future__ import annotations

import argparse
import dataclasses
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

from . import ui_console
from .core import die, log

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

