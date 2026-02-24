from __future__ import annotations

import sys

from .config import Config
from .core import die
from .history import parse_history_entries

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

