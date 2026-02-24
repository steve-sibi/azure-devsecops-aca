from __future__ import annotations

import json
from typing import Any

from . import ui_render
from .config import Config

def emit_output(output, config: Config, *, kind: str | None = None):
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
