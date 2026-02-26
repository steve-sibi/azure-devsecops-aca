#!/usr/bin/env python3
"""Enforce OpenTelemetry dependency contract across API/Worker requirements."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


EXPECTED_PINS: dict[str, str] = {
    "opentelemetry-api": "1.38.0",
    "opentelemetry-sdk": "1.38.0",
    "opentelemetry-exporter-otlp-proto-http": "1.38.0",
    "azure-monitor-opentelemetry-exporter": "1.0.0b45",
}

LINE_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*([<>=!~]{1,2})\s*([^\s;]+)")
INCLUDE_RE = re.compile(r"^(?:-r|--requirement)\s+(.+)$")


@dataclass(frozen=True)
class ReqEntry:
    path: Path
    name: str
    op: str
    version: str
    line_no: int
    raw: str


def _merge_entry(
    entries: dict[str, ReqEntry],
    entry: ReqEntry,
    *,
    errors: list[str],
) -> None:
    if entry.name in entries:
        prev = entries[entry.name]
        errors.append(
            f"{entry.path}:{entry.line_no} duplicate entry for '{entry.name}' "
            f"(already defined at {prev.path}:{prev.line_no})."
        )
        return
    entries[entry.name] = entry


def _parse_entries_recursive(
    path: Path,
    *,
    stack: tuple[Path, ...],
) -> tuple[dict[str, ReqEntry], list[str]]:
    entries: dict[str, ReqEntry] = {}
    errors: list[str] = []

    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return entries, [f"{path} requirements file not found."]

    if path in stack:
        cycle = " -> ".join(str(p) for p in (*stack, path))
        return entries, [f"requirements include cycle detected: {cycle}"]

    for idx, raw in enumerate(raw_lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        include_match = INCLUDE_RE.match(line)
        if include_match:
            include_value = include_match.group(1).strip()
            if not include_value:
                errors.append(f"{path}:{idx} empty include path in '{raw.strip()}'.")
                continue
            include_path = (path.parent / include_value).resolve()
            child_entries, child_errors = _parse_entries_recursive(
                include_path,
                stack=(*stack, path),
            )
            errors.extend(child_errors)
            for child_entry in child_entries.values():
                _merge_entry(entries, child_entry, errors=errors)
            continue

        if line.startswith(("-", "--")):
            continue

        match = LINE_RE.match(line)
        if not match:
            continue

        name = match.group(1).lower()
        if name not in EXPECTED_PINS:
            continue

        entry = ReqEntry(
            path=path,
            name=name,
            op=match.group(2),
            version=match.group(3),
            line_no=idx,
            raw=line,
        )

        _merge_entry(entries, entry, errors=errors)

    return entries, errors


def parse_target_entries(path: Path) -> tuple[dict[str, ReqEntry], list[str]]:
    entries, errors = _parse_entries_recursive(path.resolve(), stack=())

    for name, expected in EXPECTED_PINS.items():
        if name not in entries:
            errors.append(
                f"{path} missing required pin '{name}=={expected}'."
            )
            continue

        entry = entries[name]
        if entry.op != "==":
            errors.append(
                f"{entry.path}:{entry.line_no} '{name}' must use exact pin '=={expected}', "
                f"found '{entry.raw}'."
            )
            continue

        if entry.version != expected:
            errors.append(
                f"{entry.path}:{entry.line_no} '{name}' must be '{expected}', "
                f"found '{entry.version}'."
            )

    return entries, errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    api_requirements = repo_root / "app" / "api" / "requirements.txt"
    worker_requirements = repo_root / "app" / "worker" / "requirements.txt"

    api_entries, api_errors = parse_target_entries(api_requirements)
    worker_entries, worker_errors = parse_target_entries(worker_requirements)

    errors = [*api_errors, *worker_errors]
    if not errors:
        api_contract = {name: (entry.op, entry.version) for name, entry in api_entries.items()}
        worker_contract = {
            name: (entry.op, entry.version) for name, entry in worker_entries.items()
        }
        if api_contract != worker_contract:
            errors.append(
                "Telemetry pins differ between app/api/requirements.txt and "
                "app/worker/requirements.txt."
            )

    if errors:
        print("[otel-contract] FAIL")
        for err in errors:
            print(f"- {err}")
        return 1

    print("[otel-contract] PASS")
    for name in sorted(EXPECTED_PINS):
        print(f"- {name}=={EXPECTED_PINS[name]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
