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


@dataclass(frozen=True)
class ReqEntry:
    name: str
    op: str
    version: str
    line_no: int
    raw: str


def parse_target_entries(path: Path) -> tuple[dict[str, ReqEntry], list[str]]:
    entries: dict[str, ReqEntry] = {}
    errors: list[str] = []

    for idx, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue

        match = LINE_RE.match(line)
        if not match:
            continue

        name = match.group(1).lower()
        if name not in EXPECTED_PINS:
            continue

        entry = ReqEntry(
            name=name,
            op=match.group(2),
            version=match.group(3),
            line_no=idx,
            raw=line,
        )

        if name in entries:
            prev = entries[name]
            errors.append(
                f"{path}:{idx} duplicate entry for '{name}' "
                f"(already defined at line {prev.line_no})."
            )
            continue

        entries[name] = entry

    for name, expected in EXPECTED_PINS.items():
        if name not in entries:
            errors.append(
                f"{path} missing required pin '{name}=={expected}'."
            )
            continue

        entry = entries[name]
        if entry.op != "==":
            errors.append(
                f"{path}:{entry.line_no} '{name}' must use exact pin '=={expected}', "
                f"found '{entry.raw}'."
            )
            continue

        if entry.version != expected:
            errors.append(
                f"{path}:{entry.line_no} '{name}' must be '{expected}', "
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
