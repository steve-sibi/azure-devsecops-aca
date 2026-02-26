#!/usr/bin/env python3
"""Validate duplicated status constants stay synchronized across app and CLI."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_terminal_statuses(path: Path) -> set[str]:
    tree = ast.parse(_read(path), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == "TERMINAL_STATUSES":
                value = ast.literal_eval(node.value)
                if not isinstance(value, (set, list, tuple)):
                    raise TypeError(
                        f"{path}: TERMINAL_STATUSES must be a set/list/tuple literal"
                    )
                out = {str(item) for item in value}
                if not out:
                    raise ValueError(f"{path}: TERMINAL_STATUSES must not be empty")
                return out
    raise ValueError(f"{path}: TERMINAL_STATUSES assignment not found")


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    server_path = repo_root / "app" / "common" / "statuses.py"
    cli_path = repo_root / "src" / "aca_cli" / "core.py"
    errors: list[str] = []

    try:
        server_statuses = _load_terminal_statuses(server_path)
    except Exception as exc:
        errors.append(f"{server_path}: {exc}")
        server_statuses = set()

    try:
        cli_statuses = _load_terminal_statuses(cli_path)
    except Exception as exc:
        errors.append(f"{cli_path}: {exc}")
        cli_statuses = set()

    if not errors and server_statuses != cli_statuses:
        errors.append(
            f"terminal status mismatch: app/common={sorted(server_statuses)} "
            f"src/aca_cli={sorted(cli_statuses)}"
        )

    if errors:
        print("[status-check] FAIL")
        for item in errors:
            print(f"- {item}")
        return 1

    print("[status-check] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
