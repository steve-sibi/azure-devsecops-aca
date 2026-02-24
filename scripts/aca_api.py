#!/usr/bin/env python3
"""Compatibility shim for the packaged ACA CLI.

This script remains runnable from a source checkout while delegating all CLI
implementation to `aca_cli.cli` for packaging/installability.
"""

from __future__ import annotations

import sys
from pathlib import Path


# Support running directly from a source checkout without `pip install -e .`.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if SRC_DIR.exists():
    src_str = str(SRC_DIR)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)

from aca_cli.cli import *  # noqa: E402,F401,F403
from aca_cli.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
