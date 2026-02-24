from __future__ import annotations

import sys
from typing import NoReturn

from ._version import __version__

# "pending" is CLI-visible as an initial submit state and is not in server STATUS_RANKS.
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
TERMINAL_STATUSES = {"completed", "error", "blocked"}  # Keep in sync with app/common/statuses.py:TERMINAL_STATUSES
RESULT_VIEW_CHOICES = ("summary", "full")


def die(msg: str) -> NoReturn:
    """Print error message to stderr and exit with status 1."""
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg):
    """Print message to stderr."""
    print(msg, file=sys.stderr)
