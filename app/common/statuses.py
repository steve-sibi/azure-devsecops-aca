from __future__ import annotations

STATUS_RANKS: dict[str, int] = {
    "queued": 10,
    "fetching": 20,
    "queued_scan": 30,
    "retrying": 40,
    # terminal
    "blocked": 100,
    "completed": 100,
    "error": 100,
}

TERMINAL_STATUSES = {"completed", "error", "blocked"}
ALLOWED_JOB_STATUSES = set(STATUS_RANKS.keys())
