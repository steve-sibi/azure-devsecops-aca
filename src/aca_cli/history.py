from __future__ import annotations

import sys
from datetime import datetime, timezone

from .config import Config
from .core import log

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

