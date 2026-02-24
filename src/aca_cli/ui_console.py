from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any, Mapping

try:  # pragma: no cover - optional dependency
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.text import Text
    from rich.pretty import Pretty
    from rich.status import Status
    from rich import box

    RICH_AVAILABLE = True
except Exception:  # pragma: no cover - fallback when rich is not installed
    Console = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Tree = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]
    Pretty = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    box = None  # type: ignore[assignment]
    RICH_AVAILABLE = False


STATUS_STYLES: dict[str, str] = {
    "pending": "yellow",
    "queued": "yellow",
    "fetching": "cyan",
    "queued_scan": "blue",
    "retrying": "magenta",
    "blocked": "bright_red",
    "error": "red",
    "completed": "green",
}


@dataclass(slots=True)
class ConsoleBundle:
    stdout: Any | None
    stderr: Any | None
    rich_stdout: bool
    rich_stderr: bool
    color_mode: str
    unicode_symbols: bool


def resolve_color_mode(requested: str | None, env: Mapping[str, str] | None = None) -> str:
    mode = str(requested or "auto").strip().lower() or "auto"
    if mode not in {"auto", "always", "never"}:
        mode = "auto"
    env_map = dict(env or os.environ)
    if mode == "auto" and "NO_COLOR" in env_map:
        return "never"
    return mode


def _stream_encoding(stream) -> str:
    try:
        return str(getattr(stream, "encoding", "") or "")
    except Exception:
        return ""


def supports_unicode(stream=None) -> bool:
    stream = stream or sys.stdout
    enc = _stream_encoding(stream).lower()
    if enc and "utf" in enc:
        return True
    lang = str(os.environ.get("LC_ALL") or os.environ.get("LANG") or "").lower()
    return "utf" in lang


def _should_force_terminal(stream, *, color_mode: str) -> bool:
    if color_mode == "always":
        return True
    if color_mode == "never":
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def create_console(stream, *, color_mode: str = "auto", stderr: bool = False):
    if not RICH_AVAILABLE or Console is None:
        return None
    force_terminal = _should_force_terminal(stream, color_mode=color_mode)
    no_color = color_mode == "never"
    return Console(
        file=stream,
        stderr=stderr,
        force_terminal=force_terminal,
        no_color=no_color,
        soft_wrap=True,
        highlight=False,
    )


def build_console_bundle(*, color_mode: str, stdout, stderr) -> ConsoleBundle:
    resolved = resolve_color_mode(color_mode)
    stdout_console = create_console(stdout, color_mode=resolved, stderr=False)
    stderr_console = create_console(stderr, color_mode=resolved, stderr=True)
    return ConsoleBundle(
        stdout=stdout_console,
        stderr=stderr_console,
        rich_stdout=bool(stdout_console),
        rich_stderr=bool(stderr_console),
        color_mode=resolved,
        unicode_symbols=supports_unicode(stdout) and supports_unicode(stderr),
    )


def status_style(status: str | None) -> str:
    key = str(status or "").strip().lower()
    return STATUS_STYLES.get(key, "white")


def status_icon(status: str | None, *, unicode_symbols: bool = True) -> str:
    key = str(status or "").strip().lower()
    if unicode_symbols:
        mapping = {
            "pending": "◌",
            "queued": "◔",
            "fetching": "⇣",
            "queued_scan": "⧗",
            "retrying": "↻",
            "blocked": "✖",
            "error": "✖",
            "completed": "✔",
        }
    else:
        mapping = {
            "pending": ".",
            "queued": ">",
            "fetching": "v",
            "queued_scan": "~",
            "retrying": "R",
            "blocked": "X",
            "error": "X",
            "completed": "OK",
        }
    return mapping.get(key, "?")


def bool_icon(value: bool, *, unicode_symbols: bool = True) -> str:
    if unicode_symbols:
        return "✔" if value else "✖"
    return "OK" if value else "NO"


def fmt_bytes(value: Any) -> str:
    try:
        num = int(value)
    except Exception:
        return "-"
    if num < 0:
        return str(num)
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(num)
    for unit in units:
        if n < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(n)} {unit}"
            if n >= 100:
                return f"{n:.0f} {unit}"
            if n >= 10:
                return f"{n:.1f} {unit}"
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{num} B"


def fmt_duration_ms(value: Any) -> str:
    try:
        ms = int(value)
    except Exception:
        return "-"
    if ms < 1000:
        return f"{ms} ms"
    seconds = ms / 1000.0
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes = int(seconds // 60)
    rem = seconds % 60
    return f"{minutes}m {rem:.0f}s"


def truncate(value: Any, limit: int) -> str:
    text = str(value or "")
    if limit <= 0 or len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."

