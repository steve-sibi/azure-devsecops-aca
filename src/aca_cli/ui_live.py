from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import ui_console


@dataclass
class RichLiveReporter:
    console: Any | None
    enabled: bool
    unicode_symbols: bool = True
    _status_obj: Any | None = None
    _last_transition: tuple[str, str, str] | None = None
    _started: bool = False
    _spinner_enabled: bool = True
    _active_message: str = ""
    _timeline: list[tuple[str, str, str | None]] = field(default_factory=list)

    @classmethod
    def from_config(cls, config) -> "RichLiveReporter":
        console = getattr(config, "stderr_console", None)
        enabled = bool(getattr(config, "rich_stderr", False) and console and ui_console.Status)
        return cls(
            console=console,
            enabled=enabled,
            unicode_symbols=bool(getattr(config, "unicode_symbols", True)),
            _spinner_enabled=bool(getattr(config, "spinner", True)),
        )

    @property
    def active(self) -> bool:
        return self.enabled

    def start(self, message: str) -> None:
        if not self.enabled or self.console is None:
            return
        self._active_message = message
        if not self._spinner_enabled:
            self.console.print(message)
            return
        try:
            self._status_obj = self.console.status(message, spinner="dots")
            self._status_obj.start()
            self._started = True
        except Exception:
            self._status_obj = None
            self._started = False

    def update(self, message: str) -> None:
        if not self.enabled or self.console is None:
            return
        self._active_message = message
        if self._status_obj is not None:
            try:
                self._status_obj.update(message)
                return
            except Exception:
                pass
        if not self._spinner_enabled:
            return

    def _stop_spinner(self) -> None:
        if not self.enabled:
            return
        if self._status_obj is None:
            return
        try:
            self._status_obj.stop()
        except Exception:
            pass
        finally:
            self._status_obj = None
            self._started = False

    def note(self, message: str, *, style: str | None = None) -> None:
        if not self.enabled or self.console is None:
            return
        restart = bool(self._status_obj)
        if restart:
            self._stop_spinner()
        if style:
            self.console.print(f"[{style}]{message}[/{style}]")
        else:
            self.console.print(message)
        if restart and self._spinner_enabled and self._active_message:
            self.start(self._active_message)

    def transition(
        self,
        status: str | None,
        *,
        stage: str | None = None,
        error: str | None = None,
        duration_ms: Any = None,
        size_bytes: Any = None,
    ) -> None:
        if not self.enabled or self.console is None:
            return
        status_s = str(status or "unknown").strip().lower() or "unknown"
        stage_s = str(stage or "").strip().lower()
        error_s = str(error or "").strip()
        key = (status_s, stage_s, error_s)
        if key == self._last_transition:
            return
        self._last_transition = key
        icon = ui_console.status_icon(status_s, unicode_symbols=self.unicode_symbols)
        style = ui_console.status_style(status_s)
        parts = [f"[{style}]{icon} {status_s}[/{style}]"]
        if stage_s:
            parts.append(f"stage={stage_s}")
        if duration_ms not in (None, "", 0):
            parts.append(f"duration={ui_console.fmt_duration_ms(duration_ms)}")
        if size_bytes not in (None, "", 0):
            parts.append(f"size={ui_console.fmt_bytes(size_bytes)}")
        if error_s:
            parts.append(f"error={ui_console.truncate(error_s, 160)}")
        line = "  ".join(parts)
        self.note(line)
        self._timeline.append((status_s, stage_s, error_s or None))

    def fallback_notice(self) -> None:
        self.note("Live stream unavailable; falling back to polling.", style="yellow")

    def done(self, message: str | None = None) -> None:
        if not self.enabled or self.console is None:
            return
        self._stop_spinner()
        if message:
            self.console.print(message)
