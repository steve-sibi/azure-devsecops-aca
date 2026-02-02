from __future__ import annotations

import json
from dataclasses import dataclass

DEFAULT_MAX_ERROR_CHARS = 300


@dataclass(frozen=True)
class ErrorInfo:
    code: str
    message: str
    retryable: bool
    log_traceback: bool = False


def _truncate(value: str, *, max_chars: int) -> str:
    s = str(value or "")
    if max_chars <= 0 or len(s) <= max_chars:
        return s
    return s[: max(0, max_chars - 3)] + "..."


def classify_exception(
    exc: Exception, *, max_error_chars: int = DEFAULT_MAX_ERROR_CHARS
) -> ErrorInfo:
    from common.scan_messages import ScanMessageValidationError
    from common.url_validation import UrlValidationError

    if isinstance(exc, ScanMessageValidationError):
        return ErrorInfo(
            code="invalid_message",
            message=_truncate(str(exc), max_chars=max_error_chars),
            retryable=False,
            log_traceback=False,
        )

    if isinstance(exc, UrlValidationError):
        return ErrorInfo(
            code=str(exc.code or "invalid_url"),
            message=_truncate(str(exc), max_chars=max_error_chars),
            retryable=False,
            log_traceback=False,
        )

    if isinstance(exc, json.JSONDecodeError):
        return ErrorInfo(
            code="invalid_message_json",
            message="invalid message JSON",
            retryable=False,
            log_traceback=False,
        )

    msg = str(exc or "").strip()
    if msg.startswith("invalid message payload"):
        return ErrorInfo(
            code="invalid_message",
            message=_truncate(msg, max_chars=max_error_chars),
            retryable=False,
            log_traceback=False,
        )
    if msg == "artifact sha256 mismatch" or msg.startswith("artifact size mismatch"):
        return ErrorInfo(
            code="artifact_mismatch",
            message=_truncate(msg, max_chars=max_error_chars),
            retryable=False,
            log_traceback=False,
        )

    if msg in (
        "content too large",
        "too many redirects",
        "redirect without Location header",
    ):
        return ErrorInfo(
            code="upstream_rejected",
            message=_truncate(msg, max_chars=max_error_chars),
            retryable=False,
            log_traceback=False,
        )

    # requests.HTTPError and friends (avoid importing requests at runtime)
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int) and 100 <= status <= 599:
        retryable = status >= 500 or status in (408, 425, 429)
        code = f"http_{status}"
        return ErrorInfo(
            code=code,
            message=f"upstream HTTP {status}",
            retryable=retryable,
            log_traceback=not retryable,
        )

    # Treat common network-ish errors as retryable; keep message generic.
    exc_name = exc.__class__.__name__
    if exc_name.lower().endswith("timeout") or exc_name in (
        "ConnectionError",
        "ConnectError",
        "ConnectTimeout",
        "ReadTimeout",
        "Timeout",
    ):
        return ErrorInfo(
            code="network_error",
            message="network error",
            retryable=True,
            log_traceback=False,
        )

    return ErrorInfo(
        code="internal_error",
        message=_truncate(exc.__class__.__name__, max_chars=max_error_chars),
        retryable=True,
        log_traceback=True,
    )
