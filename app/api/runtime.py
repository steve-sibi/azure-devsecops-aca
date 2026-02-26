from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from common.live_updates import resolve_live_updates_backend
from common.webpubsub import create_service_client
from fastapi import FastAPI, Request

import settings


def _new_runtime_state() -> SimpleNamespace:
    live_updates_state = resolve_live_updates_backend(
        webpubsub_cfg=settings.WEBPUBSUB_CFG,
        redis_available=False,
    )
    return SimpleNamespace(
        sb_client=None,
        sb_sender=None,
        table_service=None,
        table_client=None,
        redis_client=None,
        blob_service=None,
        webpubsub_client=None,
        live_updates_state=live_updates_state,
        live_updates_backend=live_updates_state.selected,
        telemetry_active=False,
    )


_FALLBACK_STATE = _new_runtime_state()


def _state(obj: Request | FastAPI | None = None):
    if isinstance(obj, Request):
        app = getattr(obj, "app", None)
        if app is not None and hasattr(app, "state"):
            return app.state
        return _FALLBACK_STATE
    if isinstance(obj, FastAPI):
        return obj.state
    if obj is None:
        return _FALLBACK_STATE
    state = getattr(obj, "state", None)
    return state if state is not None else _FALLBACK_STATE


def init_app_state(app: FastAPI) -> None:
    dst = app.state
    src = _new_runtime_state()
    for name, value in vars(src).items():
        if not hasattr(dst, name):
            setattr(dst, name, value)


def refresh_live_updates_backend(*, obj: Request | FastAPI | None = None, redis_available: bool) -> None:
    state = _state(obj)
    live_updates_state = resolve_live_updates_backend(
        webpubsub_cfg=settings.WEBPUBSUB_CFG,
        redis_available=redis_available,
    )
    state.live_updates_state = live_updates_state
    state.live_updates_backend = live_updates_state.selected


def get_live_updates_backend(obj: Request | FastAPI | None = None) -> str:
    state = _state(obj)
    return str(getattr(state, "live_updates_backend", "none") or "none")


def get_webpubsub_client(obj: Request | FastAPI | None = None):
    if not settings.WEBPUBSUB_CFG:
        return None
    state = _state(obj)
    client = getattr(state, "webpubsub_client", None)
    if client is None:
        client = create_service_client(settings.WEBPUBSUB_CFG)
        state.webpubsub_client = client
    return client


def get_sb_client(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "sb_client", None)


def set_sb_client(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).sb_client = value


def get_sb_sender(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "sb_sender", None)


def set_sb_sender(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).sb_sender = value


def get_table_service(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "table_service", None)


def set_table_service(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).table_service = value


def get_table_client(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "table_client", None)


def set_table_client(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).table_client = value


def get_redis_client(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "redis_client", None)


def set_redis_client(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).redis_client = value


def get_blob_service(obj: Request | FastAPI | None = None):
    return getattr(_state(obj), "blob_service", None)


def set_blob_service(value: Any, obj: Request | FastAPI | None = None) -> None:
    _state(obj).blob_service = value


def is_telemetry_active(obj: Request | FastAPI | None = None) -> bool:
    return bool(getattr(_state(obj), "telemetry_active", False))


def set_telemetry_active(value: bool, obj: Request | FastAPI | None = None) -> None:
    _state(obj).telemetry_active = bool(value)
