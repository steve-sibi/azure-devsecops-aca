from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_TELEMETRY_INIT_DONE = False
_TELEMETRY_ACTIVE = False


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def get_appinsights_connection_string() -> str:
    return (
        os.getenv("APPINSIGHTS_CONN")
        or os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING")
        or ""
    ).strip()


def get_otlp_traces_endpoint() -> str:
    traces_endpoint = (os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or "").strip()
    if traces_endpoint:
        return traces_endpoint

    otlp_endpoint = (os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or "").strip()
    if not otlp_endpoint:
        return ""
    if otlp_endpoint.lower().endswith("/v1/traces"):
        return otlp_endpoint
    return otlp_endpoint.rstrip("/") + "/v1/traces"


def get_otlp_headers() -> dict[str, str]:
    raw = (os.getenv("OTEL_EXPORTER_OTLP_HEADERS") or "").strip()
    if not raw:
        return {}
    headers: dict[str, str] = {}
    for part in raw.split(","):
        item = part.strip()
        if not item or "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def telemetry_enabled_from_env() -> bool:
    raw = os.getenv("OTEL_ENABLED")
    if isinstance(raw, str) and raw.strip():
        return _is_truthy(raw)
    return bool(get_appinsights_connection_string() or get_otlp_traces_endpoint())


def telemetry_is_active() -> bool:
    return _TELEMETRY_ACTIVE


def _trace_sampler_ratio() -> float:
    raw = (os.getenv("OTEL_TRACES_SAMPLER_RATIO", "0.10") or "0.10").strip()
    try:
        value = float(raw)
    except Exception:
        return 0.10
    return max(0.0, min(1.0, value))


def setup_telemetry(*, service_name: str, logger_obj: Optional[logging.Logger] = None) -> bool:
    """
    Configure OpenTelemetry trace export for the configured backend.

    Returns True when telemetry is active; False when disabled/unavailable.
    Safe to call repeatedly.
    """
    global _TELEMETRY_INIT_DONE, _TELEMETRY_ACTIVE

    if _TELEMETRY_INIT_DONE:
        return _TELEMETRY_ACTIVE
    _TELEMETRY_INIT_DONE = True

    log = logger_obj or logger
    if not telemetry_enabled_from_env():
        log.info("OpenTelemetry disabled (OTEL_ENABLED=false).")
        _TELEMETRY_ACTIVE = False
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased
    except Exception as exc:
        log.warning("OpenTelemetry dependencies unavailable: %s", exc)
        _TELEMETRY_ACTIVE = False
        return False

    try:
        resource = Resource.create(
            {
                "service.name": service_name,
                "service.namespace": (
                    os.getenv("OTEL_SERVICE_NAMESPACE", "aca-urlscanner").strip()
                    or "aca-urlscanner"
                ),
                "service.version": (
                    os.getenv("OTEL_SERVICE_VERSION", "1.0.0").strip() or "1.0.0"
                ),
            }
        )
        ratio = _trace_sampler_ratio()
        provider = TracerProvider(
            resource=resource,
            sampler=ParentBased(TraceIdRatioBased(ratio)),
        )

        exporter_name = ""
        conn = get_appinsights_connection_string()
        if conn:
            from azure.monitor.opentelemetry.exporter import AzureMonitorTraceExporter

            exporter = AzureMonitorTraceExporter(connection_string=conn)
            exporter_name = "azure-monitor"
        else:
            otlp_endpoint = get_otlp_traces_endpoint()
            if not otlp_endpoint:
                log.warning(
                    "OpenTelemetry requested but no trace exporter is configured. "
                    "Set APPINSIGHTS_CONN/APPLICATIONINSIGHTS_CONNECTION_STRING or "
                    "OTEL_EXPORTER_OTLP_ENDPOINT."
                )
                _TELEMETRY_ACTIVE = False
                return False

            from opentelemetry.exporter.otlp.proto.http.trace_exporter import \
                OTLPSpanExporter

            headers = get_otlp_headers()
            exporter = OTLPSpanExporter(
                endpoint=otlp_endpoint,
                headers=headers or None,
            )
            exporter_name = f"otlp-http ({otlp_endpoint})"

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _TELEMETRY_ACTIVE = True
        log.info(
            "OpenTelemetry enabled (service=%s exporter=%s sampler_ratio=%.2f).",
            service_name,
            exporter_name,
            ratio,
        )
        return True
    except Exception as exc:
        log.warning("OpenTelemetry initialization failed: %s", exc)
        _TELEMETRY_ACTIVE = False
        return False


def get_tracer(name: str):
    try:
        from opentelemetry import trace
    except Exception:
        return None
    return trace.get_tracer(name)


def inject_trace_context(carrier: dict[str, str]) -> dict[str, str]:
    try:
        from opentelemetry import propagate
    except Exception:
        return carrier
    try:
        propagate.inject(carrier)
    except Exception:
        return carrier
    return carrier


def extract_trace_context(*, traceparent: Optional[str], tracestate: Optional[str]):
    carrier: dict[str, str] = {}
    if isinstance(traceparent, str) and traceparent.strip():
        carrier["traceparent"] = traceparent.strip()
    if isinstance(tracestate, str) and tracestate.strip():
        carrier["tracestate"] = tracestate.strip()
    if not carrier:
        return None

    try:
        from opentelemetry import propagate
    except Exception:
        return None
    try:
        return propagate.extract(carrier)
    except Exception:
        return None


def get_current_trace_fields() -> dict[str, str]:
    try:
        from opentelemetry import trace
    except Exception:
        return {}

    try:
        span = trace.get_current_span()
        span_ctx = span.get_span_context() if span else None
        if not span_ctx or not span_ctx.is_valid:
            return {}
        return {
            "trace_id": f"{int(span_ctx.trace_id):032x}",
            "span_id": f"{int(span_ctx.span_id):016x}",
        }
    except Exception:
        return {}
