#!/usr/bin/env python3
"""Validate local OpenTelemetry sampler ratio using Jaeger traces."""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any


def _http_json(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> Any:
    data = None
    req_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(
        url=url,
        data=data,
        headers=req_headers,
        method=method,
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    if not raw.strip():
        return {}
    return json.loads(raw)


def _submit_scan(
    *,
    api_url: str,
    api_key: str,
    run_label: str,
    index: int,
    timeout: float,
) -> tuple[str, str]:
    url = f"{api_url.rstrip('/')}/scan"
    corr_id = f"{run_label}-{index:04d}"
    body = {
        "url": f"https://example.com/?sampler={urllib.parse.quote(corr_id, safe='')}",
        "type": "url",
        "force": True,
        "visibility": "private",
    }
    response = _http_json(
        url=url,
        method="POST",
        timeout=timeout,
        headers={
            "X-API-Key": api_key,
            "X-Correlation-ID": corr_id,
        },
        payload=body,
    )
    if not isinstance(response, dict):
        raise RuntimeError(f"Unexpected /scan response payload type: {type(response)}")
    job_id = str(response.get("job_id") or "").strip()
    run_id = str(response.get("run_id") or "").strip()
    if not job_id:
        raise RuntimeError(f"Missing job_id in /scan response: {response}")
    if not run_id:
        run_id = job_id
    return job_id, run_id


def _query_jaeger_trace_ids(
    *,
    jaeger_url: str,
    service: str,
    operation: str,
    start_us: int,
    end_us: int,
    limit: int,
    timeout: float,
) -> set[str]:
    params = urllib.parse.urlencode(
        {
            "service": service,
            "operation": operation,
            "start": str(start_us),
            "end": str(end_us),
            "limit": str(limit),
        }
    )
    url = f"{jaeger_url.rstrip('/')}/api/traces?{params}"
    payload = _http_json(url=url, timeout=timeout)
    if not isinstance(payload, dict):
        return set()
    data = payload.get("data")
    if not isinstance(data, list):
        return set()
    out: set[str] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        trace_id = item.get("traceID")
        if isinstance(trace_id, str) and trace_id.strip():
            out.add(trace_id.strip())
    return out


def _tolerance(expected_ratio: float, requests: int, min_abs: float) -> float:
    if requests <= 0:
        return 1.0
    variance = expected_ratio * (1.0 - expected_ratio)
    sigma = 3.0 * math.sqrt(max(variance, 1e-9) / float(requests))
    return max(min_abs, sigma)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Submit local scan requests and verify observed sampled traces in Jaeger "
            "against OTEL_TRACES_SAMPLER_RATIO."
        )
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="Base API URL (default: %(default)s)",
    )
    parser.add_argument(
        "--api-key",
        default="local-dev-key",
        help="API key to use for /scan requests (default: %(default)s)",
    )
    parser.add_argument(
        "--jaeger-url",
        default="http://localhost:16686",
        help="Jaeger UI/API base URL (default: %(default)s)",
    )
    parser.add_argument(
        "--service",
        default="api",
        help="Jaeger service.name to query (default: %(default)s)",
    )
    parser.add_argument(
        "--operation",
        default="POST /scan",
        help="Jaeger operation name to query (default: %(default)s)",
    )
    parser.add_argument(
        "--requests",
        type=int,
        default=80,
        help="Number of scan requests to submit (default: %(default)s)",
    )
    parser.add_argument(
        "--expected-ratio",
        type=float,
        default=0.10,
        help="Expected sample ratio to validate (default: %(default)s)",
    )
    parser.add_argument(
        "--query-limit",
        type=int,
        default=2000,
        help="Jaeger query limit for traces (default: %(default)s)",
    )
    parser.add_argument(
        "--poll-attempts",
        type=int,
        default=15,
        help="Polling attempts after traffic submission (default: %(default)s)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds between Jaeger polling attempts (default: %(default)s)",
    )
    parser.add_argument(
        "--http-timeout",
        type=float,
        default=20.0,
        help="HTTP timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--min-abs-tolerance",
        type=float,
        default=0.05,
        help="Minimum absolute tolerance around expected ratio (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if args.requests <= 0:
        print("requests must be > 0", file=sys.stderr)
        return 2
    if not (0.0 <= args.expected_ratio <= 1.0):
        print("expected-ratio must be between 0 and 1", file=sys.stderr)
        return 2

    run_label = f"sampler-{uuid.uuid4().hex[:12]}"
    start_us = int(time.time() * 1_000_000)
    submitted = 0

    print(
        "[sampling] starting test "
        f"run={run_label} requests={args.requests} expected_ratio={args.expected_ratio:.4f}"
    )

    try:
        for idx in range(args.requests):
            _submit_scan(
                api_url=args.api_url,
                api_key=args.api_key,
                run_label=run_label,
                index=idx,
                timeout=args.http_timeout,
            )
            submitted += 1
    except urllib.error.URLError as exc:
        print(f"[sampling] request failed after {submitted} submissions: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(
            f"[sampling] unexpected failure after {submitted} submissions: {exc}",
            file=sys.stderr,
        )
        return 2

    print(f"[sampling] submitted={submitted}, polling Jaeger for sampled traces...")

    query_limit = max(args.query_limit, args.requests * 4)
    best_count = 0
    stable_rounds = 0

    for attempt in range(1, args.poll_attempts + 1):
        time.sleep(args.poll_interval)
        end_us = int(time.time() * 1_000_000)
        try:
            trace_ids = _query_jaeger_trace_ids(
                jaeger_url=args.jaeger_url,
                service=args.service,
                operation=args.operation,
                start_us=start_us,
                end_us=end_us,
                limit=query_limit,
                timeout=args.http_timeout,
            )
        except urllib.error.URLError as exc:
            print(f"[sampling] Jaeger query error (attempt {attempt}): {exc}", file=sys.stderr)
            continue
        except Exception as exc:
            print(f"[sampling] Jaeger query parse error (attempt {attempt}): {exc}", file=sys.stderr)
            continue

        count = len(trace_ids)
        print(
            f"[sampling] attempt={attempt}/{args.poll_attempts} "
            f"sampled_traces={count} submitted={submitted}"
        )

        if count > best_count:
            best_count = count
            stable_rounds = 0
        else:
            stable_rounds += 1

        if stable_rounds >= 3:
            break

    observed_ratio = best_count / float(submitted)
    tolerance = _tolerance(args.expected_ratio, submitted, args.min_abs_tolerance)
    delta = abs(observed_ratio - args.expected_ratio)

    print(
        "[sampling] summary "
        f"sampled={best_count} submitted={submitted} "
        f"observed_ratio={observed_ratio:.4f} "
        f"expected_ratio={args.expected_ratio:.4f} "
        f"tolerance=+/-{tolerance:.4f}"
    )

    if args.expected_ratio > 0.0 and best_count == 0:
        print(
            "[sampling] FAIL: zero traces were discovered in Jaeger. "
            "This indicates exporter/collector wiring is not functioning.",
            file=sys.stderr,
        )
        return 1

    if delta > tolerance:
        print(
            "[sampling] FAIL: observed ratio is outside tolerance window.",
            file=sys.stderr,
        )
        return 1

    print("[sampling] PASS: observed ratio is within tolerance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
