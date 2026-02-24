from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
import uuid
from typing import Any, Tuple, Union

from .config import Config
from .core import die, log

def make_request(
    config: Config, method: str, path: str, data=None, headers=None, stream=False
) -> Tuple[int, Any, Union[str, bytes]]:
    """
    Execute an HTTP request using the standard library.

    Args:
        config: Configuration object containing base_url and api_key.
        method: HTTP method (GET, POST, DELETE, etc.).
        path: API endpoint path.
        data: Request body (dict, str, or bytes).
        headers: Optional dictionary of headers.
        stream: If True, returns raw bytes for body; otherwise decodes UTF-8.

    Returns:
        Tuple containing (status_code, headers, body).
    """
    if headers is None:
        headers = {}

    url = f"{config.base_url}{path}"

    # Default headers
    if "accept" not in headers:
        headers["accept"] = "application/json"

    # Auth header (if key/header is set, though some endpoints usually don't need it, we can just send it)
    if config.api_key:
        headers[config.api_key_header] = config.api_key

    # Body handling
    encoded_data = None
    if data is not None:
        if isinstance(data, dict):
            encoded_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(data, str):
            encoded_data = data.encode("utf-8")
        elif isinstance(data, bytes):
            encoded_data = data
        else:
            raise ValueError(f"Unknown data type: {type(data)}")

    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
            if stream:
                # Return headers and content separately for binary downloads
                return status, response.headers, response.read()

            body = response.read().decode("utf-8")
            return status, response.headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        if config.verbose:
            log(f"HTTP {e.code}: {body}")

        # Return the error body as result, but we might want to fail?
        # The bash script printed invalid statuses and exited 1 usually,
        # but sometimes printed the error body.
        # We'll mimic: Print body to stderr if present, then die/raise.
        if body:
            print(body, file=sys.stderr)
        die(f"HTTP {e.code}")
    except urllib.error.URLError as e:
        die(f"Connection failed to {url}: {e.reason}")


def open_ndjson_stream(
    config: Config, path: str, *, headers=None, timeout_seconds: int = 30
):
    if headers is None:
        headers = {}

    url = f"{config.base_url}{path}"
    if "accept" not in headers:
        headers["accept"] = "application/x-ndjson, application/json"
    if config.api_key:
        headers[config.api_key_header] = config.api_key

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        return urllib.request.urlopen(req, timeout=max(1, int(timeout_seconds or 1)))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else ""
        if body:
            print(body, file=sys.stderr)
        raise


def _build_multipart_body(
    parts: list[tuple[str, str | bytes, str | None, str | None]],
    *,
    boundary: str | None = None,
) -> tuple[bytes, str]:
    boundary_value = str(boundary or uuid.uuid4().hex)
    crlf = b"\r\n"
    dash_boundary = f"--{boundary_value}".encode("utf-8")
    body_parts: list[bytes] = []

    for name, content, filename, mime_type in parts:
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content

        body_parts.append(dash_boundary + crlf)

        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            disposition += f'; filename="{filename}"'
        body_parts.append(disposition.encode("utf-8") + crlf)

        if mime_type:
            body_parts.append(f"Content-Type: {mime_type}".encode("utf-8") + crlf)

        body_parts.append(crlf)
        body_parts.append(content_bytes)
        body_parts.append(crlf)

    body_parts.append(dash_boundary + b"--" + crlf)
    return b"".join(body_parts), f"multipart/form-data; boundary={boundary_value}"
