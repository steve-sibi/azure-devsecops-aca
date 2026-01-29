#!/usr/bin/env python3
"""
aca_api.py

Interact with the FastAPI scanner service.

Dependencies:
    Python 3.11+ (standard library only)

Configuration precedence (highest first):
  - API key:
      1) --api-key
      2) environment: ACA_API_KEY, else API_KEY
      3) repo .env: ACA_API_KEY, else API_KEY
  - Base URL:
      1) --base-url
      2) environment: ACA_BASE_URL, else API_URL
      3) default: http://localhost:8000
"""

import argparse
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn, Optional, Tuple, Union

# --- Configuration & Helpers ---


def load_dotenv(path: Path) -> dict:
    """Simple .env parser to match bash script behavior."""
    env_vars = {}
    if not path.exists():
        return env_vars

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Remove 'export ' prefix
            if line.startswith("export "):
                line = line[7:].strip()

            if "=" not in line:
                continue

            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip()

            # Remove quotes if present around the whole value
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]

            env_vars[key] = val
    return env_vars


def get_repo_root() -> Path:
    """
    Get the repository root directory.
    Assumes this script is located in the scripts/ directory.
    """
    return Path(__file__).resolve().parent.parent


class Config:
    """
    Configuration handling class.

    Loads configuration from CLI arguments, environment variables, and .env files
    with specific precedence rules.
    """

    def __init__(self, args):
        self.repo_root = get_repo_root()
        self.dotenv = load_dotenv(self.repo_root / ".env")

        # Base URL
        self.base_url = (
            args.base_url
            or os.environ.get("ACA_BASE_URL")
            or os.environ.get("API_URL")
            or "http://localhost:8000"
        ).rstrip("/")

        # API Key
        self.api_key = (
            args.api_key
            or os.environ.get("ACA_API_KEY")
            or os.environ.get("API_KEY")
            or self.dotenv.get("ACA_API_KEY")
            or self.dotenv.get("API_KEY")
            or ""
        )

        # API Key Header
        self.api_key_header = (
            args.api_key_header
            or os.environ.get("ACA_API_KEY_HEADER")
            or os.environ.get("API_KEY_HEADER")
            or "X-API-Key"
        )

        # History Path
        history_path_str = args.history or os.environ.get("ACA_API_HISTORY")
        if history_path_str:
            self.history_path = Path(history_path_str)
        else:
            self.history_path = self.repo_root / ".aca_api_history"

        self.raw = args.raw
        self.verbose = args.verbose

    def require_api_key(self):
        """
        Ensure an API key is present. Exits if missing.
        """
        if not self.api_key:
            die(
                "Missing API key. Set --api-key, ACA_API_KEY, API_KEY, or add API_KEY to .env."
            )


def die(msg: str) -> NoReturn:
    """Print error message to stderr and exit with status 1."""
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg):
    """Print message to stderr."""
    print(msg, file=sys.stderr)


# --- HTTP Client ---


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


def emit_json(output, config: Config):
    """
    Print output as JSON, optionally pretty-printed based on config.
    """
    if config.raw:
        if isinstance(output, str):
            print(output)
        else:
            print(json.dumps(output))
    else:
        if isinstance(output, str):
            try:
                # Try to pretty print if it's a JSON string
                parsed = json.loads(output)
                print(json.dumps(parsed, indent=2))
            except json.JSONDecodeError:
                print(output)
        else:
            print(json.dumps(output, indent=2))


# --- History ---


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


# --- Commands ---


def cmd_health(config: Config, args):
    """Handler for 'health' command."""
    status, _, body = make_request(config, "GET", "/healthz")
    emit_json(body, config)


def cmd_scan_url(config: Config, args):
    """Handler for 'scan-url' command."""
    config.require_api_key()

    payload = {"url": args.url, "type": "url"}
    if args.source:
        payload["source"] = args.source
    if args.force:
        payload["force"] = True

    meta = {}
    if args.meta_json:
        try:
            meta.update(json.loads(args.meta_json))
        except json.JSONDecodeError as e:
            die(f"invalid --meta-json: {e}")

    if args.meta:
        for item in args.meta:
            if "=" not in item:
                die("--meta must be key=value")
            k, v = item.split("=", 1)
            if not k.strip():
                die("--meta key cannot be empty")
            meta[k.strip()] = v.strip()

    if meta:
        payload["metadata"] = meta

    status, _, body = make_request(config, "POST", "/scan", data=payload)

    try:
        resp_json = json.loads(body)
    except json.JSONDecodeError:
        log("Submit response (no job_id found):")
        log(body)
        die("Submit succeeded but response did not include job_id")

    job_id = resp_json.get("job_id")
    if not job_id:
        log("Submit response (no job_id found):")
        emit_json(resp_json, config)
        die("Submit succeeded but response did not include job_id")

    append_history(config, job_id, args.url)

    if args.wait:
        if config.verbose:
            log(f"JOB_ID={job_id}")
        # Need to parse timeout values from args which are handled by wait logic
    else:
        emit_json(resp_json, config)
        return

    # Wait logic
    wait_args = argparse.Namespace(
        job_id=job_id, interval=2, timeout=120, view=args.view
    )
    cmd_wait(config, wait_args)


def cmd_status(config: Config, args):
    """Handler for 'status' command."""
    config.require_api_key()
    path = f"/scan/{args.job_id}?view={args.view}"
    status, _, body = make_request(config, "GET", path)
    emit_json(body, config)


def cmd_wait(config: Config, args):
    """Handler for 'wait' command."""
    config.require_api_key()
    start_time = time.time()
    last_status = None

    while True:
        path = f"/scan/{args.job_id}?view={args.view}"
        status_code, _, body = make_request(config, "GET", path)

        try:
            data = json.loads(body)
            status = data.get("status")
        except json.JSONDecodeError:
            status = None
            data = {}

        if config.verbose and status and status != last_status:
            log(f"status={status}")
            last_status = status

        if status == "completed":
            emit_json(data, config)
            return
        if status == "error":
            emit_json(data, config)
            sys.exit(1)

        if args.timeout > 0:
            if time.time() - start_time >= args.timeout:
                die(
                    f"Timed out after {args.timeout}s waiting for job {args.job_id} (last status: {status or 'unknown'})"
                )

        time.sleep(args.interval)


def cmd_jobs(config: Config, args):
    """Handler for 'jobs' command."""
    config.require_api_key()

    params = [f"limit={args.limit}"]
    if args.status:
        params.append(f"status={args.status}")

    path = f"/jobs?{'&'.join(params)}"
    status, _, body = make_request(config, "GET", path)

    if args.format == "json":
        emit_json(body, config)
        return

    # Lines format
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        die("/jobs did not return JSON.")

    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        die("unexpected /jobs response shape (missing 'jobs' list)")

    print(f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  url")
    for j in jobs:
        if not isinstance(j, dict):
            continue
        jid = str(j.get("job_id") or "")
        jst = str(j.get("status") or "")
        sub = str(j.get("submitted_at") or "")
        scan = str(j.get("scanned_at") or "")
        url = str(j.get("url") or "")
        if len(url) > 80:
            url = url[:77] + "..."
        print(f"{jid:36}  {jst:12}  {sub[:20]:20}  {scan[:20]:20}  {url}")


def cmd_history(config: Config, args):
    """Handler for 'history' command."""
    if not config.history_path.exists():
        log(f"No history yet at: {config.history_path}")
        return
    read_history(config, args.limit)


def cmd_clear_history(config: Config, args):
    """Handler for 'clear-history' command."""
    if config.history_path.exists():
        config.history_path.unlink()
    log(f"Cleared history: {config.history_path}")


def cmd_clear_server_history(config: Config, args):
    """Handler for 'clear-server-history' command."""
    config.require_api_key()
    status, _, body = make_request(config, "DELETE", "/jobs")
    emit_json(body, config)


def cmd_screenshot(config: Config, args):
    """Handler for 'screenshot' command."""
    config.require_api_key()

    status_code, headers, body_bytes = make_request(
        config, "GET", f"/scan/{args.job_id}/screenshot", stream=True
    )

    if not isinstance(body_bytes, bytes):
        die("Expected bytes response for screenshot")

    out_path = args.out
    if not out_path:
        ctype = headers.get("Content-Type", "")
        ext = "bin"
        if "image/jpeg" in ctype:
            ext = "jpg"
        elif "image/png" in ctype:
            ext = "png"
        out_path = f"./{args.job_id}.{ext}"

    try:
        with open(out_path, "wb") as f:
            f.write(body_bytes)
        print(out_path)
    except Exception as e:
        die(f"Failed to write screenshot to {out_path}: {e}")


def cmd_scan_file(config: Config, args):
    """Handler for 'scan-file' command (multipart upload)."""
    config.require_api_key()
    file_path = Path(args.path)
    if not file_path.exists():
        die(f"File not found: {file_path}")

    # Multipart upload manually strictly with standard library is painful.
    # We will construct the body manually.
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    dash_boundary = f"--{boundary}".encode("utf-8")

    lines = []

    # File part
    filename = file_path.name
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    lines.append(dash_boundary)
    lines.append(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"'.encode(
            "utf-8"
        )
    )
    lines.append(f"Content-Type: {mime_type}".encode("utf-8"))
    lines.append(crlf)

    with open(file_path, "rb") as f:
        file_content = f.read()

    body = b"".join([*lines, file_content, crlf, dash_boundary + b"--" + crlf])

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }

    status, _, resp_body = make_request(
        config, "POST", "/file/scan", data=body, headers=headers
    )
    emit_json(resp_body, config)


def cmd_scan_payload(config: Config, args):
    """Handler for 'scan-payload' command (multipart upload of text)."""
    config.require_api_key()

    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    dash_boundary = f"--{boundary}".encode("utf-8")

    parts = []

    # payload_base64
    if args.base64:
        parts.append(("payload_base64", "true"))

    # payload
    parts.append(("payload", args.text))

    body_parts = []
    for name, value in parts:
        body_parts.append(dash_boundary)
        body_parts.append(
            f'Content-Disposition: form-data; name="{name}"'.encode("utf-8")
        )
        body_parts.append(crlf)  # Empty header line
        body_parts.append(value.encode("utf-8"))
        body_parts.append(crlf)

    body_parts.append(dash_boundary + b"--" + crlf)

    full_body = b"".join(body_parts)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(full_body)),
    }

    status, _, resp_body = make_request(
        config, "POST", "/file/scan", data=full_body, headers=headers
    )
    emit_json(resp_body, config)


# --- Main ---


def main():
    parser = argparse.ArgumentParser(
        description="Terminal helper for the FastAPI scanner."
    )

    # Global options
    parser.add_argument("-b", "--base-url", help="Base API URL")
    parser.add_argument("-k", "--api-key", help="API key")
    parser.add_argument("--api-key-header", help="Header name (default: X-API-Key)")
    parser.add_argument("--history", help="Job history file")
    parser.add_argument(
        "--raw", action="store_true", help="Print raw response (no pretty-print)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Extra progress output"
    )

    subparsers = parser.add_subparsers(dest="command", title="Commands")
    subparsers.required = True

    # Health
    subparsers.add_parser("health", help="Check health")

    # Scan URL
    p_scan = subparsers.add_parser("scan-url", help="Scan a URL")
    p_scan.add_argument("url", help="URL to scan")
    p_scan.add_argument("--source", help="Source identifier")
    p_scan.add_argument(
        "--meta", action="append", help="Metadata key=value", default=[]
    )
    p_scan.add_argument("--meta-json", help="Metadata JSON object")
    p_scan.add_argument("--force", action="store_true", help="Force scan")
    p_scan.add_argument("--wait", action="store_true", help="Wait for completion")
    p_scan.add_argument(
        "--view", default="summary", choices=["summary", "full"], help="View type"
    )

    # Status
    p_status = subparsers.add_parser("status", help="Get job status")
    p_status.add_argument("job_id", help="Job ID")
    p_status.add_argument("--view", default="summary", choices=["summary", "full"])

    # Wait
    p_wait = subparsers.add_parser("wait", help="Wait for job")
    p_wait.add_argument("job_id", help="Job ID")
    p_wait.add_argument("--interval", type=int, default=2, help="Poll interval (s)")
    p_wait.add_argument("--timeout", type=int, default=120, help="Timeout (s)")
    p_wait.add_argument("--view", default="summary", choices=["summary", "full"])

    # Jobs
    p_jobs = subparsers.add_parser("jobs", help="List jobs")
    p_jobs.add_argument("--limit", type=int, default=20, help="Max jobs to return")
    p_jobs.add_argument("--status", help="Comma-separated statuses")
    p_jobs.add_argument("--format", default="lines", choices=["lines", "json"])

    # History
    p_hist = subparsers.add_parser("history", help="Local client history")
    p_hist.add_argument("--limit", type=int, default=0, help="Max lines")

    # Clear History
    subparsers.add_parser("clear-history", help="Clear local history")
    subparsers.add_parser(
        "clear-server-history", help="Clear server history (for API key)"
    )

    # Screenshot
    p_screen = subparsers.add_parser("screenshot", help="Download screenshot")
    p_screen.add_argument("job_id", help="Job ID")
    p_screen.add_argument("-o", "--out", help="Output path")

    # Scan File
    p_file = subparsers.add_parser("scan-file", help="Scan a file (multipart)")
    p_file.add_argument("path", help="File path")

    # Scan Payload
    p_payload = subparsers.add_parser("scan-payload", help="Scan text payload")
    p_payload.add_argument("text", help="Text payload")
    p_payload.add_argument(
        "--base64", action="store_true", help="Payload is base64 encoded"
    )

    args = parser.parse_args()

    config = Config(args)

    # Dispatch
    cmd_map = {
        "health": cmd_health,
        "scan-url": cmd_scan_url,
        "status": cmd_status,
        "wait": cmd_wait,
        "jobs": cmd_jobs,
        "history": cmd_history,
        "clear-history": cmd_clear_history,
        "clear-server-history": cmd_clear_server_history,
        "screenshot": cmd_screenshot,
        "scan-file": cmd_scan_file,
        "scan-payload": cmd_scan_payload,
    }

    handler = cmd_map.get(args.command)
    if handler:
        handler(config, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
