from __future__ import annotations

import argparse
import itertools
import json
import mimetypes
import shutil
import socket
import sys
import time
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from . import ui_live, ui_render
from .config import Config, _mask_secret, emit_shell_exports
from .core import SCAN_STATUS_CHOICES, TERMINAL_STATUSES, die, log
from .history import append_history, parse_history_entries, read_history
from .http import _build_multipart_body, make_request, open_ndjson_stream
from .output import emit_output
from .prompts import confirm_or_die, ensure_required_command_args, maybe_prompt_for_missing_args

class Spinner:
    def __init__(self, enabled: bool):
        self.enabled = bool(enabled)
        self._frames = itertools.cycle(["|", "/", "-", "\\"])
        self._last_len = 0
        self._active = False

    def tick(self, message: str) -> None:
        if not self.enabled:
            return
        frame = next(self._frames)
        text = f"\r{frame} {message}"
        pad = ""
        if self._last_len > len(text):
            pad = " " * (self._last_len - len(text))
        sys.stderr.write(text + pad)
        sys.stderr.flush()
        self._last_len = len(text)
        self._active = True

    def clear(self) -> None:
        if not self.enabled or not self._active:
            return
        sys.stderr.write("\r" + (" " * self._last_len) + "\r")
        sys.stderr.flush()
        self._active = False
        self._last_len = 0

    def done(self, message: str | None = None) -> None:
        if not self.enabled:
            return
        if message:
            self.clear()
            sys.stderr.write(f"{message}\n")
            sys.stderr.flush()
        else:
            self.clear()

def _follow_mode_from_submit_args(args) -> str:
    follow_mode = getattr(args, "follow", None)
    wait_flag = bool(getattr(args, "wait", False))
    if wait_flag and follow_mode not in (None, "", "poll"):
        die("--wait is only compatible with --follow poll (or omit --follow)")
    if follow_mode is None:
        return "poll" if wait_flag else "none"
    return str(follow_mode or "none").strip().lower() or "none"


def _follow_submitted_job(config: Config, args, job_id: str) -> None:
    follow_mode = _follow_mode_from_submit_args(args)
    if follow_mode == "none":
        return

    if config.verbose:
        log(f"JOB_ID={job_id}")

    if follow_mode == "watch":
        watch_args = argparse.Namespace(
            job_id=job_id,
            cursor="$",
            read_timeout=30,
            fallback_poll=True,
            interval=int(getattr(args, "interval", 2)),
            timeout=int(getattr(args, "timeout", 120)),
            view=str(getattr(args, "view", "summary") or "summary"),
        )
        cmd_watch(config, watch_args)
        return

    wait_args = argparse.Namespace(
        job_id=job_id,
        interval=int(getattr(args, "interval", 2)),
        timeout=int(getattr(args, "timeout", 120)),
        view=str(getattr(args, "view", "summary") or "summary"),
    )
    cmd_wait(config, wait_args)


def _default_history_target_for_submit(kind: str, args) -> str:
    kind_norm = str(kind or "url").strip().lower()
    if kind_norm == "file":
        path = Path(str(getattr(args, "path", "") or ""))
        name = path.name or str(path or "file")
        return f"file://{name}"
    if kind_norm == "payload":
        text = str(getattr(args, "text", "") or "")
        base64_flag = bool(getattr(args, "base64", False))
        prefix = "payload+b64" if base64_flag else "payload"
        return f"{prefix}://{len(text)}-chars"
    return str(getattr(args, "url", "") or "")


def _handle_submit_response(
    config: Config,
    args,
    body: str,
    *,
    history_target: str | None = None,
) -> None:
    try:
        resp_json = json.loads(body)
    except json.JSONDecodeError:
        log("Submit response (no job_id found):")
        log(body)
        die("Submit succeeded but response did not include job_id")

    if not isinstance(resp_json, dict):
        emit_output(resp_json, config)
        return

    job_id = str(resp_json.get("job_id") or "").strip()
    if not job_id:
        log("Submit response (no job_id found):")
        emit_output(resp_json, config)
        die("Submit succeeded but response did not include job_id")

    target = history_target
    if target is None:
        target = _default_history_target_for_submit(str(getattr(args, "command", "url")), args)
    if target:
        append_history(config, job_id, target)

    follow_mode = _follow_mode_from_submit_args(args)
    if follow_mode == "none":
        emit_output(resp_json, config, kind="scan_result")
        return
    _follow_submitted_job(config, args, job_id)


# --- Commands ---


def cmd_health(config: Config, args):
    """Handler for 'health' command."""
    status, _, body = make_request(config, "GET", "/healthz")
    emit_output(body, config)


def cmd_scan_url(config: Config, args):
    """Handler for 'scan-url' command."""
    config.require_api_key()
    if not args.url:
        die("Missing URL. Provide a URL argument or use --prompt.")

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

    _, _, body = make_request(config, "POST", "/scan", data=payload)
    _handle_submit_response(config, args, body, history_target=str(args.url))


def cmd_status(config: Config, args):
    """Handler for 'status' command."""
    config.require_api_key()
    path = f"/scan/{args.job_id}?view={args.view}"
    status, _, body = make_request(config, "GET", path)
    emit_output(body, config, kind="scan_result")


def cmd_wait(config: Config, args):
    """Handler for 'wait' command."""
    config.require_api_key()
    start_time = time.time()
    last_status = None
    live = ui_live.RichLiveReporter.from_config(config)
    live.start(f"Waiting for {args.job_id}")
    spinner = Spinner(config.spinner and not live.active)

    while True:
        path = f"/scan/{args.job_id}?view={args.view}"
        _, _, body = make_request(config, "GET", path)

        try:
            data = json.loads(body)
            status = data.get("status")
        except json.JSONDecodeError:
            status = None
            data = {}

        status_changed = bool(status and status != last_status)

        if config.verbose and status_changed:
            spinner.clear()
            log(f"status={status}")

        if status_changed:
            live.transition(
                str(status),
                error=str(data.get("error") or "") or None,
                duration_ms=data.get("duration_ms"),
                size_bytes=data.get("size_bytes"),
            )
            last_status = status
        msg = f"Waiting for {args.job_id} ({status or 'unknown'})"
        spinner.tick(msg)
        live.update(msg)

        if status in TERMINAL_STATUSES:
            spinner.done()
            live.done()
            emit_output(data, config, kind="scan_result")
            if status != "completed":
                sys.exit(1)
            return

        if args.timeout > 0:
            if time.time() - start_time >= args.timeout:
                spinner.done()
                live.done()
                die(
                    f"Timed out after {args.timeout}s waiting for job {args.job_id} (last status: {status or 'unknown'})"
                )

        time.sleep(args.interval)


def cmd_watch(config: Config, args):
    """Handler for 'watch' command (NDJSON live stream with polling fallback)."""
    config.require_api_key()
    start_time = time.time()
    live = ui_live.RichLiveReporter.from_config(config)
    live.start(f"Connecting live stream for {args.job_id}")
    spinner = Spinner(config.spinner and not live.active)

    # Resolve run_id from the request-scoped job record.
    status_path = f"/scan/{args.job_id}?view=summary"
    _, _, body = make_request(config, "GET", status_path)
    try:
        status_doc = json.loads(body)
    except json.JSONDecodeError:
        die("status response is not JSON")

    status_value = str(status_doc.get("status") or "").strip().lower()
    run_id = str(status_doc.get("run_id") or "").strip() or str(args.job_id)
    if status_value:
        live.transition(
            status_value,
            error=str(status_doc.get("error") or "") or None,
            duration_ms=status_doc.get("duration_ms"),
            size_bytes=status_doc.get("size_bytes"),
        )

    # If already terminal, return immediately with requested view.
    if status_value in TERMINAL_STATUSES:
        _, _, final_body = make_request(
            config, "GET", f"/scan/{args.job_id}?view={args.view}"
        )
        spinner.done()
        live.done()
        emit_output(final_body, config, kind="scan_result")
        if status_value != "completed":
            sys.exit(1)
        return

    cursor = str(args.cursor or "$").strip() or "$"
    params = [("cursor", cursor), ("run_id", run_id)]
    stream_path = "/events/stream?" + urllib.parse.urlencode(params)

    if config.verbose:
        log(f"watching run_id={run_id} via {stream_path}")

    try:
        spinner.tick(f"Connecting live stream for {args.job_id}")
        live.update(f"Connecting live stream for {args.job_id}")
        with open_ndjson_stream(
            config,
            stream_path,
            timeout_seconds=max(1, int(args.read_timeout or 30)),
        ) as stream:
            while True:
                if args.timeout > 0 and (time.time() - start_time) >= args.timeout:
                    spinner.done()
                    raise TimeoutError(
                        f"Timed out after {args.timeout}s waiting for job {args.job_id}"
                    )
                try:
                    raw = stream.readline()
                except socket.timeout:
                    msg = f"Watching {args.job_id} ({status_value or 'waiting'})"
                    spinner.tick(msg)
                    live.update(msg)
                    continue

                if not raw:
                    spinner.done()
                    live.done()
                    raise ConnectionError("live stream closed")

                line = raw.decode("utf-8", "replace").strip()
                if not line:
                    continue

                try:
                    packet = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(packet, dict):
                    continue

                packet_id = str(packet.get("id") or "").strip()
                if packet_id:
                    cursor = packet_id
                event = packet.get("event")
                if not isinstance(event, dict):
                    continue

                event_status = str(event.get("status") or "").strip().lower()
                event_stage = str(event.get("stage") or "").strip().lower() or None
                event_error = str(event.get("error") or "").strip() or None
                if config.verbose and event_status:
                    spinner.clear()
                    log(f"status={event_status}")
                if event_status:
                    status_value = event_status
                    live.transition(
                        event_status,
                        stage=event_stage,
                        error=event_error,
                        duration_ms=event.get("duration_ms"),
                        size_bytes=event.get("size_bytes"),
                    )
                    msg = f"Watching {args.job_id} ({event_status})"
                    spinner.tick(msg)
                    live.update(msg)

                if event_status in TERMINAL_STATUSES:
                    _, _, final_body = make_request(
                        config, "GET", f"/scan/{args.job_id}?view={args.view}"
                    )
                    spinner.done()
                    live.done()
                    emit_output(final_body, config, kind="scan_result")
                    if event_status != "completed":
                        sys.exit(1)
                    return
    except urllib.error.HTTPError as e:
        spinner.done()
        live.done()
        if not args.fallback_poll:
            die(f"Live stream failed with HTTP {e.code}")
    except Exception as e:
        spinner.done()
        live.done()
        if not args.fallback_poll:
            die(str(e))

    if not args.fallback_poll:
        return

    if config.verbose:
        log("falling back to polling")
    live.fallback_notice()
    remaining_timeout = int(args.timeout)
    if remaining_timeout > 0:
        elapsed = int(time.time() - start_time)
        remaining_timeout = max(1, remaining_timeout - elapsed)
    wait_args = argparse.Namespace(
        job_id=args.job_id,
        interval=args.interval,
        timeout=remaining_timeout,
        view=args.view,
    )
    cmd_wait(config, wait_args)


def cmd_jobs(config: Config, args):
    """Handler for 'jobs' command."""
    config.require_api_key()
    if config.json_output and getattr(args, "format", "table") in ("table", "lines"):
        args.format = "json"

    if args.status:
        statuses = [s.strip() for s in str(args.status).split(",") if s.strip()]
        invalid = sorted(set(statuses) - set(SCAN_STATUS_CHOICES))
        if invalid:
            die(
                f"--status contains invalid value(s): {', '.join(invalid)}; choices: {', '.join(SCAN_STATUS_CHOICES)}"
            )
        args.status = ",".join(statuses)

    def _fetch_jobs(scan_type: str) -> list[dict]:
        params = [f"limit={args.limit}"]
        if args.status:
            params.append(f"status={args.status}")
        if scan_type and scan_type != "all":
            params.append(f"type={scan_type}")
        path = f"/jobs?{'&'.join(params)}"
        _, _, body = make_request(config, "GET", path)

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            die("/jobs did not return JSON.")

        jobs = data.get("jobs")
        if not isinstance(jobs, list):
            die("unexpected /jobs response shape (missing 'jobs' list)")
        return [j for j in jobs if isinstance(j, dict)]

    def _print_url_jobs(jobs: list[dict]) -> None:
        print(
            f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  url"
        )
        for j in jobs:
            jid = str(j.get("job_id") or "")
            jst = str(j.get("status") or "")
            sub = str(j.get("submitted_at") or "")
            scan = str(j.get("scanned_at") or "")
            url = str(j.get("url") or "")
            if len(url) > 80:
                url = url[:77] + "..."
            print(f"{jid:36}  {jst:12}  {sub[:20]:20}  {scan[:20]:20}  {url}")

    def _print_file_jobs(jobs: list[dict]) -> None:
        print(
            f"{'job_id':36}  {'status':12}  {'submitted_at':20}  {'scanned_at':20}  {'verdict':10}  {'sha256':12}  filename"
        )
        for j in jobs:
            jid = str(j.get("job_id") or "")
            jst = str(j.get("status") or "")
            sub = str(j.get("submitted_at") or "")
            scan = str(j.get("scanned_at") or "")
            verdict = str(j.get("verdict") or "")
            sha = str(j.get("sha256") or "")
            sha_short = sha[:12] if sha else ""
            filename = str(j.get("filename") or "")
            if len(filename) > 60:
                filename = filename[:57] + "..."
            print(
                f"{jid:36}  {jst:12}  {sub[:20]:20}  {scan[:20]:20}  {verdict[:10]:10}  {sha_short:12}  {filename}"
            )

    scan_type = getattr(args, "scan_type", None)
    if scan_type is not None:
        scan_type = str(scan_type).strip().lower()
        if scan_type not in ("url", "file"):
            die("--type must be one of: url, file")

    out_format = str(getattr(args, "format", "table") or "table").strip().lower()
    if out_format == "json":
        if scan_type is None:
            out = {
                "url_jobs": _fetch_jobs("url"),
                "file_jobs": _fetch_jobs("file"),
            }
            print(json.dumps(out, indent=2))
            return
        out = {"jobs": _fetch_jobs(scan_type)}
        print(json.dumps(out, indent=2))
        return

    # Table/lines format
    if scan_type is None:
        url_jobs = _fetch_jobs("url")
        file_jobs = _fetch_jobs("file")

        if out_format in ("table", "lines") and ui_render.render_jobs(
            [("URL scans", "url", url_jobs), ("File scans", "file", file_jobs)],
            config,
        ):
            return

        print("URL scans:")
        _print_url_jobs(url_jobs)
        print("")
        print("File scans:")
        _print_file_jobs(file_jobs)
        return

    jobs = _fetch_jobs(scan_type)
    if out_format in ("table", "lines") and ui_render.render_jobs(
        [(f"{scan_type.upper()} scans", scan_type, jobs)],
        config,
    ):
        return
    if scan_type == "file":
        _print_file_jobs(jobs)
    else:
        _print_url_jobs(jobs)


def cmd_history(config: Config, args):
    """Handler for 'history' command."""
    if not config.history_path.exists():
        log(f"No history yet at: {config.history_path}")
        return
    out_format = str(getattr(args, "format", "table") or "table").strip().lower()
    if config.json_output and out_format == "table":
        out_format = "json"
    limit = int(getattr(args, "limit", 0) or 0)

    if out_format == "tsv":
        read_history(config, limit)
        return

    entries = parse_history_entries(config, limit=limit)
    if out_format == "json":
        print(json.dumps(entries, indent=2))
        return

    if ui_render.render_history(entries, config):
        return

    print(f"{'timestamp':24}  {'job_id':36}  {'target':50}  base_url")
    for item in entries:
        ts = str(item.get("timestamp") or "")[:24]
        job_id = str(item.get("job_id") or "")[:36]
        target = str(item.get("url") or "")
        if len(target) > 50:
            target = target[:47] + "..."
        base_url = str(item.get("base_url") or "")
        print(f"{ts:24}  {job_id:36}  {target:50}  {base_url}")


def cmd_clear_history(config: Config, args):
    """Handler for 'clear-history' command."""
    confirm_or_die(config, args, f"Clear local history file at {config.history_path}?")
    if config.history_path.exists():
        config.history_path.unlink()
    log(f"Cleared history: {config.history_path}")


def cmd_clear_server_history(config: Config, args):
    """Handler for 'clear-server-history' command."""
    config.require_api_key()
    scan_type = getattr(args, "scan_type", None)
    if scan_type is not None:
        scan_type = str(scan_type).strip().lower()
        if scan_type not in ("url", "file"):
            die("--type must be one of: url, file")
    confirm_or_die(
        config,
        args,
        (
            f"Delete server job history for type={scan_type}?"
            if scan_type is not None
            else "Delete all server job history for this API key?"
        ),
    )

    path = "/jobs"
    if scan_type is not None:
        path = f"{path}?type={scan_type}"
    status, _, body = make_request(config, "DELETE", path)
    emit_output(body, config)


def cmd_screenshot(config: Config, args):
    """Handler for 'screenshot' command."""
    config.require_api_key()

    status_code, headers, body_bytes = make_request(
        config, "GET", f"/scan/{args.job_id}/screenshot", stream=True
    )

    if not isinstance(body_bytes, bytes):
        die("Expected bytes response for screenshot")

    ctype = headers.get("Content-Type", "")
    ext = "bin"
    if "image/jpeg" in ctype:
        ext = "jpg"
    elif "image/png" in ctype:
        ext = "png"

    default_name = f"{args.job_id}.{ext}"

    out_path = args.out
    if out_path:
        out_path_obj = Path(out_path)
        # Allow `--out` to be a directory (existing directory or a path ending in a separator).
        if out_path_obj.exists() and out_path_obj.is_dir():
            out_path_obj = out_path_obj / default_name
        elif str(out_path).endswith(("/", "\\")):
            out_path_obj = out_path_obj / default_name
        out_path = str(out_path_obj)
    elif args.out_dir:
        out_path = str(Path(args.out_dir) / default_name)
    else:
        out_path = f"./{default_name}"

    try:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
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

    # File part
    filename = file_path.name
    mime_type, _ = mimetypes.guess_type(file_path)
    if not mime_type:
        mime_type = "application/octet-stream"

    with open(file_path, "rb") as f:
        file_content = f.read()

    body, content_type = _build_multipart_body([("file", file_content, filename, mime_type)])

    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
    }

    _, _, resp_body = make_request(
        config, "POST", "/file/scan", data=body, headers=headers
    )
    _handle_submit_response(config, args, resp_body, history_target=f"file://{filename}")


def cmd_scan_payload(config: Config, args):
    """Handler for 'scan-payload' command (multipart upload of text)."""
    config.require_api_key()

    parts: list[tuple[str, str | bytes, str | None, str | None]] = []

    # payload_base64
    if args.base64:
        parts.append(("payload_base64", "true", None, None))

    # payload
    parts.append(("payload", args.text, None, None))
    full_body, content_type = _build_multipart_body(parts)

    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(full_body)),
    }

    _, _, resp_body = make_request(
        config, "POST", "/file/scan", data=full_body, headers=headers
    )
    target = _default_history_target_for_submit("payload", args)
    _handle_submit_response(config, args, resp_body, history_target=target)


def cmd_admin_list_api_keys(config: Config, args):
    """Handler for 'admin-list-keys' command."""
    config.require_api_key()
    params = [f"limit={args.limit}"]
    if args.include_inactive:
        params.append("include_inactive=true")
    path = f"/admin/api-keys?{'&'.join(params)}"
    status, _, body = make_request(config, "GET", path)
    emit_output(body, config)


def cmd_admin_mint_api_key(config: Config, args):
    """Handler for 'admin-mint-key' command."""
    config.require_api_key()
    payload: dict[str, Any] = {}
    if args.label:
        payload["label"] = args.label
    if args.read_rpm is not None:
        payload["read_rpm"] = args.read_rpm
    if args.write_rpm is not None:
        payload["write_rpm"] = args.write_rpm
    if args.ttl_days is not None:
        payload["ttl_days"] = args.ttl_days
    if args.is_admin:
        payload["is_admin"] = True
    status, _, body = make_request(config, "POST", "/admin/api-keys", data=payload)
    emit_output(body, config)


def cmd_admin_revoke_api_key(config: Config, args):
    """Handler for 'admin-revoke-key' command."""
    config.require_api_key()
    key_hash = str(args.key_hash or "").strip().lower()
    if len(key_hash) != 64 or any(c not in "0123456789abcdef" for c in key_hash):
        die("key_hash must be a 64-character sha256 hex digest")
    path = f"/admin/api-keys/{key_hash}/revoke"
    status, _, body = make_request(config, "POST", path)
    emit_output(body, config)


def cmd_env(config: Config, args):
    unset = bool(getattr(args, "unset", False))
    print(emit_shell_exports(config.resolved_context, unset=unset))


def cmd_config_show(config: Config, args):
    show_secrets = bool(getattr(args, "show_secrets", False))
    out = {
        "context": config.context,
        "base_url": config.base_url,
        "api_key_header": config.api_key_header,
        "api_key_present": bool(config.api_key),
        "api_key": config.api_key if show_secrets else _mask_secret(config.api_key),
        "api_fqdn": config.resolved_context.api_fqdn,
        "history_path": str(config.history_path),
        "dotenv_path": str(config.dotenv_path) if config.dotenv_path else "",
        "repo_root": str(config.repo_root) if config.repo_root else "",
        "is_tty": config.is_tty,
        "source_details": config.resolved_context.source_details,
    }
    emit_output(out, config, kind="config")


def cmd_doctor(config: Config, args):
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    add("python", True, sys.executable)
    add(
        "repo_root",
        bool(config.repo_root and config.repo_root.exists()),
        str(config.repo_root) if config.repo_root else "not a source checkout",
    )
    add(
        "dotenv_path",
        bool(config.dotenv_path and config.dotenv_path.exists()),
        str(config.dotenv_path) if config.dotenv_path else "not found",
    )
    add("history_parent", config.history_path.parent.exists(), str(config.history_path.parent))
    add("base_url", bool(config.base_url), config.base_url or "<empty>")
    add("api_key", bool(config.api_key), "present" if config.api_key else "missing")
    if config.context == "az":
        add("az_cli", shutil.which("az") is not None, shutil.which("az") or "not found")
        add(
            "azure_context",
            bool(config.resolved_context.api_fqdn and config.resolved_context.api_key),
            config.resolved_context.api_fqdn or "resolution failed",
        )
    else:
        add("az_cli", shutil.which("az") is not None, shutil.which("az") or "not found")

    out = {
        "context": config.context,
        "base_url": config.base_url,
        "api_key_header": config.api_key_header,
        "api_key_present": bool(config.api_key),
        "history_path": str(config.history_path),
        "dotenv_path": str(config.dotenv_path) if config.dotenv_path else "",
        "checks": checks,
    }
    emit_output(out, config, kind="doctor")


def _resolved_command_name(args) -> str:
    if getattr(args, "command", None) == "config":
        sub = str(getattr(args, "config_command", "") or "").strip()
        if sub:
            return f"config {sub}"
    return str(getattr(args, "command", "") or "")

def _dispatch_command(config: Config, args) -> int:
    cmd_map = {
        "health": cmd_health,
        "scan-url": cmd_scan_url,
        "status": cmd_status,
        "wait": cmd_wait,
        "watch": cmd_watch,
        "jobs": cmd_jobs,
        "history": cmd_history,
        "clear-history": cmd_clear_history,
        "clear-server-history": cmd_clear_server_history,
        "screenshot": cmd_screenshot,
        "scan-file": cmd_scan_file,
        "scan-payload": cmd_scan_payload,
        "admin-list-keys": cmd_admin_list_api_keys,
        "admin-mint-key": cmd_admin_mint_api_key,
        "admin-revoke-key": cmd_admin_revoke_api_key,
        "env": cmd_env,
        "doctor": cmd_doctor,
        "config show": cmd_config_show,
    }
    command_name = _resolved_command_name(args)
    handler = cmd_map.get(command_name)
    if not handler:
        return 0

    if command_name not in {"env", "doctor", "config show"}:
        maybe_prompt_for_missing_args(command_name, args, config)
        ensure_required_command_args(command_name, args)
    handler(config, args)
    return 0
