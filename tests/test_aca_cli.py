from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_MODULE_PATH = REPO_ROOT / "src" / "aca_cli" / "cli.py"
WRAPPER_PATH = REPO_ROOT / "scripts" / "aca"
SRC_DIR = REPO_ROOT / "src"


def _load_cli_module():
    src_str = str(SRC_DIR)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
    module = importlib.import_module("aca_cli.cli")
    return importlib.reload(module)


@pytest.fixture
def aca_cli():
    return _load_cli_module()


def test_build_parser_accepts_prompt_flags_and_follow(aca_cli):
    parser = aca_cli.build_parser()

    args = parser.parse_args(
        ["--prompt", "--json", "scan-url", "https://example.com", "--follow", "watch"]
    )
    assert args.prompt is True
    assert args.no_prompt is False
    assert args.json_output is True
    assert args.command == "scan-url"
    assert args.url == "https://example.com"
    assert args.follow == "watch"

    args = parser.parse_args(["--no-prompt", "status", "job-123"])
    assert args.prompt is False
    assert args.no_prompt is True
    assert args.command == "status"
    assert args.job_id == "job-123"

    args = parser.parse_args(
        ["--color", "never", "scan-file", "sample.bin", "--follow", "watch", "--timeout", "9"]
    )
    assert args.color == "never"
    assert args.command == "scan-file"
    assert args.follow == "watch"
    assert args.timeout == 9

    args = parser.parse_args(["scan-payload", "hello", "--wait", "--view", "full"])
    assert args.command == "scan-payload"
    assert args.wait is True
    assert args.view == "full"

    args = parser.parse_args(["history", "--format", "json", "--limit", "5"])
    assert args.command == "history"
    assert args.format == "json"
    assert args.limit == 5


def test_emit_json_defaults_to_human_friendly_output(capsys, aca_cli):
    config = SimpleNamespace(raw=False, json_output=False)
    aca_cli.emit_json(
        {
            "job_id": "job-1",
            "status": "completed",
            "verdict": "clean",
            "summary": {"score": 1, "signals": ["ok"]},
        },
        config,
    )
    out = capsys.readouterr().out
    assert "Result" in out
    assert "status" in out
    assert "summary:" in out
    assert '"job_id"' not in out


def test_emit_json_with_json_flag_outputs_json(capsys, aca_cli):
    config = SimpleNamespace(raw=False, json_output=True)
    aca_cli.emit_json({"job_id": "job-1", "status": "queued"}, config)
    out = capsys.readouterr().out
    assert '"job_id": "job-1"' in out


def test_scan_url_follow_watch_dispatches_to_watch(monkeypatch, aca_cli):
    calls: dict[str, object] = {}

    class _FakeConfig:
        verbose = False
        base_url = "http://localhost:8000"
        api_key = "k"
        api_key_header = "X-API-Key"

        def require_api_key(self):
            return None

    def fake_make_request(config, method, path, data=None, headers=None, stream=False):
        calls["request"] = {"method": method, "path": path, "data": data}
        return 200, {}, json.dumps({"job_id": "job-1", "status": "queued"})

    def fake_append_history(config, job_id, url):
        calls["history"] = {"job_id": job_id, "url": url}

    def fake_cmd_watch(config, args):
        calls["watch"] = {
            "job_id": args.job_id,
            "interval": args.interval,
            "timeout": args.timeout,
            "view": args.view,
            "fallback_poll": args.fallback_poll,
        }

    def fake_cmd_wait(config, args):
        calls["wait"] = True

    monkeypatch.setattr(aca_cli, "make_request", fake_make_request)
    monkeypatch.setattr(aca_cli, "append_history", fake_append_history)
    monkeypatch.setattr(aca_cli, "cmd_watch", fake_cmd_watch)
    monkeypatch.setattr(aca_cli, "cmd_wait", fake_cmd_wait)

    args = argparse.Namespace(
        url="https://example.com",
        source=None,
        force=False,
        meta=[],
        meta_json=None,
        wait=False,
        follow="watch",
        interval=3,
        timeout=45,
        view="summary",
    )
    aca_cli.cmd_scan_url(_FakeConfig(), args)

    assert calls["request"]["method"] == "POST"
    assert calls["history"] == {"job_id": "job-1", "url": "https://example.com"}
    assert calls["watch"]["job_id"] == "job-1"
    assert "wait" not in calls


def test_scan_file_follow_watch_dispatches_to_watch(monkeypatch, tmp_path, aca_cli):
    calls: dict[str, object] = {}
    f = tmp_path / "sample.bin"
    f.write_bytes(b"abc")

    class _FakeConfig:
        verbose = False
        base_url = "http://localhost:8000"
        api_key = "k"
        api_key_header = "X-API-Key"

        def require_api_key(self):
            return None

    def fake_make_request(config, method, path, data=None, headers=None, stream=False):
        calls["request"] = {"method": method, "path": path, "headers": headers}
        return 200, {}, json.dumps({"job_id": "job-file-1", "status": "completed"})

    def fake_append_history(config, job_id, target):
        calls["history"] = {"job_id": job_id, "target": target}

    def fake_cmd_watch(config, args):
        calls["watch"] = {"job_id": args.job_id, "view": args.view, "timeout": args.timeout}

    monkeypatch.setattr(aca_cli, "make_request", fake_make_request)
    monkeypatch.setattr(aca_cli, "append_history", fake_append_history)
    monkeypatch.setattr(aca_cli, "cmd_watch", fake_cmd_watch)

    args = argparse.Namespace(
        command="scan-file",
        path=str(f),
        wait=False,
        follow="watch",
        interval=2,
        timeout=15,
        view="summary",
    )
    aca_cli.cmd_scan_file(_FakeConfig(), args)

    assert calls["request"]["method"] == "POST"
    assert calls["request"]["path"] == "/file/scan"
    assert calls["history"]["target"] == "file://sample.bin"
    assert calls["watch"]["job_id"] == "job-file-1"


def test_scan_payload_follow_wait_dispatches_to_wait(monkeypatch, aca_cli):
    calls: dict[str, object] = {}

    class _FakeConfig:
        verbose = False
        base_url = "http://localhost:8000"
        api_key = "k"
        api_key_header = "X-API-Key"

        def require_api_key(self):
            return None

    def fake_make_request(config, method, path, data=None, headers=None, stream=False):
        calls["request"] = {"method": method, "path": path}
        return 200, {}, json.dumps({"job_id": "job-payload-1", "status": "completed"})

    def fake_append_history(config, job_id, target):
        calls["history"] = {"job_id": job_id, "target": target}

    def fake_cmd_wait(config, args):
        calls["wait"] = {"job_id": args.job_id, "view": args.view, "timeout": args.timeout}

    monkeypatch.setattr(aca_cli, "make_request", fake_make_request)
    monkeypatch.setattr(aca_cli, "append_history", fake_append_history)
    monkeypatch.setattr(aca_cli, "cmd_wait", fake_cmd_wait)

    args = argparse.Namespace(
        command="scan-payload",
        text="hello",
        base64=False,
        wait=True,
        follow=None,
        interval=3,
        timeout=20,
        view="full",
    )
    aca_cli.cmd_scan_payload(_FakeConfig(), args)

    assert calls["request"]["path"] == "/file/scan"
    assert calls["history"]["target"] == "payload://5-chars"
    assert calls["wait"]["job_id"] == "job-payload-1"
    assert calls["wait"]["view"] == "full"


def test_resolve_azure_env_and_emit_shell_exports(monkeypatch, aca_cli):
    outputs = iter(["my-api.example.com\r\n", "sekret'value\r\n"])

    def fake_run(cmd, check, capture_output, text):
        return SimpleNamespace(stdout=next(outputs), stderr="")

    monkeypatch.setattr(aca_cli.subprocess, "run", fake_run)

    resolved = aca_cli.resolve_azure_env(
        {
            "ACA_RG": "rg-test",
            "ACA_API_APP": "app-test",
            "ACA_KV": "kv-test",
            "ACA_API_KEY_SECRET_NAME": "ApiKey",
        }
    )
    assert resolved.context == "az"
    assert resolved.api_fqdn == "my-api.example.com"
    assert resolved.base_url == "https://my-api.example.com"
    assert resolved.api_key == "sekret'value"

    exports = aca_cli.emit_shell_exports(resolved)
    assert "export API_FQDN='my-api.example.com'" in exports
    assert "export API_KEY='sekret'\"'\"'value'" in exports


def test_config_skips_azure_resolution_for_env_unset(monkeypatch, aca_cli):
    parser = aca_cli.build_parser()
    args = parser.parse_args(["--context", "az", "env", "--unset"])

    def boom(*_args, **_kwargs):
        raise AssertionError("resolve_context should not be called for env --unset")

    monkeypatch.setattr(aca_cli, "resolve_context", boom)
    cfg = aca_cli.Config(args)
    assert cfg.context == "az"
    assert cfg.resolved_context.context == "az"


def test_config_honors_no_color_by_default(monkeypatch, aca_cli):
    parser = aca_cli.build_parser()
    args = parser.parse_args(["health"])
    monkeypatch.setenv("NO_COLOR", "1")
    cfg = aca_cli.Config(args)
    assert cfg.color == "never"

    args = parser.parse_args(["--color", "always", "health"])
    cfg = aca_cli.Config(args)
    assert cfg.color == "always"


def test_prompt_requires_tty(monkeypatch, aca_cli):
    monkeypatch.setattr(aca_cli.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(aca_cli.sys.stdout, "isatty", lambda: False)

    with pytest.raises(SystemExit) as exc:
        aca_cli.main(["--prompt", "scan-url"])
    assert exc.value.code == 1


def test_prompt_status_uses_history_selection(monkeypatch, tmp_path, aca_cli):
    history_file = tmp_path / "history.txt"
    history_file.write_text(
        "2026-02-22T00:00:00Z\tjob-aaa\thttps://example.com\thttp://localhost:8000\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(aca_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(aca_cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "1")

    captured: dict[str, str] = {}

    def fake_make_request(config, method, path, data=None, headers=None, stream=False):
        captured["method"] = method
        captured["path"] = path
        return 200, {}, json.dumps({"job_id": "job-aaa", "status": "completed"})

    def fake_emit_json(output, config, **_kwargs):
        captured["output"] = output if isinstance(output, str) else json.dumps(output)

    monkeypatch.setattr(aca_cli, "make_request", fake_make_request)
    monkeypatch.setattr(aca_cli, "emit_json", fake_emit_json)

    aca_cli.main(["--prompt", "--history", str(history_file), "status"])

    assert captured["method"] == "GET"
    assert captured["path"] == "/scan/job-aaa?view=summary"


def test_wrapper_smoke_commands():
    for cmd in (
        [str(WRAPPER_PATH), "--help"],
        [str(WRAPPER_PATH), "help"],
        [str(WRAPPER_PATH), "env", "--unset"],
        [str(WRAPPER_PATH), "az", "help"],
    ):
        proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        assert proc.returncode == 0, f"{cmd} failed: {proc.stderr}"


def test_python_module_entrypoint_help():
    env = dict(os.environ)
    src_path = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = src_path + (f":{env['PYTHONPATH']}" if env.get("PYTHONPATH") else "")
    proc = subprocess.run(
        [sys.executable, "-m", "aca_cli", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert "CLI helper for the FastAPI scanner service" in proc.stdout
