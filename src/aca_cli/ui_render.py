from __future__ import annotations

from typing import Any

from . import ui_console


def _stdout_console(config):
    return getattr(config, "stdout_console", None)


def _unicode(config) -> bool:
    return bool(getattr(config, "unicode_symbols", True))


def _rich_stdout(config) -> bool:
    return bool(getattr(config, "rich_stdout", False)) and _stdout_console(config) is not None


def _is_scan_result(data: Any) -> bool:
    return isinstance(data, dict) and ("job_id" in data or "status" in data)


def render_output(data: Any, config, *, kind: str | None = None) -> bool:
    if not _rich_stdout(config):
        return False

    if kind == "doctor":
        return render_doctor(data, config)
    if kind == "config":
        return render_config(data, config)
    if kind == "history":
        return render_history(data, config)
    if kind == "scan_result":
        return render_scan_result(data, config)

    if _is_scan_result(data):
        return render_scan_result(data, config)
    if isinstance(data, dict) and isinstance(data.get("checks"), list):
        return render_doctor(data, config)
    if isinstance(data, dict) and "api_key_present" in data and "history_path" in data:
        return render_config(data, config)

    return render_generic(data, config)


def _tree_add(tree, key: str, value: Any) -> None:
    if isinstance(value, dict):
        branch = tree.add(f"{key}")
        if not value:
            branch.add("(empty)")
            return
        for child_key, child_val in value.items():
            _tree_add(branch, str(child_key), child_val)
        return
    if isinstance(value, list):
        branch = tree.add(f"{key}")
        if not value:
            branch.add("(empty)")
            return
        for idx, item in enumerate(value, start=1):
            if isinstance(item, (dict, list)):
                _tree_add(branch, f"[{idx}]", item)
            else:
                branch.add(f"[{idx}] {item}")
        return
    tree.add(f"{key}: {value if value not in (None, '') else '-'}")


def render_generic(data: Any, config) -> bool:
    console = _stdout_console(config)
    if console is None or not ui_console.RICH_AVAILABLE:
        return False
    if ui_console.Tree is None:
        console.print(data)
        return True
    if isinstance(data, dict):
        root = ui_console.Tree("Result")
        if not data:
            root.add("(empty)")
        else:
            for key, value in data.items():
                _tree_add(root, str(key), value)
        console.print(root)
        return True
    if isinstance(data, list):
        root = ui_console.Tree("List")
        if not data:
            root.add("(empty)")
        else:
            for idx, item in enumerate(data, start=1):
                _tree_add(root, f"[{idx}]", item)
        console.print(root)
        return True
    console.print(data)
    return True


def _value_text(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _meta_rows_for_scan(data: dict[str, Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []

    def add(label: str, key: str, *, transform=None):
        if key not in data:
            return
        value = data.get(key)
        if value in (None, "", []):
            return
        if transform:
            value = transform(value)
        rows.append((label, _value_text(value)))

    add("Status", "status")
    add("Verdict", "verdict")
    add("Type", "type")
    add("Job ID", "job_id")
    add("Run ID", "run_id")
    add("URL", "url")
    add("Filename", "filename")
    add("Deduped", "deduped", transform=lambda v: "yes" if bool(v) else "no")
    add("Submitted", "submitted_at")
    add("Scanned", "scanned_at")
    add("Size", "size_bytes", transform=ui_console.fmt_bytes)
    add("Duration", "duration_ms", transform=ui_console.fmt_duration_ms)
    add("Dashboard", "dashboard_url")
    add("Error", "error")
    return rows


def _summary_from_scan_doc(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary")
    if isinstance(summary, dict):
        out = dict(summary)
        if "url" not in out:
            if isinstance(data.get("url"), str):
                out["url"] = data["url"]
        return out
    return {}


def render_scan_result(data: Any, config) -> bool:
    if not _rich_stdout(config) or not isinstance(data, dict):
        return False
    console = _stdout_console(config)
    if console is None or ui_console.Table is None:
        return False

    unicode_symbols = _unicode(config)
    status = str(data.get("status") or "").strip().lower()
    icon = ui_console.status_icon(status, unicode_symbols=unicode_symbols)
    style = ui_console.status_style(status)
    title = f"{icon} Scan Result" if unicode_symbols else "Scan Result"

    meta = ui_console.Table.grid(padding=(0, 2))
    meta.add_column(style="bold")
    meta.add_column()
    for label, value in _meta_rows_for_scan(data):
        value_style = style if label == "Status" else ("green" if label == "Verdict" else None)
        meta.add_row(label, f"[{value_style}]{value}[/{value_style}]" if value_style else value)

    if ui_console.Panel is not None:
        console.print(ui_console.Panel(meta, title=f"[{style}]{title}[/{style}]"))
    else:
        console.print(title)
        console.print(meta)

    summary = _summary_from_scan_doc(data)
    details = data.get("details") if isinstance(data.get("details"), dict) else None
    if summary:
        console.print()
        _print_kv_table(console, "Summary", summary, config)

        download = summary.get("download")
        if isinstance(download, dict) and download:
            console.print()
            _print_kv_table(console, "Download", download, config)

        web = summary.get("web")
        if isinstance(web, dict) and web:
            console.print()
            _print_kv_table(console, "Web Findings", web, config, value_limit=200)

    if details:
        console.print()
        if ui_console.Tree is not None:
            tree = ui_console.Tree("Details")
            for key, value in details.items():
                _tree_add(tree, str(key), value)
            console.print(tree)
        else:
            console.print(details)
    return True


def _print_kv_table(console, title: str, data: dict[str, Any], config, *, value_limit: int = 120) -> None:
    if ui_console.Table is None:
        console.print(title)
        for key, value in data.items():
            console.print(f"  {key}: {value}")
        return
    table = ui_console.Table(
        title=title,
        box=ui_console.box.SIMPLE_HEAVY if ui_console.box else None,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            rendered = ui_console.truncate(str(value), value_limit)
        else:
            rendered = _value_text(value)
            rendered = ui_console.truncate(rendered, value_limit)
        if str(key).lower() == "status":
            style = ui_console.status_style(rendered)
            rendered = f"[{style}]{rendered}[/{style}]"
        table.add_row(str(key), rendered)
    console.print(table)


def render_jobs(sections: list[tuple[str, str, list[dict[str, Any]]]], config) -> bool:
    if not _rich_stdout(config):
        return False
    console = _stdout_console(config)
    if console is None or ui_console.Table is None:
        return False
    unicode_symbols = _unicode(config)

    for idx, (title, scan_type, jobs) in enumerate(sections):
        if idx:
            console.print()
        table = ui_console.Table(
            title=title,
            box=ui_console.box.SIMPLE_HEAVY if ui_console.box else None,
            show_lines=False,
        )
        table.add_column("Status", no_wrap=True)
        table.add_column("Job ID", no_wrap=True)
        table.add_column("Submitted", no_wrap=True)
        table.add_column("Scanned", no_wrap=True)
        if scan_type == "file":
            table.add_column("Verdict", no_wrap=True)
            table.add_column("SHA256", no_wrap=True)
            table.add_column("Filename")
        else:
            table.add_column("Target")

        if not jobs:
            console.print(table)
            console.print("  (no jobs)")
            continue

        for job in jobs:
            status = str(job.get("status") or "")
            icon = ui_console.status_icon(status, unicode_symbols=unicode_symbols)
            style = ui_console.status_style(status)
            status_cell = f"[{style}]{icon} {status}[/{style}]"
            jid = ui_console.truncate(job.get("job_id") or "", 36)
            submitted = ui_console.truncate(job.get("submitted_at") or "", 20)
            scanned = ui_console.truncate(job.get("scanned_at") or "", 20)
            if scan_type == "file":
                verdict = str(job.get("verdict") or "")
                verdict_style = "green" if verdict.lower() == "clean" else ("red" if verdict else "white")
                sha = ui_console.truncate(str(job.get("sha256") or ""), 12)
                filename = ui_console.truncate(str(job.get("filename") or ""), 64)
                table.add_row(
                    status_cell,
                    jid,
                    submitted,
                    scanned,
                    f"[{verdict_style}]{verdict}[/{verdict_style}]" if verdict else "-",
                    sha or "-",
                    filename or "-",
                )
            else:
                target = ui_console.truncate(str(job.get("url") or ""), 84)
                table.add_row(status_cell, jid, submitted, scanned, target or "-")
        console.print(table)
    return True


def render_history(entries: Any, config) -> bool:
    if not _rich_stdout(config) or not isinstance(entries, list):
        return False
    console = _stdout_console(config)
    if console is None or ui_console.Table is None:
        return False

    table = ui_console.Table(
        title="History",
        box=ui_console.box.SIMPLE_HEAVY if ui_console.box else None,
    )
    table.add_column("#", style="bold", no_wrap=True)
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Job ID", no_wrap=True)
    table.add_column("Target")
    table.add_column("Base URL")

    if not entries:
        console.print(table)
        console.print("  (no history)")
        return True

    for idx, item in enumerate(entries, start=1):
        table.add_row(
            str(idx),
            ui_console.truncate(item.get("timestamp") or "", 24),
            ui_console.truncate(item.get("job_id") or "", 36),
            ui_console.truncate(item.get("url") or "", 96),
            ui_console.truncate(item.get("base_url") or "", 64),
        )
    console.print(table)
    return True


def render_doctor(data: Any, config) -> bool:
    if not _rich_stdout(config) or not isinstance(data, dict):
        return False
    console = _stdout_console(config)
    if console is None or ui_console.Table is None:
        return False

    top = ui_console.Table.grid(padding=(0, 2))
    top.add_column(style="bold")
    top.add_column()
    for key in ("context", "base_url", "api_key_header", "api_key_present", "history_path", "dotenv_path"):
        if key in data:
            value = data.get(key)
            if key == "api_key_present":
                value = "yes" if bool(value) else "no"
            top.add_row(key, _value_text(value))

    if ui_console.Panel is not None:
        console.print(ui_console.Panel(top, title="Doctor"))
    else:
        console.print("Doctor")
        console.print(top)

    checks = data.get("checks")
    if not isinstance(checks, list):
        return True

    table = ui_console.Table(
        title="Checks",
        box=ui_console.box.SIMPLE_HEAVY if ui_console.box else None,
    )
    table.add_column("OK", no_wrap=True)
    table.add_column("Check", style="bold", no_wrap=True)
    table.add_column("Detail")
    unicode_symbols = _unicode(config)
    failed = 0
    for item in checks:
        if not isinstance(item, dict):
            continue
        ok = bool(item.get("ok"))
        if not ok:
            failed += 1
        icon = ui_console.bool_icon(ok, unicode_symbols=unicode_symbols)
        style = "green" if ok else "red"
        table.add_row(
            f"[{style}]{icon}[/{style}]",
            _value_text(item.get("check")),
            ui_console.truncate(_value_text(item.get("detail")), 140),
        )
    console.print()
    console.print(table)
    if failed:
        console.print(f"[red]{failed} check(s) need attention[/red]")
    else:
        console.print("[green]All checks passed[/green]")
    return True


def render_config(data: Any, config) -> bool:
    if not _rich_stdout(config) or not isinstance(data, dict):
        return False
    console = _stdout_console(config)
    if console is None or ui_console.Table is None:
        return False

    primary = {
        k: data.get(k)
        for k in (
            "context",
            "base_url",
            "api_key_header",
            "api_key_present",
            "api_key",
            "api_fqdn",
            "history_path",
            "dotenv_path",
            "repo_root",
            "is_tty",
        )
        if k in data
    }
    if "api_key_present" in primary:
        primary["api_key_present"] = "yes" if bool(primary["api_key_present"]) else "no"
    if "is_tty" in primary:
        primary["is_tty"] = "yes" if bool(primary["is_tty"]) else "no"

    _print_kv_table(console, "Configuration", primary, config)

    source_details = data.get("source_details")
    if isinstance(source_details, dict) and source_details:
        console.print()
        _print_kv_table(console, "Resolved Sources", source_details, config)
    return True

