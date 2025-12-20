#!/usr/bin/env python3
import json
import sys


def _clean(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value)


def _fmt_kv(key: str, value) -> str:
    value = _clean(value)
    return f"{key}={value}" if value else ""


def format_line(obj: dict) -> str:
    ts = _clean(obj.get("TimeStamp") or obj.get("timestamp") or obj.get("time"))

    if "Msg" in obj:
        parts: list[str] = []
        if ts:
            parts.append(ts)

        typ = _clean(obj.get("Type") or obj.get("type"))
        reason = _clean(obj.get("Reason") or obj.get("reason"))
        src = _clean(
            obj.get("EventSource") or obj.get("eventSource") or obj.get("source")
        )
        if typ:
            parts.append(typ)
        if reason:
            parts.append(reason)
        if src:
            parts.append(src)

        meta = " ".join(
            p
            for p in [
                _fmt_kv("app", obj.get("ContainerAppName")),
                _fmt_kv("rev", obj.get("RevisionName")),
                _fmt_kv("rep", obj.get("ReplicaName")),
                _fmt_kv("container", obj.get("ContainerName")),
            ]
            if p
        )
        if meta:
            parts.append(meta)

        msg = _clean(obj.get("Msg"))
        if msg:
            parts.append(msg)

        count = obj.get("Count")
        if count not in (None, "", 1):
            parts.append(f"count={count}")

        return " | ".join(parts) if parts else json.dumps(obj, ensure_ascii=False)

    if "Log" in obj:
        parts: list[str] = []
        if ts:
            parts.append(ts)
        rep = _fmt_kv("rep", obj.get("ReplicaName"))
        if rep:
            parts.append(rep)
        log = _clean(obj.get("Log"))
        if log:
            parts.append(log)
        return " | ".join(parts) if parts else json.dumps(obj, ensure_ascii=False)

    return json.dumps(obj, ensure_ascii=False)


def main() -> int:
    for raw in sys.stdin:
        line = raw.rstrip("\n")
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            print(line, flush=True)
            continue
        if isinstance(obj, dict):
            print(format_line(obj), flush=True)
        else:
            print(json.dumps(obj, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

