from __future__ import annotations

import errno
import socket
import struct
import sys
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.clamav_client import (  # noqa: E402
    clamd_scan_bytes,
    clamd_scan_chunks,
    parse_clamd_response,
)


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def _recv_until(conn: socket.socket, delim: bytes) -> bytes:
    buf = bytearray()
    while True:
        b = conn.recv(1)
        if not b:
            raise EOFError("connection closed")
        buf.extend(b)
        if buf.endswith(delim):
            return bytes(buf)


@contextmanager
def _fake_clamd_server(*, response: bytes):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
    except OSError as e:
        try:
            server.close()
        except Exception:
            pass
        if getattr(e, "errno", None) in (errno.EPERM, errno.EACCES):
            pytest.skip("Socket bind not permitted in this environment.")
        raise
    server.listen(1)
    port = server.getsockname()[1]
    received: dict = {}

    def handler():
        conn, _ = server.accept()
        with conn:
            cmd = _recv_until(conn, b"\0")
            received["command"] = cmd

            data = bytearray()
            while True:
                raw_len = _recv_exact(conn, 4)
                (n,) = struct.unpack("!I", raw_len)
                if n == 0:
                    break
                data.extend(_recv_exact(conn, n))
            received["data"] = bytes(data)
            conn.sendall(response)

    t = threading.Thread(target=handler, daemon=True)
    t.start()
    try:
        yield port, received
    finally:
        try:
            server.close()
        except Exception:
            pass
        t.join(timeout=2)


def test_parse_ok():
    res = parse_clamd_response("stream: OK")
    assert res.verdict == "clean"
    assert res.signature is None


def test_parse_found():
    res = parse_clamd_response("stream: Eicar-Test-Signature FOUND")
    assert res.verdict == "malicious"
    assert res.signature == "Eicar-Test-Signature"


def test_parse_error():
    res = parse_clamd_response("stream: something went wrong ERROR")
    assert res.verdict == "error"
    assert res.error


def test_scan_bytes_stream_protocol_and_ok_response():
    payload = b"hello world"
    with _fake_clamd_server(response=b"stream: OK\0") as (port, received):
        res = clamd_scan_bytes(payload, host="127.0.0.1", port=port, timeout_seconds=1.0)
    assert received["command"] == b"zINSTREAM\0"
    assert received["data"] == payload
    assert res.verdict == "clean"


def test_scan_bytes_found_response():
    payload = b"x" * 32
    with _fake_clamd_server(response=b"stream: Eicar-Test-Signature FOUND\0") as (port, _):
        res = clamd_scan_bytes(payload, host="127.0.0.1", port=port, timeout_seconds=1.0)
    assert res.verdict == "malicious"
    assert res.signature == "Eicar-Test-Signature"


def test_scan_chunks_concatenates_stream():
    with _fake_clamd_server(response=b"stream: OK\0") as (port, received):
        res = clamd_scan_chunks([b"a", b"b", b"", b"c"], host="127.0.0.1", port=port, timeout_seconds=1.0)
    assert received["data"] == b"abc"
    assert res.verdict == "clean"
