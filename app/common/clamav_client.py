from __future__ import annotations

from dataclasses import dataclass
import socket
import struct
from typing import Iterable, Optional


class ClamAVError(RuntimeError):
    pass


class ClamAVConnectionError(ClamAVError):
    pass


class ClamAVProtocolError(ClamAVError):
    pass


@dataclass(frozen=True)
class ClamAVScanResult:
    verdict: str  # clean | malicious | error
    signature: Optional[str]
    raw: str
    error: Optional[str] = None

    def as_dict(self) -> dict:
        out = {
            "verdict": self.verdict,
            "raw": self.raw,
        }
        if self.signature:
            out["signature"] = self.signature
        if self.error:
            out["error"] = self.error
        return out


def _recv_until_delim(
    sock: socket.socket,
    *,
    delims: tuple[bytes, ...] = (b"\0", b"\n"),
    max_bytes: int = 16_384,
) -> bytes:
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        for d in delims:
            idx = buf.find(d)
            if idx != -1:
                return bytes(buf[: idx + len(d)])
    return bytes(buf)


def _send_command(sock: socket.socket, command: bytes) -> None:
    try:
        sock.sendall(command)
    except OSError as e:
        raise ClamAVConnectionError(f"failed to send command: {e}") from e


def _decode_line(raw: bytes) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", "replace").strip("\r\n\0 ")


def parse_clamd_response(line: str) -> ClamAVScanResult:
    raw = (line or "").strip().strip("\0")
    if not raw:
        return ClamAVScanResult(
            verdict="error", signature=None, raw="", error="empty response from clamd"
        )

    # Typical formats:
    # - "stream: OK"
    # - "stream: Eicar-Signature FOUND"
    # - "stream: <message> ERROR"
    _prefix, _sep, rest = raw.partition(":")
    body = (rest or raw).strip()

    upper = body.upper()
    if upper.endswith("OK"):
        return ClamAVScanResult(verdict="clean", signature=None, raw=raw)

    if upper.endswith("FOUND"):
        sig = body[: -len("FOUND")].strip()
        return ClamAVScanResult(
            verdict="malicious", signature=sig or None, raw=raw
        )

    if upper.endswith("ERROR"):
        msg = body[: -len("ERROR")].strip()
        return ClamAVScanResult(
            verdict="error",
            signature=None,
            raw=raw,
            error=msg or "clamd returned error",
        )

    return ClamAVScanResult(
        verdict="error",
        signature=None,
        raw=raw,
        error="unrecognized clamd response",
    )


def clamd_ping(*, host: str = "127.0.0.1", port: int = 3310, timeout_seconds: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            _send_command(sock, b"PING\n")
            resp = _decode_line(_recv_until_delim(sock))
            return resp == "PONG"
    except OSError:
        return False


def clamd_version(
    *, host: str = "127.0.0.1", port: int = 3310, timeout_seconds: float = 2.0
) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            _send_command(sock, b"VERSION\n")
            resp = _decode_line(_recv_until_delim(sock))
            if not resp:
                raise ClamAVProtocolError("empty VERSION response from clamd")
            return resp
    except OSError as e:
        raise ClamAVConnectionError(f"failed to connect to clamd: {e}") from e


def clamd_scan_bytes(
    data: bytes,
    *,
    host: str = "127.0.0.1",
    port: int = 3310,
    timeout_seconds: float = 8.0,
    chunk_size: int = 8192,
) -> ClamAVScanResult:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            # Use a null-terminated command to avoid ambiguity, then read until \0 or \n.
            _send_command(sock, b"zINSTREAM\0")

            if data:
                view = memoryview(data)
                offset = 0
                while offset < len(view):
                    chunk = view[offset : offset + chunk_size]
                    offset += len(chunk)
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)

            sock.sendall(struct.pack("!I", 0))
            raw = _decode_line(_recv_until_delim(sock))
            if not raw:
                raise ClamAVProtocolError("empty scan response from clamd")
            return parse_clamd_response(raw)
    except ClamAVError:
        raise
    except OSError as e:
        raise ClamAVConnectionError(f"clamd scan failed: {e}") from e


def clamd_scan_chunks(
    chunks: Iterable[bytes],
    *,
    host: str = "127.0.0.1",
    port: int = 3310,
    timeout_seconds: float = 8.0,
) -> ClamAVScanResult:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            sock.settimeout(timeout_seconds)
            _send_command(sock, b"zINSTREAM\0")

            for chunk in chunks:
                if not chunk:
                    continue
                if not isinstance(chunk, (bytes, bytearray, memoryview)):
                    chunk = bytes(chunk)
                chunk_bytes = bytes(chunk)
                sock.sendall(struct.pack("!I", len(chunk_bytes)))
                sock.sendall(chunk_bytes)

            sock.sendall(struct.pack("!I", 0))
            raw = _decode_line(_recv_until_delim(sock))
            if not raw:
                raise ClamAVProtocolError("empty scan response from clamd")
            return parse_clamd_response(raw)
    except ClamAVError:
        raise
    except OSError as e:
        raise ClamAVConnectionError(f"clamd scan failed: {e}") from e
