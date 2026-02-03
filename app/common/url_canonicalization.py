from __future__ import annotations

import ipaddress
import posixpath
import re
import string
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

_UNRESERVED = set(string.ascii_letters + string.digits + "-._~")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def _normalize_percent_encoding(value: str) -> str:
    # RFC 3986: percent-encoded octets corresponding to unreserved characters may be decoded.
    # Uppercase hex for all remaining percent-escapes for stable canonicalization.
    def repl(match: re.Match[str]) -> str:
        try:
            ch = chr(int(match.group(1), 16))
        except Exception:
            return match.group(0).upper()
        if ch in _UNRESERVED:
            return ch
        return match.group(0).upper()

    return _PCT_RE.sub(repl, value or "")


def _remove_dot_segments(path: str) -> str:
    # Conservative normalization: remove "." and ".." segments after decoding unreserved chars.
    if not path:
        return "/"

    leading_slash = path.startswith("/")
    trailing_slash = path.endswith("/")

    segments = path.split("/")
    out: list[str] = []
    for seg in segments:
        if seg == ".":
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)

    normalized = "/".join(out)
    if leading_slash and not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized == "":
        normalized = "/" if leading_slash else ""
    if trailing_slash and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def normalize_url_path(path: str) -> str:
    raw = path or ""
    if raw == "":
        return "/"

    # Normalize percent-encoding first so encoded dot segments are handled.
    normalized = _normalize_percent_encoding(raw)
    normalized = _remove_dot_segments(normalized)

    # posixpath.normpath removes redundant separators and up-level refs; we already handled dot
    # segments but keep this as a final guard. Preserve trailing slash.
    trailing = normalized.endswith("/") and normalized != "/"
    normed = posixpath.normpath(normalized)
    if normalized.startswith("/") and not normed.startswith("/"):
        normed = "/" + normed
    if normed == ".":
        normed = "/"
    if trailing and not normed.endswith("/"):
        normed += "/"
    return normed


def _to_unicode_host(host: str) -> str:
    h = (host or "").strip().rstrip(".")
    if not h:
        return ""
    try:
        return h.encode("ascii").decode("idna")
    except Exception:
        return h


def _to_punycode_host(host_unicode: str) -> str:
    h = (host_unicode or "").strip().rstrip(".")
    if not h:
        return ""
    try:
        return h.encode("idna").decode("ascii")
    except Exception:
        return h


def _format_host_for_url(host_punycode: str) -> str:
    host = (host_punycode or "").strip().rstrip(".")
    if not host:
        return ""
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{host}]"
    except ValueError:
        pass
    return host


def _strip_default_port(scheme: str, port: int | None) -> int | None:
    if port is None:
        return None
    if scheme == "https" and port == 443:
        return None
    if scheme == "http" and port == 80:
        return None
    return port


@dataclass(frozen=True)
class CanonicalUrl:
    original: str
    canonical: str
    scheme: str
    host_unicode: str
    host_punycode: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    removed_fragment: str

    def as_dict(self) -> dict:
        return {
            "original": self.original,
            "canonical": self.canonical,
            "scheme": self.scheme,
            "host_unicode": self.host_unicode,
            "host_punycode": self.host_punycode,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "has_userinfo": self.has_userinfo,
            "removed_fragment": self.removed_fragment,
        }


def canonicalize_url(url: str) -> CanonicalUrl:
    parsed: SplitResult = urlsplit(url or "")
    scheme = (parsed.scheme or "").strip().lower()

    raw_host = parsed.hostname or ""
    host_unicode = _to_unicode_host(raw_host).casefold()
    host_punycode = _to_punycode_host(host_unicode).lower()

    port = _strip_default_port(scheme, parsed.port)

    path = normalize_url_path(parsed.path)
    query = _normalize_percent_encoding(parsed.query or "")

    has_userinfo = bool(parsed.username or parsed.password)
    removed_fragment = parsed.fragment or ""

    # Canonical netloc: never include userinfo; avoid logging credentials.
    host_for_url = _format_host_for_url(host_punycode)
    netloc = host_for_url
    if port is not None and host_for_url:
        netloc = f"{host_for_url}:{port}"

    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return CanonicalUrl(
        original=url or "",
        canonical=canonical,
        scheme=scheme,
        host_unicode=host_unicode,
        host_punycode=host_punycode,
        port=port,
        path=path,
        query=query,
        has_userinfo=has_userinfo,
        removed_fragment=removed_fragment,
    )
