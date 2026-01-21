from __future__ import annotations

from urllib.parse import urljoin

import requests

from common.limits import get_web_fetch_limits
from common.http_parsing import parse_set_cookie_headers
from common.url_canonicalization import CanonicalUrl, canonicalize_url
from common.url_validation import UrlValidationError, validate_public_https_url

_LIMITS = get_web_fetch_limits()
MAX_DOWNLOAD_BYTES = _LIMITS.max_download_bytes
REQUEST_TIMEOUT = _LIMITS.request_timeout_seconds
MAX_REDIRECTS = _LIMITS.max_redirects
BLOCK_PRIVATE_NETWORKS = _LIMITS.block_private_networks

# Response headers/cookies are used for the web analysis UI.
WEB_MAX_HEADER_VALUE_LEN = _LIMITS.max_header_value_len
WEB_MAX_HEADERS = _LIMITS.max_headers


def validate_url_for_download(
    url: str, *, block_private_networks: bool = BLOCK_PRIVATE_NETWORKS
) -> CanonicalUrl:
    canonical = canonicalize_url(url)
    if canonical.has_userinfo:
        raise UrlValidationError(
            code="userinfo_not_allowed", message="userinfo in url is not allowed"
        )
    validate_public_https_url(
        canonical.canonical, block_private_networks=block_private_networks
    )
    return canonical


def download_url(
    url: str,
    *,
    max_download_bytes: int = MAX_DOWNLOAD_BYTES,
    request_timeout: float = REQUEST_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    block_private_networks: bool = BLOCK_PRIVATE_NETWORKS,
    max_headers: int = WEB_MAX_HEADERS,
    max_header_value_len: int = WEB_MAX_HEADER_VALUE_LEN,
) -> tuple[bytes, int, dict]:
    session = requests.Session()
    current = url
    redirects: list[dict] = []

    try:
        for _hop in range(max_redirects + 1):
            canonical = validate_url_for_download(
                current, block_private_networks=block_private_networks
            )
            request_url = canonical.canonical

            with session.get(
                request_url,
                timeout=request_timeout,
                stream=True,
                allow_redirects=False,
            ) as resp:
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location")
                    if not location:
                        raise ValueError("redirect without Location header")
                    next_url = urljoin(request_url, location)
                    redirects.append(
                        {
                            "from": request_url,
                            "to": next_url,
                            "status_code": resp.status_code,
                        }
                    )
                    current = next_url
                    continue

                resp.raise_for_status()
                buf = bytearray()
                content_type = (resp.headers.get("Content-Type") or "").strip()
                content_length = (resp.headers.get("Content-Length") or "").strip()
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    buf.extend(chunk)
                    if len(buf) > max_download_bytes:
                        raise ValueError("content too large")

                # Response headers/cookies (sanitized) for UI analysis.
                response_headers: list[dict] = []
                response_header_names: list[str] = []
                try:
                    seen_names: set[str] = set()
                    for k in resp.headers.keys():
                        name = str(k or "").strip().lower()
                        if not name or name == "set-cookie":
                            continue
                        if name in seen_names:
                            continue
                        seen_names.add(name)
                        response_header_names.append(name)
                    for k, v in resp.headers.items():
                        name = str(k or "").strip().lower()
                        if not name or name == "set-cookie":
                            continue
                        val = str(v or "").strip()
                        if val and len(val) > max(0, int(max_header_value_len)):
                            val = val[: max(0, int(max_header_value_len) - 3)] + "..."
                        response_headers.append({"name": name, "value": val})
                        if len(response_headers) >= max(1, int(max_headers)):
                            break
                except Exception:
                    response_headers = []
                    response_header_names = []

                set_cookie_raw: list[str] = []
                try:
                    raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
                    if raw_headers is not None and hasattr(raw_headers, "getlist"):
                        set_cookie_raw = [
                            str(x) for x in raw_headers.getlist("Set-Cookie") if x
                        ]
                    elif raw_headers is not None and hasattr(raw_headers, "get_all"):
                        set_cookie_raw = [
                            str(x) for x in raw_headers.get_all("Set-Cookie") if x
                        ]
                except Exception:
                    set_cookie_raw = []
                if not set_cookie_raw:
                    sc = resp.headers.get("Set-Cookie")
                    if isinstance(sc, str) and sc.strip():
                        set_cookie_raw = [sc.strip()]

                cookies = parse_set_cookie_headers(set_cookie_raw)
                download_info = {
                    "requested_url": url,
                    "final_url": request_url,
                    "redirects": redirects,
                    "status_code": int(resp.status_code),
                }
                if content_type:
                    download_info["content_type"] = content_type
                if content_length:
                    download_info["content_length"] = content_length
                if response_headers:
                    download_info["response_headers"] = response_headers
                if response_header_names:
                    download_info["response_header_names"] = response_header_names
                if cookies:
                    download_info["cookies"] = cookies
                return bytes(buf), len(buf), download_info

        raise ValueError("too many redirects")
    finally:
        try:
            session.close()
        except Exception:
            pass
