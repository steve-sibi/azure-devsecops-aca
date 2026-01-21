from __future__ import annotations

from typing import Optional


def parse_set_cookie_headers(
    set_cookie_headers: list[str], *, max_cookies: int = 50
) -> list[dict]:
    cookies: list[dict] = []
    for raw in set_cookie_headers or []:
        if not isinstance(raw, str):
            continue
        cookie = _parse_set_cookie(raw)
        if cookie:
            cookies.append(cookie)
        if len(cookies) >= max_cookies:
            break
    return cookies


def _parse_set_cookie(header_value: str) -> Optional[dict]:
    parts = [p.strip() for p in (header_value or "").split(";") if p.strip()]
    if not parts:
        return None
    if "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None

    secure = False
    httponly = False
    samesite: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None
    expires: Optional[str] = None
    max_age: Optional[str] = None

    for attr in parts[1:]:
        low = attr.lower()
        if low == "secure":
            secure = True
            continue
        if low == "httponly":
            httponly = True
            continue
        if "=" not in attr:
            continue
        key, val = attr.split("=", 1)
        k = key.strip().lower()
        v = val.strip()
        if not k:
            continue
        if k == "samesite":
            samesite = v
        elif k == "domain":
            domain = v
        elif k == "path":
            path = v
        elif k == "expires":
            expires = v
        elif k == "max-age":
            max_age = v

    issues: list[str] = []
    if not secure:
        issues.append("Missing Secure")
    if samesite and samesite.strip().lower() == "none" and not secure:
        issues.append("SameSite=None without Secure")

    out: dict = {
        "name": name,
        "secure": bool(secure),
        "httponly": bool(httponly),
    }
    if samesite:
        out["samesite"] = samesite
    if domain:
        out["domain"] = domain
    if path:
        out["path"] = path
    if expires:
        out["expires"] = expires
    if max_age:
        out["max_age"] = max_age
    if issues:
        out["issues"] = issues
    return out

