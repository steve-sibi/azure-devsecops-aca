from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import parse_qsl, urljoin, urlparse


def _truncate(value: str, *, max_len: int) -> str:
    text = value or ""
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _safe_str(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _is_http_url(url: str) -> bool:
    try:
        scheme = urlparse(url).scheme.lower()
    except Exception:
        return False
    return scheme in ("http", "https")


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip().lower().rstrip(".")
    except Exception:
        return ""


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def classify_internal_external(*, resource_url: str, page_host: str) -> str:
    host = _url_host(resource_url)
    if not host:
        return "internal"
    if not page_host:
        return "external"
    return "internal" if host == page_host else "external"


def _safe_urljoin(base_url: str, maybe_url: str) -> str:
    raw = (maybe_url or "").strip()
    if not raw:
        return ""
    if raw.startswith("#"):
        return ""
    lowered = raw.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return ""
    try:
        return urljoin(base_url, raw)
    except Exception:
        return ""


_TRACKING_HOST_HINTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "doubleclick.net",
    "facebook.net",
    "connect.facebook.net",
    "analytics.twitter.com",
    "cdn.segment.com",
    "static.hotjar.com",
    "script.hotjar.com",
    "mixpanel.com",
    "stats.g.doubleclick.net",
    "snap.licdn.com",
)

_TRACKING_PATH_HINTS = (
    "gtag/js",
    "analytics.js",
    "fbevents.js",
    "pixel.js",
    "matomo.js",
)

_FINGERPRINTING_HINTS = (
    "fingerprintjs",
    "fp.min.js",
    "audioContext".lower(),
    "offlineaudiocontext",
    "webglrenderingcontext",
    "getimagedata",
    "todataurl",
    "navigator.plugins",
    "navigator.hardwareconcurrency",
    "navigator.devicememory",
    "canvas",
)

_SUSPICIOUS_JS_HINTS = (
    "activeXObject".lower(),
    "wscript.",
    "powershell",
    "cmd.exe",
    "mshta",
    "rundll32",
    "regsvr32",
    "document.write(",
    "unescape(",
    "fromcharcode",
    "atob(",
    "eval(",
    "new function(",
)

_EVAL_HINTS = ("eval(", "new function(")
_INNER_HTML_HINTS = ("innerhtml", "outerhtml")

_OPEN_REDIRECT_PARAM_HINTS = {
    "redirect",
    "redir",
    "next",
    "url",
    "return",
    "return_url",
    "returnurl",
    "continue",
    "dest",
    "destination",
    "goto",
    "to",
    "forward",
    "callback",
}


def parse_set_cookie_headers(
    set_cookie_headers: list[str], *, max_cookies: int = 50
) -> list[dict]:
    cookies: list[dict] = []
    for raw in set_cookie_headers or []:
        if not isinstance(raw, str):
            continue
        c = _parse_set_cookie(raw)
        if c:
            cookies.append(c)
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


@dataclass
class ParsedPage:
    title: str
    links: list[dict]
    images: list[dict]
    scripts: list[dict]
    styles: list[dict]
    form_actions: list[str]
    password_fields: int
    login_forms: int
    csrf_protection: bool
    external_scripts: int
    suspicious_scripts: int
    suspicious_api_calls: bool
    mixed_content: list[str]
    tracking_scripts: bool
    fingerprinting: bool
    eval_usage: bool
    inner_html_usage: bool


class _PageHTMLParser(HTMLParser):
    def __init__(
        self,
        *,
        base_url: str,
        page_host: str,
        max_items: int,
        max_inline_script_chars: int,
    ):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page_host = page_host
        self.max_items = max(1, int(max_items))
        self.max_inline_script_chars = max(1, int(max_inline_script_chars))

        self._in_a = False
        self._a_href = ""
        self._a_text_parts: list[str] = []

        self._in_title = False
        self._title_parts: list[str] = []

        self._in_script = False
        self._script_text_parts: list[str] = []

        self._in_form = False
        self._form_has_password = False

        self.links: list[dict] = []
        self.images: list[dict] = []
        self.scripts: list[dict] = []
        self.styles: list[dict] = []
        self.form_actions: list[str] = []

        self.password_fields = 0
        self.login_forms = 0
        self.csrf_protection = False

        self.external_scripts = 0
        self.suspicious_scripts = 0
        self.suspicious_api_calls = False
        self.mixed_content: list[str] = []
        self.tracking_scripts = False
        self.fingerprinting = False
        self.eval_usage = False
        self.inner_html_usage = False

    def _maybe_add_mixed(self, url: str) -> None:
        if url.startswith("http://") and len(self.mixed_content) < 20:
            self.mixed_content.append(url)

    def handle_starttag(self, tag: str, attrs) -> None:
        t = (tag or "").lower()
        a = {k.lower(): v for (k, v) in attrs if k}

        if t == "base":
            href = a.get("href") or ""
            resolved = _safe_urljoin(self.base_url, href)
            if resolved:
                self.base_url = resolved
            return

        if t == "title":
            self._in_title = True
            return

        if t == "a":
            href = a.get("href") or ""
            resolved = _safe_urljoin(self.base_url, href)
            if resolved and _is_http_url(resolved) and len(self.links) < self.max_items:
                self._in_a = True
                self._a_href = resolved
                self._a_text_parts = []
            return

        if t == "img":
            src = a.get("src") or a.get("data-src") or ""
            if not src and isinstance(a.get("srcset"), str):
                src = (a.get("srcset") or "").split(",", 1)[0].strip().split(" ", 1)[0]
            resolved = _safe_urljoin(self.base_url, src)
            if (
                resolved
                and _is_http_url(resolved)
                and len(self.images) < self.max_items
            ):
                self.images.append(
                    {
                        "url": resolved,
                        "type": classify_internal_external(
                            resource_url=resolved, page_host=self.page_host
                        ),
                    }
                )
                self._maybe_add_mixed(resolved)
            return

        if t == "script":
            src = a.get("src") or ""
            if src:
                resolved = _safe_urljoin(self.base_url, src)
                if (
                    resolved
                    and _is_http_url(resolved)
                    and len(self.scripts) < self.max_items
                ):
                    rtype = classify_internal_external(
                        resource_url=resolved, page_host=self.page_host
                    )
                    self.scripts.append({"url": resolved, "type": rtype})
                    self._maybe_add_mixed(resolved)
                    if rtype == "external":
                        self.external_scripts += 1

                    low = resolved.lower()
                    host = _url_host(resolved)
                    if host and any(h in host for h in _TRACKING_HOST_HINTS):
                        self.tracking_scripts = True
                    if any(p in low for p in _TRACKING_PATH_HINTS):
                        self.tracking_scripts = True
                    if any(h in low for h in _FINGERPRINTING_HINTS):
                        self.fingerprinting = True
                    if _is_ip_host(host):
                        self.suspicious_scripts += 1
                return

            # Inline script
            self._in_script = True
            self._script_text_parts = []
            return

        if t == "link":
            rel = (a.get("rel") or "").lower()
            if "stylesheet" in rel:
                href = a.get("href") or ""
                resolved = _safe_urljoin(self.base_url, href)
                if (
                    resolved
                    and _is_http_url(resolved)
                    and len(self.styles) < self.max_items
                ):
                    self.styles.append(
                        {
                            "url": resolved,
                            "type": classify_internal_external(
                                resource_url=resolved, page_host=self.page_host
                            ),
                        }
                    )
                    self._maybe_add_mixed(resolved)
            return

        if t == "form":
            self._in_form = True
            self._form_has_password = False
            action = a.get("action") or ""
            resolved = _safe_urljoin(self.base_url, action) if action else ""
            if resolved and _is_http_url(resolved) and len(self.form_actions) < 50:
                self.form_actions.append(resolved)
            return

        if t == "input":
            typ = (a.get("type") or "").lower()
            if typ == "password":
                self.password_fields += 1
                if self._in_form:
                    self._form_has_password = True
            if typ == "hidden":
                n = (a.get("name") or a.get("id") or "").lower()
                if "csrf" in n or "xsrf" in n:
                    self.csrf_protection = True
            return

        if t == "meta":
            n = (a.get("name") or "").lower()
            if ("csrf" in n or "xsrf" in n) and a.get("content"):
                self.csrf_protection = True
            return

    def handle_endtag(self, tag: str) -> None:
        t = (tag or "").lower()
        if t == "a" and self._in_a:
            text = " ".join(p.strip() for p in self._a_text_parts if p.strip())
            self.links.append(
                {
                    "url": self._a_href,
                    "text": _truncate(text, max_len=120),
                    "type": classify_internal_external(
                        resource_url=self._a_href, page_host=self.page_host
                    ),
                }
            )
            self._in_a = False
            self._a_href = ""
            self._a_text_parts = []
            return

        if t == "title":
            self._in_title = False
            return

        if t == "script" and self._in_script:
            script_text = "".join(self._script_text_parts)
            low = script_text.lower()
            if any(h in low for h in _SUSPICIOUS_JS_HINTS):
                self.suspicious_scripts += 1
            if any(h in low for h in _SUSPICIOUS_JS_HINTS):
                self.suspicious_api_calls = True
            if any(h in low for h in _EVAL_HINTS):
                self.eval_usage = True
            if any(h in low for h in _INNER_HTML_HINTS):
                self.inner_html_usage = True
            if any(h in low for h in _FINGERPRINTING_HINTS):
                self.fingerprinting = True
            if any(h in low for h in ("gtag(", "ga(", "fbq(", "dataLayer".lower())):
                self.tracking_scripts = True
            self._in_script = False
            self._script_text_parts = []
            return

        if t == "form" and self._in_form:
            if self._form_has_password:
                self.login_forms += 1
            self._in_form = False
            self._form_has_password = False
            return

    def handle_data(self, data: str) -> None:
        if not data:
            return
        if self._in_title and len(self._title_parts) < 50:
            self._title_parts.append(data)
            return
        if self._in_a:
            if len(self._a_text_parts) < 50:
                self._a_text_parts.append(data)
            return
        if self._in_script:
            current_len = sum(len(p) for p in self._script_text_parts)
            if current_len < self.max_inline_script_chars:
                remaining = self.max_inline_script_chars - current_len
                self._script_text_parts.append(data[:remaining])
            return

    def parsed(self) -> ParsedPage:
        title = _truncate(" ".join(p.strip() for p in self._title_parts if p.strip()), max_len=140)
        return ParsedPage(
            title=title,
            links=self.links,
            images=self.images,
            scripts=self.scripts,
            styles=self.styles,
            form_actions=self.form_actions,
            password_fields=int(self.password_fields),
            login_forms=int(self.login_forms),
            csrf_protection=bool(self.csrf_protection),
            external_scripts=int(self.external_scripts),
            suspicious_scripts=int(self.suspicious_scripts),
            suspicious_api_calls=bool(self.suspicious_api_calls),
            mixed_content=list(self.mixed_content),
            tracking_scripts=bool(self.tracking_scripts),
            fingerprinting=bool(self.fingerprinting),
            eval_usage=bool(self.eval_usage),
            inner_html_usage=bool(self.inner_html_usage),
        )


def analyze_html(
    html: str,
    *,
    base_url: str,
    max_items: int = 200,
    max_inline_script_chars: int = 80_000,
) -> ParsedPage:
    page_host = _url_host(base_url)
    parser = _PageHTMLParser(
        base_url=base_url,
        page_host=page_host,
        max_items=max_items,
        max_inline_script_chars=max_inline_script_chars,
    )
    try:
        parser.feed(html)
    except Exception:
        # Best-effort parse; ignore malformed HTML.
        pass
    return parser.parsed()


def find_open_redirects(
    urls: list[str], *, page_host: str, max_examples: int = 5
) -> dict:
    examples: list[str] = []
    for raw in urls or []:
        if not isinstance(raw, str) or not raw:
            continue
        try:
            parsed = urlparse(raw)
        except Exception:
            continue
        if not parsed.query:
            continue
        params = parse_qsl(parsed.query, keep_blank_values=True)
        for key, val in params:
            k = (key or "").strip().lower()
            if k not in _OPEN_REDIRECT_PARAM_HINTS:
                continue
            v = (val or "").strip()
            if not v:
                continue
            if v.lower().startswith(("http://", "https://")):
                dest_host = _url_host(v)
                if dest_host and page_host and dest_host != page_host:
                    examples.append(_truncate(raw, max_len=300))
                    break
        if len(examples) >= max_examples:
            break
    return {"detected": bool(examples), "examples": examples}


def resolve_dns_addresses(host: str, *, max_addresses: int = 10) -> list[str]:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return []
    out: list[str] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(h, None)
    except Exception:
        return []
    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if not isinstance(ip, str) or not ip:
            continue
        if ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
        if len(out) >= max(1, int(max_addresses)):
            break
    return out


def rdap_whois(domain: str, *, timeout_seconds: float = 3.0) -> Optional[dict]:
    d = (domain or "").strip().lower().rstrip(".")
    if not d or _is_ip_host(d):
        return None
    url = f"https://rdap.org/domain/{d}"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "aca-url-scanner/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=max(0.5, float(timeout_seconds))) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if int(getattr(e, "code", 0) or 0) == 404:
            return None
        return {"error": _safe_str(e)}
    except Exception as e:
        return {"error": _safe_str(e)}

    try:
        doc = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"error": "rdap_parse_failed"}
    if not isinstance(doc, dict):
        return {"error": "rdap_unexpected_payload"}

    registrar = None
    entities = doc.get("entities")
    if isinstance(entities, list):
        for ent in entities:
            if not isinstance(ent, dict):
                continue
            roles = ent.get("roles")
            if not isinstance(roles, list) or "registrar" not in [str(r).lower() for r in roles if r]:
                continue
            vcard = ent.get("vcardArray")
            if (
                isinstance(vcard, list)
                and len(vcard) == 2
                and isinstance(vcard[1], list)
            ):
                for item in vcard[1]:
                    if not isinstance(item, list) or len(item) < 4:
                        continue
                    if str(item[0]).lower() == "fn":
                        registrar = _safe_str(item[3]).strip() or registrar
                        break
            registrar = registrar or _safe_str(ent.get("handle")).strip() or registrar
            if registrar:
                break

    creation = None
    expiration = None
    events = doc.get("events")
    if isinstance(events, list):
        for ev in events:
            if not isinstance(ev, dict):
                continue
            action = _safe_str(ev.get("eventAction")).strip().lower()
            date = _safe_str(ev.get("eventDate")).strip()
            if not date:
                continue
            if action == "registration" and not creation:
                creation = date
            elif action == "expiration" and not expiration:
                expiration = date

    out: dict = {}
    if registrar:
        out["registrar"] = registrar
    if creation:
        out["creation_date"] = creation
    if expiration:
        out["expiration_date"] = expiration
    return out or None


def registrable_domain(host: str) -> str:
    # Best-effort eTLD+1 extraction without PSL dependency.
    h = (host or "").strip().lower().rstrip(".")
    labels = [p for p in h.split(".") if p]
    if len(labels) < 2:
        return h

    public_suffix_2 = {
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "co.in",
        "com.br",
        "com.mx",
        "co.nz",
        "com.sg",
    }
    last2 = ".".join(labels[-2:])
    if len(labels) >= 3 and last2 in public_suffix_2:
        return ".".join(labels[-3:])
    return last2
