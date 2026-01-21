from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

from common.http_parsing import parse_set_cookie_headers

try:
    from adblockparser import AdblockRules
except Exception:  # pragma: no cover
    AdblockRules = None  # type: ignore[assignment]

try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None  # type: ignore[assignment]

try:
    import yara
except Exception:  # pragma: no cover
    yara = None  # type: ignore[assignment]


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
    if host == page_host:
        return "internal"
    try:
        return (
            "internal"
            if registrable_domain(host) == registrable_domain(page_host)
            else "external"
        )
    except Exception:
        return "external"


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


_API_CALL_HINTS = (
    "fetch(",
    "xmlhttprequest",
    "sendbeacon(",
    "navigator.sendbeacon",
    "websocket(",
    "new websocket(",
    "eventsource(",
    "new eventsource(",
)

_ABSOLUTE_URL_RE = re.compile(r"(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)

_DEFAULT_TRACKING_FILTERS = Path(__file__).with_name("tracking_filters.txt")
_DEFAULT_WEB_YARA_RULES = Path(__file__).with_name("web_yara_rules.yar")


@lru_cache(maxsize=1)
def _tld_extractor():
    if tldextract is None:  # pragma: no cover
        return None
    cache_dir = os.getenv("TLD_EXTRACT_CACHE_DIR", "/tmp/tldextract-cache")
    try:
        return tldextract.TLDExtract(
            cache_dir=cache_dir,
            suffix_list_urls=None,
        )
    except Exception:
        try:
            return tldextract.TLDExtract(suffix_list_urls=None)
        except Exception:
            return None


@lru_cache(maxsize=1)
def _tracking_rules():
    if AdblockRules is None:  # pragma: no cover
        return None
    rules_path = os.getenv("WEB_TRACKING_FILTERS_PATH", "")
    path = Path(rules_path) if rules_path.strip() else _DEFAULT_TRACKING_FILTERS
    try:
        raw = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        raw = []
    raw = [line.strip() for line in raw if line and isinstance(line, str)]
    raw = [line for line in raw if line and not line.lstrip().startswith(("!", "#"))]
    if not raw:
        return None
    try:
        return AdblockRules(raw, use_re2=False)  # type: ignore[misc]
    except Exception:
        return None


@lru_cache(maxsize=1)
def _web_yara_rules():
    if yara is None:  # pragma: no cover
        return None
    rules_path = os.getenv("WEB_YARA_RULES_PATH", "")
    path = Path(rules_path) if rules_path.strip() else _DEFAULT_WEB_YARA_RULES
    if not path.exists():
        return None
    try:
        return yara.compile(filepath=str(path))
    except Exception:
        return None


def _yara_rule_names(text: str) -> set[str]:
    rules = _web_yara_rules()
    if rules is None:
        return set()
    payload = (text or "").strip()
    if not payload:
        return set()
    try:
        matches = rules.match(data=payload)
    except Exception:
        try:
            matches = rules.match(data=payload.encode("utf-8", "ignore"))
        except Exception:
            return set()
    names: set[str] = set()
    for m in matches or []:
        rule = getattr(m, "rule", None) or getattr(m, "name", None)
        if rule:
            names.add(str(rule))
    return names


def _is_tracking_resource(resource_url: str, *, page_host: str, kind: str) -> bool:
    rules = _tracking_rules()
    if rules is None:
        return False
    host = _url_host(resource_url)
    third_party = False
    if host and page_host:
        third_party = registrable_domain(host) != registrable_domain(page_host)
    opts: dict[str, object] = {"domain": page_host, "third-party": bool(third_party)}
    k = (kind or "").strip().lower()
    if k == "script":
        opts["script"] = True
    elif k == "image":
        opts["image"] = True
    elif k in ("style", "stylesheet", "css"):
        opts["stylesheet"] = True
    try:
        return bool(rules.should_block(resource_url, opts))
    except Exception:
        return False

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


@dataclass
class ParsedPage:
    title: str
    description: str
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


def _first_srcset_url(srcset: str) -> str:
    if not isinstance(srcset, str):
        return ""
    first = srcset.split(",", 1)[0].strip()
    if not first:
        return ""
    return first.split(" ", 1)[0].strip()


def _maybe_add_mixed(mixed_content: list[str], url: str) -> None:
    if url.startswith("http://") and len(mixed_content) < 20:
        mixed_content.append(url)


def analyze_html(
    html: str,
    *,
    base_url: str,
    max_items: int = 200,
    max_inline_script_chars: int = 80_000,
) -> ParsedPage:
    page_host = _url_host(base_url)
    page_domain = registrable_domain(page_host)
    max_items = max(1, int(max_items))
    max_inline_script_chars = max(1, int(max_inline_script_chars))

    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception:
        return ParsedPage(
            title="",
            description="",
            links=[],
            images=[],
            scripts=[],
            styles=[],
            form_actions=[],
            password_fields=0,
            login_forms=0,
            csrf_protection=False,
            external_scripts=0,
            suspicious_scripts=0,
            suspicious_api_calls=False,
            mixed_content=[],
            tracking_scripts=False,
            fingerprinting=False,
            eval_usage=False,
            inner_html_usage=False,
        )

    # Honor <base href="..."> for URL resolution (best-effort; first occurrence wins).
    base_tag = soup.find("base", href=True)
    if base_tag:
        resolved = _safe_urljoin(base_url, str(base_tag.get("href") or ""))
        if resolved:
            base_url = resolved

    title = ""
    title_tag = soup.find("title")
    if title_tag:
        title = _truncate(title_tag.get_text(" ", strip=True), max_len=140)

    desc_by_key: dict[str, str] = {}
    description = ""

    links: list[dict] = []
    images: list[dict] = []
    scripts: list[dict] = []
    styles: list[dict] = []
    form_actions: list[str] = []

    password_fields = 0
    login_forms = 0
    csrf_protection = False

    external_scripts = 0
    suspicious_scripts = 0
    suspicious_api_calls = False
    mixed_content: list[str] = []
    tracking_scripts = False
    fingerprinting = False
    eval_usage = False
    inner_html_usage = False

    seen_links: set[str] = set()
    seen_images: set[str] = set()
    seen_scripts: set[str] = set()
    seen_styles: set[str] = set()

    # Links
    for tag in soup.find_all("a", href=True):
        if len(links) >= max_items:
            break
        href = str(tag.get("href") or "")
        resolved = _safe_urljoin(base_url, href)
        if not resolved or not _is_http_url(resolved):
            continue
        if resolved in seen_links:
            continue
        seen_links.add(resolved)
        text = tag.get_text(" ", strip=True)
        links.append(
            {
                "url": resolved,
                "text": _truncate(text, max_len=120),
                "type": classify_internal_external(
                    resource_url=resolved, page_host=page_host
                ),
            }
        )

    # Images
    for tag in soup.find_all("img"):
        if len(images) >= max_items:
            break
        src = str(tag.get("src") or tag.get("data-src") or "")
        if not src:
            srcset = tag.get("srcset")
            if isinstance(srcset, str):
                src = _first_srcset_url(srcset)
        resolved = _safe_urljoin(base_url, src)
        if not resolved or not _is_http_url(resolved):
            continue
        if resolved in seen_images:
            continue
        seen_images.add(resolved)
        images.append(
            {
                "url": resolved,
                "type": classify_internal_external(
                    resource_url=resolved, page_host=page_host
                ),
            }
        )
        _maybe_add_mixed(mixed_content, resolved)
        if _is_tracking_resource(resolved, page_host=page_host, kind="image"):
            tracking_scripts = True

    # <picture><source srcset="..."> (common for responsive images)
    for tag in soup.find_all("source"):
        if len(images) >= max_items:
            break
        if not tag.find_parent("picture"):
            typ = str(tag.get("type") or "").strip().lower()
            if not typ.startswith("image/"):
                continue
        src = str(tag.get("src") or "")
        if not src:
            srcset = tag.get("srcset")
            if isinstance(srcset, str):
                src = _first_srcset_url(srcset)
        resolved = _safe_urljoin(base_url, src)
        if not resolved or not _is_http_url(resolved):
            continue
        if resolved in seen_images:
            continue
        seen_images.add(resolved)
        images.append(
            {
                "url": resolved,
                "type": classify_internal_external(
                    resource_url=resolved, page_host=page_host
                ),
            }
        )
        _maybe_add_mixed(mixed_content, resolved)
        if _is_tracking_resource(resolved, page_host=page_host, kind="image"):
            tracking_scripts = True

    # Link-tag resources (stylesheets + preloads)
    for tag in soup.find_all("link", href=True):
        rel = tag.get("rel")
        rels: set[str] = set()
        if isinstance(rel, list):
            rels = {str(r or "").strip().lower() for r in rel if r}
        elif isinstance(rel, str):
            rels = {p.strip().lower() for p in rel.split() if p.strip()}
        if not rels:
            continue

        as_attr = str(tag.get("as") or "").strip().lower()
        href = str(tag.get("href") or "")
        resolved = _safe_urljoin(base_url, href)
        if not resolved or not _is_http_url(resolved):
            continue

        is_stylesheet = "stylesheet" in rels or ("preload" in rels and as_attr == "style")
        is_script = "modulepreload" in rels or ("preload" in rels and as_attr == "script")
        is_image = "preload" in rels and as_attr == "image"

        if is_stylesheet and len(styles) < max_items and resolved not in seen_styles:
            seen_styles.add(resolved)
            styles.append(
                {
                    "url": resolved,
                    "type": classify_internal_external(
                        resource_url=resolved, page_host=page_host
                    ),
                }
            )
            _maybe_add_mixed(mixed_content, resolved)
            if _is_tracking_resource(resolved, page_host=page_host, kind="style"):
                tracking_scripts = True
            continue

        if is_script and len(scripts) < max_items and resolved not in seen_scripts:
            seen_scripts.add(resolved)
            rtype = classify_internal_external(resource_url=resolved, page_host=page_host)
            scripts.append({"url": resolved, "type": rtype})
            _maybe_add_mixed(mixed_content, resolved)
            if rtype == "external":
                external_scripts += 1
            if _is_tracking_resource(resolved, page_host=page_host, kind="script"):
                tracking_scripts = True
            yara_names = _yara_rule_names(resolved)
            if "Web_Fingerprinting_INFO" in yara_names:
                fingerprinting = True
            continue

        if is_image and len(images) < max_items and resolved not in seen_images:
            seen_images.add(resolved)
            images.append(
                {
                    "url": resolved,
                    "type": classify_internal_external(
                        resource_url=resolved, page_host=page_host
                    ),
                }
            )
            _maybe_add_mixed(mixed_content, resolved)
            if _is_tracking_resource(resolved, page_host=page_host, kind="image"):
                tracking_scripts = True

    # Scripts (external + inline heuristics)
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if isinstance(src, str) and src.strip():
            if len(scripts) >= max_items:
                continue
            resolved = _safe_urljoin(base_url, src)
            if not resolved or not _is_http_url(resolved):
                continue
            if resolved in seen_scripts:
                continue
            seen_scripts.add(resolved)
            rtype = classify_internal_external(resource_url=resolved, page_host=page_host)
            scripts.append({"url": resolved, "type": rtype})
            _maybe_add_mixed(mixed_content, resolved)
            if rtype == "external":
                external_scripts += 1

            host = _url_host(resolved)
            if host and _is_tracking_resource(resolved, page_host=page_host, kind="script"):
                tracking_scripts = True
            yara_names = _yara_rule_names(resolved)
            if "Web_Fingerprinting_INFO" in yara_names:
                fingerprinting = True
            if _is_ip_host(host):
                suspicious_scripts += 1
            continue

        script_text = (tag.get_text() or "")[:max_inline_script_chars]
        if not script_text:
            continue
        low = script_text.lower()

        yara_names = _yara_rule_names(script_text)
        if "Web_Suspicious_JS_MEDIUM" in yara_names:
            suspicious_scripts += 1
        if "Web_Fingerprinting_INFO" in yara_names:
            fingerprinting = True
        if "Web_Tracking_Inline_INFO" in yara_names:
            tracking_scripts = True
        if "Web_Eval_Usage_INFO" in yara_names:
            eval_usage = True
        if "Web_InnerHTML_Usage_INFO" in yara_names:
            inner_html_usage = True

        if any(h in low for h in _API_CALL_HINTS):
            for raw_url in _ABSOLUTE_URL_RE.findall(script_text):
                host = _url_host(raw_url)
                if not host:
                    continue
                if _is_ip_host(host):
                    suspicious_api_calls = True
                    break
                if page_domain and registrable_domain(host) != page_domain:
                    suspicious_api_calls = True
                    break

    # Forms and inputs
    for tag in soup.find_all("input"):
        typ = str(tag.get("type") or "").strip().lower()
        if typ == "password":
            password_fields += 1
        elif typ == "hidden":
            n = str(tag.get("name") or tag.get("id") or "").lower()
            if "csrf" in n or "xsrf" in n:
                csrf_protection = True

    for tag in soup.find_all("meta"):
        n = str(tag.get("name") or tag.get("property") or "").lower()
        if n in ("description", "og:description", "twitter:description"):
            content = str(tag.get("content") or "").strip()
            if content and n not in desc_by_key:
                desc_by_key[n] = _truncate(re.sub(r"\s+", " ", content), max_len=300)
        if ("csrf" in n or "xsrf" in n) and tag.get("content"):
            csrf_protection = True
    description = (
        desc_by_key.get("description")
        or desc_by_key.get("og:description")
        or desc_by_key.get("twitter:description")
        or ""
    )

    for tag in soup.find_all("form"):
        action = str(tag.get("action") or "").strip()
        if action:
            resolved = _safe_urljoin(base_url, action)
            if resolved and _is_http_url(resolved) and len(form_actions) < 50:
                form_actions.append(resolved)

        if tag.find("input", attrs={"type": re.compile(r"^password$", re.I)}):
            login_forms += 1

    return ParsedPage(
        title=title,
        description=description,
        links=links,
        images=images,
        scripts=scripts,
        styles=styles,
        form_actions=form_actions,
        password_fields=int(password_fields),
        login_forms=int(login_forms),
        csrf_protection=bool(csrf_protection),
        external_scripts=int(external_scripts),
        suspicious_scripts=int(suspicious_scripts),
        suspicious_api_calls=bool(suspicious_api_calls),
        mixed_content=list(mixed_content),
        tracking_scripts=bool(tracking_scripts),
        fingerprinting=bool(fingerprinting),
        eval_usage=bool(eval_usage),
        inner_html_usage=bool(inner_html_usage),
    )


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
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    if _is_ip_host(h):
        return h

    extractor = _tld_extractor()
    if extractor is not None:
        try:
            extracted = extractor(h)
            reg = str(getattr(extracted, "registered_domain", "") or "").strip().lower()
            if reg:
                return reg.rstrip(".")
        except Exception:
            pass

    # Best-effort eTLD+1 extraction without PSL dependency.
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
