from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import unicodedata
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import parse_qsl

from common.signals import Signal, signal
from common.url_canonicalization import CanonicalUrl

DEFAULT_RULES_PATH = Path(__file__).with_name("url_heuristics_rules.json")


class HeuristicsRuleError(ValueError):
    pass


def _read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_rules(path: Path = DEFAULT_RULES_PATH) -> list[dict[str, Any]]:
    doc = _read_json(path)
    if not isinstance(doc, list):
        raise HeuristicsRuleError("rules file must be a JSON array")
    rules: list[dict[str, Any]] = []
    for item in doc:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        match = item.get("match")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(match, dict) or not isinstance(match.get("type"), str):
            continue
        rules.append(item)
    return rules


def _shannon_entropy(value: str) -> float:
    s = value or ""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def _detect_script(ch: str) -> str:
    # Approximate script detection for homoglyph risk. Focus on common confusable scripts.
    if not ch or ch in ".-":
        return "none"
    if "0" <= ch <= "9":
        return "digit"
    o = ord(ch)
    if ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
        return "latin"
    # Greek
    if 0x0370 <= o <= 0x03FF:
        return "greek"
    # Cyrillic
    if 0x0400 <= o <= 0x04FF or 0x0500 <= o <= 0x052F:
        return "cyrillic"
    # Latin extended (treat as latin)
    if 0x00C0 <= o <= 0x024F:
        return "latin"
    # Common CJK blocks
    if 0x4E00 <= o <= 0x9FFF:
        return "han"
    if 0x3040 <= o <= 0x309F:
        return "hiragana"
    if 0x30A0 <= o <= 0x30FF:
        return "katakana"
    if 0xAC00 <= o <= 0xD7AF:
        return "hangul"
    # Arabic
    if 0x0600 <= o <= 0x06FF:
        return "arabic"
    # Fallback: use unicode category to ignore combining marks.
    cat = unicodedata.category(ch)
    if cat.startswith("M"):
        return "mark"
    return "other"


def _mixed_script_host(host_unicode: str) -> bool:
    scripts: set[str] = set()
    for ch in host_unicode or "":
        script = _detect_script(ch)
        if script in ("none", "digit", "mark"):
            continue
        scripts.add(script)
        if len(scripts) >= 2:
            # Mixed-script: include latin + any non-latin, or multiple non-latin.
            if "latin" in scripts and any(s != "latin" for s in scripts):
                return True
            if "latin" not in scripts and len(scripts) >= 2:
                return True
    return False


_HEX_INT_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_DEC_INT_RE = re.compile(r"^[0-9]{1,20}$")


def _try_parse_encoded_ipv4(host: str) -> tuple[Optional[ipaddress.IPv4Address], Optional[str]]:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return None, None

    # Single integer forms: decimal or hex.
    if _HEX_INT_RE.match(h):
        try:
            val = int(h, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), "hex-int"
        except Exception:
            return None, None
    if _DEC_INT_RE.match(h):
        try:
            val = int(h, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), "dec-int"
        except Exception:
            return None, None

    # Dotted forms with octal/hex segments.
    if "." in h:
        parts = h.split(".")
        if len(parts) != 4:
            return None, None
        parsed: list[int] = []
        kind = None
        for part in parts:
            part = part.strip()
            if not part:
                return None, None
            base = 10
            if part.startswith("0x") and _HEX_INT_RE.match(part):
                base = 16
                kind = kind or "hex-dotted"
            elif len(part) > 1 and part.startswith("0") and part.isdigit():
                base = 8
                kind = kind or "octal-dotted"
            elif not part.isdigit():
                return None, None
            try:
                val = int(part, base)
            except Exception:
                return None, None
            if not (0 <= val <= 255):
                return None, None
            parsed.append(val)
        if kind:
            return ipaddress.IPv4Address(bytes(parsed)), kind
    return None, None


def _registrable_domain(host_punycode: str) -> str:
    # Best-effort eTLD+1 extraction without external PSL dependency.
    host = (host_punycode or "").strip().lower().rstrip(".")
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2:
        return host

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


def _query_param_names(query: str) -> set[str]:
    out: set[str] = set()
    for key, _val in parse_qsl(query or "", keep_blank_values=True):
        if not key:
            continue
        out.add(str(key).strip().lower())
    return out


@dataclass(frozen=True)
class HeuristicsResult:
    score: int
    suspicious_threshold: int
    malicious_threshold: int
    matched_rules: list[dict[str, Any]]
    signals: list[Signal]

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": int(self.score),
            "suspicious_threshold": int(self.suspicious_threshold),
            "malicious_threshold": int(self.malicious_threshold),
            "matched_rules": list(self.matched_rules),
            "signals": [s.as_dict() for s in self.signals],
        }


def evaluate_url_heuristics(
    canonical: CanonicalUrl,
    *,
    rules: Optional[Iterable[Mapping[str, Any]]] = None,
    rules_path: Path = DEFAULT_RULES_PATH,
    suspicious_threshold: Optional[int] = None,
    malicious_threshold: Optional[int] = None,
    env: Optional[Mapping[str, str]] = None,
) -> HeuristicsResult:
    env = env or os.environ
    rules_in = list(rules) if rules is not None else load_rules(rules_path)

    if malicious_threshold is None:
        malicious_threshold = int(env.get("REPUTATION_MIN_SCORE", "60") or "60")
    if suspicious_threshold is None:
        suspicious_threshold = int(
            env.get("REPUTATION_SUSPICIOUS_SCORE", str(max(1, int(malicious_threshold / 2))))
        )

    host_unicode = canonical.host_unicode or ""
    host_punycode = canonical.host_punycode or ""
    tld = host_punycode.rsplit(".", 1)[-1] if "." in host_punycode else host_punycode
    reg_domain = _registrable_domain(host_punycode)

    params = _query_param_names(canonical.query)
    url_len = len(canonical.canonical)

    signals: list[Signal] = []
    matched: list[dict[str, Any]] = []
    score = 0

    for rule in rules_in:
        if not isinstance(rule, Mapping):
            continue
        name = str(rule.get("name") or "").strip()
        if not name:
            continue
        match = rule.get("match")
        if not isinstance(match, Mapping):
            continue
        mtype = str(match.get("type") or "").strip()
        if not mtype:
            continue

        points = int(rule.get("points") or 0)
        if points < 0:
            points = 0
        severity = str(rule.get("severity") or "info").strip().lower()
        verdict = str(rule.get("verdict") or "suspicious").strip().lower()
        description = str(rule.get("description") or "").strip()

        evidence: dict[str, Any] = {"rule": name}
        if description:
            evidence["description"] = description
        matched_rule = False

        if mtype == "userinfo_present":
            matched_rule = bool(canonical.has_userinfo)

        elif mtype == "ip_literal_host":
            try:
                ipaddress.ip_address(host_punycode)
                matched_rule = True
            except ValueError:
                matched_rule = False

        elif mtype == "ip_encoded_host":
            ip, kind = _try_parse_encoded_ipv4(host_punycode)
            if ip is not None and kind:
                matched_rule = True
                evidence["parsed_ip"] = str(ip)
                evidence["encoding"] = kind

        elif mtype == "subdomain_count_gte":
            min_labels = int(match.get("min_labels") or 0)
            labels = [p for p in host_punycode.split(".") if p]
            if min_labels > 0 and len(labels) >= min_labels:
                matched_rule = True
                evidence["label_count"] = len(labels)
                evidence["min_labels"] = min_labels

        elif mtype == "punycode_label":
            labels = [p for p in host_punycode.split(".") if p]
            if any(l.startswith("xn--") for l in labels):
                matched_rule = True

        elif mtype == "mixed_script_host":
            matched_rule = _mixed_script_host(host_unicode)

        elif mtype == "entropy_gte":
            target = str(match.get("target") or "").strip().lower()
            min_entropy = float(match.get("min_entropy") or 0.0)
            min_length = int(match.get("min_length") or 0)

            if target == "host":
                sample = host_unicode.replace(".", "").replace("-", "")
            elif target == "path":
                sample = (canonical.path or "").strip("/")
            else:
                sample = ""
            if sample and len(sample) >= min_length:
                ent = _shannon_entropy(sample)
                if ent >= min_entropy:
                    matched_rule = True
                    evidence["entropy"] = round(ent, 3)
                    evidence["min_entropy"] = min_entropy
                    evidence["length"] = len(sample)
                    evidence["min_length"] = min_length

        elif mtype == "brand_keyword_mismatch":
            keyword = str(match.get("keyword") or "").strip().lower()
            allow = match.get("allowed_registrable_domains")
            allowed = [str(x).strip().lower() for x in allow] if isinstance(allow, list) else []
            if keyword and keyword in host_unicode.lower():
                if not any(reg_domain == a or reg_domain.endswith("." + a) for a in allowed):
                    matched_rule = True
                    evidence["keyword"] = keyword
                    evidence["registrable_domain"] = reg_domain
                    if allowed:
                        evidence["allowed"] = allowed[:25]

        elif mtype == "tld_in":
            tlds = match.get("tlds")
            tlds_env = str(match.get("tlds_env") or "").strip()
            values: list[str] = []
            if tlds_env:
                raw = str(env.get(tlds_env, "") or "")
                if raw.strip():
                    values = [p.strip().lower() for p in raw.split(",") if p.strip()]
            if not values and isinstance(tlds, list):
                values = [str(x).strip().lower() for x in tlds if str(x).strip()]
            if values and tld in set(values):
                matched_rule = True
                evidence["tld"] = tld

        elif mtype == "query_param_in":
            names = match.get("names")
            values = (
                [str(x).strip().lower() for x in names if str(x).strip()]
                if isinstance(names, list)
                else []
            )
            hit = next((n for n in values if n in params), "")
            if hit:
                matched_rule = True
                evidence["param"] = hit

        elif mtype == "url_length_gte":
            min_len = int(match.get("min_length") or 0)
            if min_len > 0 and url_len >= min_len:
                matched_rule = True
                evidence["length"] = url_len
                evidence["min_length"] = min_len

        elif mtype == "path_length_gte":
            min_len = int(match.get("min_length") or 0)
            path_len = len(canonical.path or "")
            if min_len > 0 and path_len >= min_len:
                matched_rule = True
                evidence["length"] = path_len
                evidence["min_length"] = min_len

        elif mtype == "query_length_gte":
            min_len = int(match.get("min_length") or 0)
            q_len = len(canonical.query or "")
            if min_len > 0 and q_len >= min_len:
                matched_rule = True
                evidence["length"] = q_len
                evidence["min_length"] = min_len

        elif mtype == "path_extension_in":
            exts = match.get("extensions")
            values = (
                [str(x).strip().lower().lstrip(".") for x in exts if str(x).strip()]
                if isinstance(exts, list)
                else []
            )
            lower_path = (canonical.path or "").lower()
            hit_ext = next((ext for ext in values if lower_path.endswith("." + ext)), "")
            if hit_ext:
                matched_rule = True
                evidence["extension"] = "." + hit_ext

        if not matched_rule:
            continue

        score += points
        matched.append({"name": name, "points": points, "severity": severity, "evidence": evidence})

        signals.append(
            signal(
                source=f"heuristics.{name}",
                verdict=verdict,
                severity=severity,
                weight=points,
                evidence={**evidence, "reason": description or f"heuristic rule matched: {name}"},
                ttl=None,
            )
        )

    verdict: str
    if score >= int(malicious_threshold):
        verdict = "malicious"
        sev = "high"
    elif score >= int(suspicious_threshold):
        verdict = "suspicious"
        sev = "medium"
    else:
        verdict = "benign"
        sev = "info"

    signals.append(
        signal(
            source="heuristics.score",
            verdict=verdict,
            severity=sev,
            weight=int(score),
            evidence={
                "score": int(score),
                "suspicious_threshold": int(suspicious_threshold),
                "malicious_threshold": int(malicious_threshold),
                "matched_rule_count": len(matched),
                "reason": f"heuristics score={score} (suspicious≥{suspicious_threshold}, malicious≥{malicious_threshold})",
            },
            ttl=None,
        )
    )

    return HeuristicsResult(
        score=int(score),
        suspicious_threshold=int(suspicious_threshold),
        malicious_threshold=int(malicious_threshold),
        matched_rules=matched,
        signals=signals,
    )
