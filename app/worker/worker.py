import json
import logging
import os
import re
import shutil
import signal as os_signal
import subprocess
import tempfile
import time
import hashlib
import struct
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urljoin

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableClient, TableServiceClient
from azure.core.exceptions import HttpResponseError

from common.result_store import upsert_result_sync
from common.signals import Signal, aggregate_signals, signal
from common.url_canonicalization import CanonicalUrl, canonicalize_url
from common.url_heuristics import HeuristicsResult, evaluate_url_heuristics
from common.url_validation import UrlValidationError, validate_public_https_url

# ---- Config via env ----
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "servicebus").strip().lower()
SERVICEBUS_CONN = os.getenv("SERVICEBUS_CONN")
QUEUE_NAME = os.getenv("QUEUE_NAME", "tasks")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "10"))
MAX_WAIT = int(os.getenv("MAX_WAIT", "5"))  # seconds
PREFETCH = int(os.getenv("PREFETCH", "20"))
MAX_RETRIES = int(
    os.getenv("MAX_RETRIES", "5")
)  # move to DLQ after this many deliveries
APPINSIGHTS_CONN = os.getenv("APPINSIGHTS_CONN")  # optional (opencensus)
RESULT_BACKEND = os.getenv("RESULT_BACKEND", "table").strip().lower()
RESULT_STORE_CONN = os.getenv("RESULT_STORE_CONN")
RESULT_TABLE = os.getenv("RESULT_TABLE", "scanresults")
RESULT_PARTITION = os.getenv("RESULT_PARTITION", "scan")
MAX_DOWNLOAD_BYTES = int(os.getenv("MAX_DOWNLOAD_BYTES", str(1024 * 1024)))  # 1MB
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))  # seconds
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "5"))
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() in (
    "1",
    "true",
    "yes",
)

# Local dev backends (Redis)
REDIS_URL = os.getenv("REDIS_URL")
REDIS_QUEUE_KEY = os.getenv("REDIS_QUEUE_KEY", f"queue:{QUEUE_NAME}")
REDIS_DLQ_KEY = os.getenv("REDIS_DLQ_KEY", f"dlq:{QUEUE_NAME}")
REDIS_RESULT_PREFIX = os.getenv("REDIS_RESULT_PREFIX", "scan:")
REDIS_RESULT_TTL_SECONDS = int(os.getenv("REDIS_RESULT_TTL_SECONDS", "0"))

# ---- Scan engine (ClamAV) ----
CLAMAV_HOST = os.getenv("CLAMAV_HOST")  # e.g. "127.0.0.1" (local clamd sidecar)
CLAMAV_HOSTS = os.getenv(
    "CLAMAV_HOSTS"
)  # optional CSV of fallbacks, tried in order
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT = float(os.getenv("CLAMAV_TIMEOUT", "10"))
CLAMAV_MAX_RETRIES = int(os.getenv("CLAMAV_MAX_RETRIES", "2"))
CLAMAV_RETRY_DEADLINE_SECONDS = float(os.getenv("CLAMAV_RETRY_DEADLINE_SECONDS", "30"))
CLAMAV_CHUNK_SIZE = int(os.getenv("CLAMAV_CHUNK_SIZE", "16384"))
SCAN_ENGINE = os.getenv(
    "SCAN_ENGINE", "clamav" if (CLAMAV_HOSTS or CLAMAV_HOST) else "reputation"
).strip().lower()

# ---- Scan engine (YARA, bundled in the worker container) ----
YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "yara-rules/default.yar")
YARA_TIMEOUT = float(os.getenv("YARA_TIMEOUT", "5"))
YARA_MAX_MATCHES = int(os.getenv("YARA_MAX_MATCHES", "50"))
YARA_MAX_STRING_MATCHES = int(os.getenv("YARA_MAX_STRING_MATCHES", "25"))
YARA_MAX_STRING_LENGTH = int(os.getenv("YARA_MAX_STRING_LENGTH", "200"))
YARA_VERDICT_MIN_SEVERITY = os.getenv("YARA_VERDICT_MIN_SEVERITY", "high").strip().lower()
YARA_BINARY = os.getenv("YARA_BINARY", "yara")
_YARA_RULE_META_CACHE: dict[str, tuple[float, dict[str, dict[str, str]]]] = {}

# ---- Scan engine (URL reputation) ----
REPUTATION_BLOCKLIST_HOSTS = os.getenv("REPUTATION_BLOCKLIST_HOSTS", "")
REPUTATION_ALLOWLIST_HOSTS = os.getenv("REPUTATION_ALLOWLIST_HOSTS", "")
REPUTATION_SUSPICIOUS_TLDS = os.getenv(
    "REPUTATION_SUSPICIOUS_TLDS", "zip,top,xyz,click,icu,tk,gq,ml,cf,ga"
)
REPUTATION_SUSPICIOUS_KEYWORDS = os.getenv(
    "REPUTATION_SUSPICIOUS_KEYWORDS", "login,verify,update,secure,account,password,bank"
)
REPUTATION_MIN_SCORE = int(os.getenv("REPUTATION_MIN_SCORE", "60"))
REPUTATION_SUSPICIOUS_SCORE = int(
    os.getenv("REPUTATION_SUSPICIOUS_SCORE", str(max(1, int(REPUTATION_MIN_SCORE / 2))))
)
REPUTATION_BLOCK_ON_MALICIOUS = os.getenv("REPUTATION_BLOCK_ON_MALICIOUS", "false").lower() in (
    "1",
    "true",
    "yes",
)
ENABLE_DEMO_MARKERS = os.getenv("ENABLE_DEMO_MARKERS", "false").lower() in (
    "1",
    "true",
    "yes",
)

# ---- Logging (console + optional App Insights) ----
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
if APPINSIGHTS_CONN:
    try:
        from opencensus.ext.azure.log_exporter import AzureLogHandler

        logging.getLogger().addHandler(
            AzureLogHandler(connection_string=APPINSIGHTS_CONN)
        )
    except Exception as e:
        logging.warning(f"App Insights logging not enabled: {e}")

shutdown = False
table_client: Optional[TableClient] = None
redis_client = None


def _signal_handler(*_):
    global shutdown
    shutdown = True


os_signal.signal(os_signal.SIGTERM, _signal_handler)
os_signal.signal(os_signal.SIGINT, _signal_handler)


def _decode_body(msg) -> dict:
    # msg.body is an iterable of bytes/memoryview sections; join & decode
    body_bytes = b"".join(
        bytes(b) if isinstance(b, memoryview) else b for b in msg.body
    )
    return json.loads(body_bytes.decode("utf-8"))


def process(task: dict):
    job_id = task.get("job_id")
    url = task.get("url")
    correlation_id = task.get("correlation_id")

    if not url or not job_id:
        raise ValueError("missing url/job_id in task")

    start = time.time()
    engines = _get_scan_engines()

    try:
        content, size_bytes, download, url_evaluations, url_signals, reputation_summary = _download(
            url, engines=engines
        )
    except DownloadBlockedError as e:
        duration_ms = int((time.time() - start) * 1000)
        verdict = str(e.decision.get("final_verdict") or "malicious").lower()
        details = dict(e.details or {})
        details.setdefault("engine", engines[0] if len(engines) == 1 else "multi")
        details.setdefault("engines", engines)
        details.setdefault("download_blocked", True)
        details.setdefault("url", url)
        _save_result(
            job_id=job_id,
            status="completed",
            verdict=verdict,
            details=details,
            size_bytes=0,
            correlation_id=correlation_id,
            duration_ms=duration_ms,
            submitted_at=task.get("submitted_at"),
            error=None,
            url=url,
        )
        logging.info(
            "[worker] job_id=%s verdict=%s size=0B duration_ms=%s (blocked)",
            job_id,
            verdict,
            duration_ms,
        )
        return verdict, details

    verdict, details = _scan_bytes(
        content,
        url,
        engines=engines,
        download=download,
        url_evaluations=url_evaluations,
        url_signals=url_signals,
        reputation_summary=reputation_summary,
    )
    duration_ms = int((time.time() - start) * 1000)
    _save_result(
        job_id=job_id,
        status="completed",
        verdict=verdict,
        details=details,
        size_bytes=size_bytes,
        correlation_id=correlation_id,
        duration_ms=duration_ms,
        submitted_at=task.get("submitted_at"),
        error=None,
        url=url,
    )
    logging.info(
        "[worker] job_id=%s verdict=%s size=%sB duration_ms=%s",
        job_id,
        verdict,
        size_bytes,
        duration_ms,
    )
    return verdict, details


def _download(url: str, *, engines: List[str]) -> tuple[
    bytes, int, dict, list[dict], list[Signal], Optional[dict]
]:
    session = requests.Session()
    current = url
    redirects: list[dict] = []
    url_evaluations: list[dict] = []
    url_signals: list[Signal] = []

    for hop in range(MAX_REDIRECTS + 1):
        canonical, hop_signals, evaluation = _evaluate_url_hop(
            current, engines=engines, hop=hop
        )
        url_evaluations.append(evaluation)
        url_signals.extend(hop_signals)

        if "reputation" in engines and REPUTATION_BLOCK_ON_MALICIOUS:
            hop_decision = evaluation.get("decision") if isinstance(evaluation, dict) else None
            if isinstance(hop_decision, dict) and hop_decision.get("final_verdict") == "malicious":
                details = {
                    "url": url,
                    "canonical_url": canonicalize_url(url).canonical,
                    "decision": hop_decision,
                    "signals": [s.as_dict() for s in url_signals],
                    "results": {"reputation": evaluation.get("reputation", {})},
                    "download_blocked": True,
                    "download": {
                        "requested_url": url,
                        "blocked": True,
                        "blocked_at_hop": hop,
                        "blocked_url": canonical.canonical,
                    },
                    "url_evaluations": url_evaluations,
                }
                raise DownloadBlockedError(decision=hop_decision, details=details)

        request_url = canonical.canonical
        with session.get(
            request_url,
            timeout=REQUEST_TIMEOUT,
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
                if len(buf) > MAX_DOWNLOAD_BYTES:
                    raise ValueError("content too large")
            download_info = {
                "requested_url": url,
                "final_url": request_url,
                "redirects": redirects,
                "url_evaluations": url_evaluations,
            }
            if content_type:
                download_info["content_type"] = content_type
            if content_length:
                download_info["content_length"] = content_length
            reputation_summary: Optional[dict] = None
            if "reputation" in engines:
                rep_evals = [
                    e.get("reputation")
                    for e in url_evaluations
                    if isinstance(e, dict) and isinstance(e.get("reputation"), dict)
                ]
                verdict_rank = {"benign": 0, "suspicious": 1, "error": 2, "malicious": 3}
                worst_verdict = "benign"
                max_score = 0
                matched_rules: set[str] = set()
                for rep in rep_evals:
                    if not isinstance(rep, dict):
                        continue
                    v = str(rep.get("verdict") or "benign").lower()
                    if verdict_rank.get(v, 0) > verdict_rank.get(worst_verdict, 0):
                        worst_verdict = v
                    try:
                        max_score = max(max_score, int(rep.get("score") or 0))
                    except Exception:
                        pass
                    mr = rep.get("matched_rules")
                    if isinstance(mr, list):
                        matched_rules.update(str(x) for x in mr if x)
                reputation_summary = {
                    "verdict": worst_verdict,
                    "score": max_score,
                    "suspicious_threshold": REPUTATION_SUSPICIOUS_SCORE,
                    "malicious_threshold": REPUTATION_MIN_SCORE,
                    "matched_rules": sorted(matched_rules)[:50],
                }

            return (
                bytes(buf),
                len(buf),
                download_info,
                url_evaluations,
                url_signals,
                reputation_summary,
            )

    raise ValueError("too many redirects")


def _validate_url_for_download(url: str):
    # Canonicalize first to prevent representation bypasses, then validate.
    canonical = canonicalize_url(url)
    if canonical.has_userinfo:
        raise UrlValidationError(
            code="userinfo_not_allowed", message="userinfo in url is not allowed"
        )
    validate_public_https_url(
        canonical.canonical, block_private_networks=BLOCK_PRIVATE_NETWORKS
    )
    return canonical


_SUPPORTED_SCAN_ENGINES = {"clamav", "yara", "reputation"}


def _parse_csv(spec: str) -> List[str]:
    raw = (spec or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _host_matches_pattern(host: str, pattern: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    pattern = (pattern or "").strip().lower().rstrip(".")
    if not host or not pattern:
        return False
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)
    if pattern.startswith("."):
        return host == pattern[1:] or host.endswith(pattern)
    return host == pattern


class DownloadBlockedError(RuntimeError):
    def __init__(self, *, decision: dict, details: dict):
        super().__init__(decision.get("final_verdict") or "download_blocked")
        self.decision = decision
        self.details = details


def _with_url_context(sig: Signal, *, canonical_url: str, hop: int) -> Signal:
    ev = dict(sig.evidence or {})
    ev.setdefault("url", canonical_url)
    ev.setdefault("hop", hop)
    return Signal(
        source=sig.source,
        verdict=sig.verdict,
        severity=sig.severity,
        weight=sig.weight,
        evidence=ev,
        ttl=sig.ttl,
    )


def _reputation_signals(
    canonical: CanonicalUrl, *, requested_url: str, hop: int
) -> tuple[list[Signal], dict]:
    host_unicode = (canonical.host_unicode or "").strip().rstrip(".")
    host_idna = (canonical.host_punycode or "").strip().lower().rstrip(".")
    if not host_idna:
        err = signal(
            source="reputation.error",
            verdict="error",
            severity="high",
            weight=50,
            evidence={"reason": "missing host"},
        )
        return [_with_url_context(err, canonical_url=canonical.canonical, hop=hop)], {
            "verdict": "error",
            "reason": "missing-host",
        }

    allowlist = _parse_csv(REPUTATION_ALLOWLIST_HOSTS)
    blocklist = _parse_csv(REPUTATION_BLOCKLIST_HOSTS)

    matched_allow = next((p for p in allowlist if _host_matches_pattern(host_idna, p)), "")
    if matched_allow:
        s = signal(
            source="reputation.allowlist",
            verdict="benign",
            severity="info",
            weight=25,
            evidence={
                "reason": f"allowlisted host ({matched_allow})",
                "matched_allowlist": matched_allow,
                "host": host_unicode,
                "host_idna": host_idna,
            },
        )
        return [_with_url_context(s, canonical_url=canonical.canonical, hop=hop)], {
            "verdict": "benign",
            "host": host_unicode,
            "host_idna": host_idna,
            "score": 0,
            "suspicious_threshold": REPUTATION_SUSPICIOUS_SCORE,
            "malicious_threshold": REPUTATION_MIN_SCORE,
            "matched_allowlist": matched_allow,
            "matched_rules": [],
        }

    matched_block = next((p for p in blocklist if _host_matches_pattern(host_idna, p)), "")
    if matched_block:
        s = signal(
            source="reputation.blocklist",
            verdict="malicious",
            severity="critical",
            weight=100,
            evidence={
                "reason": f"blocklisted host ({matched_block})",
                "matched_blocklist": matched_block,
                "host": host_unicode,
                "host_idna": host_idna,
            },
        )
        return [_with_url_context(s, canonical_url=canonical.canonical, hop=hop)], {
            "verdict": "malicious",
            "host": host_unicode,
            "host_idna": host_idna,
            "score": 100,
            "suspicious_threshold": REPUTATION_SUSPICIOUS_SCORE,
            "malicious_threshold": REPUTATION_MIN_SCORE,
            "matched_blocklist": matched_block,
            "matched_rules": [],
        }

    # Demo-only marker for consistent presentations (off by default).
    if ENABLE_DEMO_MARKERS and "test-malicious" in (requested_url or "").lower():
        s = signal(
            source="reputation.demo_marker",
            verdict="malicious",
            severity="critical",
            weight=100,
            evidence={"reason": "demo marker matched (test-malicious)"},
        )
        return [_with_url_context(s, canonical_url=canonical.canonical, hop=hop)], {
            "verdict": "malicious",
            "host": host_unicode,
            "host_idna": host_idna,
            "score": 100,
            "suspicious_threshold": REPUTATION_SUSPICIOUS_SCORE,
            "malicious_threshold": REPUTATION_MIN_SCORE,
            "matched_test_marker": "test-malicious",
            "matched_rules": [],
        }

    heuristics: HeuristicsResult = evaluate_url_heuristics(
        canonical,
        suspicious_threshold=REPUTATION_SUSPICIOUS_SCORE,
        malicious_threshold=REPUTATION_MIN_SCORE,
        env=os.environ,
    )
    sigs = [_with_url_context(s, canonical_url=canonical.canonical, hop=hop) for s in heuristics.signals]
    verdict = sigs[-1].verdict if sigs else "benign"

    tld = host_idna.rsplit(".", 1)[-1] if "." in host_idna else host_idna
    return sigs, {
        "verdict": verdict,
        "host": host_unicode,
        "host_idna": host_idna,
        "tld": tld,
        "score": heuristics.score,
        "suspicious_threshold": heuristics.suspicious_threshold,
        "malicious_threshold": heuristics.malicious_threshold,
        "matched_rules": [m.get("name") for m in heuristics.matched_rules if isinstance(m, dict)],
    }


def _evaluate_url_hop(
    requested_url: str, *, engines: List[str], hop: int
) -> tuple[CanonicalUrl, list[Signal], dict]:
    canonical = _validate_url_for_download(requested_url)

    hop_signals: list[Signal] = []
    reputation: Optional[dict] = None
    if "reputation" in engines:
        rep_signals, reputation = _reputation_signals(
            canonical, requested_url=requested_url, hop=hop
        )
        hop_signals.extend(rep_signals)

    decision = aggregate_signals(hop_signals)
    evaluation = {
        "hop": hop,
        "requested_url": requested_url,
        "canonical": canonical.as_dict(),
        "decision": decision.as_dict(),
    }
    if reputation is not None:
        evaluation["reputation"] = reputation
    if hop_signals:
        evaluation["signals"] = [s.as_dict() for s in hop_signals]
    return canonical, hop_signals, evaluation


def _parse_scan_engines(spec: str) -> List[str]:
    raw = (spec or "").strip().lower()
    if not raw:
        return []

    parts = [p.strip() for p in re.split(r"[,+]", raw) if p.strip()]
    engines: List[str] = []
    seen: set[str] = set()
    for part in parts:
        if part not in _SUPPORTED_SCAN_ENGINES:
            raise ValueError(
                f"unsupported scan engine '{part}' (supported: {sorted(_SUPPORTED_SCAN_ENGINES)})"
            )
        if part in seen:
            continue
        seen.add(part)
        engines.append(part)
    return engines


def _get_scan_engines() -> List[str]:
    engines = _parse_scan_engines(SCAN_ENGINE)
    return engines if engines else ["reputation"]


def _parse_yara_rule_metadata(rules_text: str) -> dict[str, dict[str, str]]:
    rule_re = re.compile(r"^\s*(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)\b")
    section_re = re.compile(r"^\s*(meta|strings|condition)\s*:\s*$", re.IGNORECASE)
    kv_re = re.compile(r"^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$")

    out: dict[str, dict[str, str]] = {}
    current_rule: Optional[str] = None
    in_meta = False

    for raw_line in (rules_text or "").splitlines():
        line = raw_line.rstrip()

        m_rule = rule_re.match(line)
        if m_rule:
            current_rule = m_rule.group(1)
            in_meta = False
            out.setdefault(current_rule, {})
            continue

        if current_rule is None:
            continue

        if line.strip().startswith("}"):
            current_rule = None
            in_meta = False
            continue

        m_section = section_re.match(line)
        if m_section:
            section = m_section.group(1).lower()
            in_meta = section == "meta"
            continue

        if not in_meta:
            continue

        m_kv = kv_re.match(line)
        if not m_kv:
            continue

        key = m_kv.group(1).strip()
        value = m_kv.group(2).strip()
        if len(value) >= 2 and (
            (value.startswith('"') and value.endswith('"'))
            or (value.startswith("'") and value.endswith("'"))
        ):
            value = value[1:-1]
            value = value.replace('\\"', '"').replace("\\'", "'")

        if current_rule is not None and key and value:
            out.setdefault(current_rule, {})[key] = value

    # Drop rules with no metadata to keep output small.
    return {k: v for k, v in out.items() if v}


def _load_yara_rule_metadata(rules_path: str) -> dict[str, dict[str, str]]:
    path = (rules_path or "").strip()
    if not path:
        return {}

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}

    cached = _YARA_RULE_META_CACHE.get(path)
    if cached and cached[0] == mtime:
        return cached[1]

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return {}

    meta = _parse_yara_rule_metadata(text)
    _YARA_RULE_META_CACHE[path] = (mtime, meta)
    return meta


def _yara_scan(content: bytes) -> tuple[str, dict]:
    rules_path = (YARA_RULES_PATH or "").strip()
    if not rules_path:
        raise ValueError("YARA_RULES_PATH is required when SCAN_ENGINE includes 'yara'")
    if not os.path.exists(rules_path):
        raise ValueError(f"YARA_RULES_PATH not found: {rules_path}")

    yara_bin = (YARA_BINARY or "yara").strip()
    if not shutil.which(yara_bin):
        raise ValueError(f"YARA binary not found on PATH: {yara_bin}")

    tmp_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="scan-", suffix=".bin", delete=False
        ) as f:
            tmp_path = f.name
            f.write(content)

        cmd = [yara_bin, "-s", rules_path, tmp_path]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=YARA_TIMEOUT,
        )
        if proc.returncode not in (0, 1):
            stderr = (proc.stderr or proc.stdout or "").strip()
            raise ValueError(
                f"yara scan failed (exit={proc.returncode}): {stderr or 'unknown error'}"
            )

        rule_names: List[str] = []
        match_details: List[dict] = []
        truncated = False

        current: Optional[dict] = None
        if proc.returncode == 0:
            for raw_line in (proc.stdout or "").splitlines():
                line = raw_line.strip()
                if not line:
                    continue

                if line.startswith("0x") and current is not None:
                    m = re.match(r"^0x([0-9a-fA-F]+):([^:]+):\\s*(.*)$", line)
                    if not m:
                        continue
                    if len(current["strings"]) >= max(1, YARA_MAX_STRING_MATCHES):
                        continue
                    offset = int(m.group(1), 16)
                    identifier = m.group(2).strip()
                    value = m.group(3).strip()
                    if len(value) > max(0, YARA_MAX_STRING_LENGTH):
                        value = value[: max(0, YARA_MAX_STRING_LENGTH)] + "…"
                    current["strings"].append(
                        {"offset": offset, "identifier": identifier, "value": value}
                    )
                    continue

                # Start of a new match: "<rule> <target>" (target is the temp path).
                rule = line.split(maxsplit=1)[0]
                if not rule:
                    continue

                if rule not in rule_names:
                    rule_names.append(rule)
                current = {"rule": rule, "strings": []}
                match_details.append(current)

                if len(rule_names) >= max(1, YARA_MAX_MATCHES):
                    truncated = True
                    break

        if match_details:
            rule_meta = _load_yara_rule_metadata(rules_path)
            if rule_meta:
                for m in match_details:
                    rule = m.get("rule")
                    if not isinstance(rule, str) or not rule:
                        continue
                    meta = rule_meta.get(rule)
                    if meta:
                        m["meta"] = meta

        verdict_min_severity = (YARA_VERDICT_MIN_SEVERITY or "high").strip().lower()
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3}
        min_rank = severity_rank.get(verdict_min_severity, 3)
        malicious_matches = [
            rule
            for rule in rule_names
            if severity_rank.get(_yara_rule_severity(rule), 3) >= min_rank
        ]

        verdict = "malicious" if malicious_matches else "clean"
        return verdict, {
            "yara": {
                "matches": rule_names,
                "malicious_matches": malicious_matches,
                "match_details": match_details,
                "rules_path": rules_path,
                "verdict_min_severity": verdict_min_severity,
                "truncated": truncated,
            }
        }
    except subprocess.TimeoutExpired as e:
        raise ValueError(f"yara scan timed out after {YARA_TIMEOUT}s") from e
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _yara_rule_severity(rule_name: str) -> str:
    upper = (rule_name or "").upper()
    for suffix in ("_INFO", "_LOW", "_MEDIUM", "_HIGH"):
        if upper.endswith(suffix):
            return suffix.lstrip("_").lower()
    return "high"


def _scan_bytes(
    content: bytes,
    url: str,
    *,
    engines: Optional[List[str]] = None,
    download: Optional[dict] = None,
    url_evaluations: Optional[list[dict]] = None,
    url_signals: Optional[list[Signal]] = None,
    reputation_summary: Optional[dict] = None,
) -> tuple[str, dict]:
    digest = hashlib.sha256(content).hexdigest()
    engines = engines or _get_scan_engines()
    results: dict[str, dict] = {}
    signals: list[Signal] = list(url_signals or [])

    for engine in engines:
        if engine == "reputation":
            if isinstance(reputation_summary, dict) and reputation_summary:
                results["reputation"] = reputation_summary
        elif engine == "clamav":
            if not _get_clamav_hosts():
                raise ValueError(
                    "CLAMAV_HOST or CLAMAV_HOSTS is required when SCAN_ENGINE includes 'clamav'"
                )
            scan_verdict, clamav_details = _clamav_instream_scan(content)
            clam = clamav_details.get("clamav", clamav_details)
            results["clamav"] = clam
            if scan_verdict == "malicious":
                signature = ""
                if isinstance(clam, dict):
                    signature = str(clam.get("signature") or "")
                signals.append(
                    signal(
                        source="clamav.sig",
                        verdict="malicious",
                        severity="critical",
                        weight=100,
                        evidence={
                            "signature": signature,
                            "reason": f"ClamAV detected {signature or 'a known signature'}",
                        },
                    )
                )
            else:
                signals.append(
                    signal(
                        source="clamav.result",
                        verdict="benign",
                        severity="info",
                        weight=20,
                        evidence={"reason": "ClamAV scan OK"},
                    )
                )
        elif engine == "yara":
            scan_verdict, yara_details = _yara_scan(content)
            yara = yara_details.get("yara", yara_details)
            results["yara"] = yara

            malicious_matches: list[str] = []
            matches: list[str] = []
            if isinstance(yara, dict):
                mm = yara.get("malicious_matches")
                if isinstance(mm, list):
                    malicious_matches = [str(x) for x in mm if x]
                m = yara.get("matches")
                if isinstance(m, list):
                    matches = [str(x) for x in m if x]

            yara_weight = {"info": 20, "low": 40, "medium": 70, "high": 90, "critical": 100}
            if malicious_matches:
                for rule in malicious_matches[:50]:
                    sev = _yara_rule_severity(rule)
                    signals.append(
                        signal(
                            source=f"yara.rule.{rule}",
                            verdict="malicious",
                            severity=sev,
                            weight=yara_weight.get(sev, 90),
                            evidence={"rule": rule, "reason": f"YARA match: {rule}"},
                        )
                    )
            elif matches:
                signals.append(
                    signal(
                        source="yara.match",
                        verdict="benign",
                        severity="info",
                        weight=5,
                        evidence={
                            "match_count": len(matches),
                            "matched_rules": matches[:25],
                            "reason": "YARA matched rules below verdict threshold (informational)",
                        },
                    )
                )
            else:
                signals.append(
                    signal(
                        source="yara.result",
                        verdict="benign",
                        severity="info",
                        weight=20,
                        evidence={"reason": "YARA: no matches"},
                    )
                )
        else:
            raise ValueError(f"unsupported scan engine: {engine}")

    decision = aggregate_signals(signals)

    details = {
        "url": url,
        "canonical_url": (
            url_evaluations[0].get("canonical", {}).get("canonical")
            if isinstance(url_evaluations, list)
            and url_evaluations
            and isinstance(url_evaluations[0], dict)
            else None
        ),
        "sha256": digest,
        "length": len(content),
        "engine": engines[0] if len(engines) == 1 else "multi",
        "engines": engines,
        "results": results,
        "decision": decision.as_dict(),
        "signals": [s.as_dict() for s in signals],
    }
    if isinstance(url_evaluations, list) and url_evaluations:
        details["url_evaluations"] = url_evaluations
    if isinstance(download, dict) and download:
        details["download"] = download
    if details.get("canonical_url") is None:
        details.pop("canonical_url", None)
    return decision.final_verdict, details


def _clamav_instream_scan(content: bytes) -> tuple[str, dict]:
    """Scan bytes via clamd INSTREAM protocol."""
    hosts = _get_clamav_hosts()
    if not hosts:
        raise ValueError("clamav scan failed: no CLAMAV_HOST(S) configured")

    last_err: Optional[Exception] = None

    deadline = time.monotonic() + CLAMAV_RETRY_DEADLINE_SECONDS
    for attempt in range(CLAMAV_MAX_RETRIES + 1):
        for host in hosts:
            # clamd can accept INSTREAM as either newline-delimited or null-terminated.
            for cmd in (b"zINSTREAM\0", b"INSTREAM\n"):
                try:
                    with socket.create_connection(
                        (host, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT
                    ) as sock:
                        sock.settimeout(CLAMAV_TIMEOUT)

                        sock.sendall(cmd)
                        view = memoryview(content)
                        for i in range(0, len(content), CLAMAV_CHUNK_SIZE):
                            chunk = view[i : i + CLAMAV_CHUNK_SIZE]
                            sock.sendall(struct.pack("!I", len(chunk)))
                            sock.sendall(chunk)
                        sock.sendall(struct.pack("!I", 0))

                        buf = b""
                        while True:
                            part = sock.recv(4096)
                            if not part:
                                break
                            buf += part
                            if b"\0" in buf or b"\n" in buf:
                                break

                        line = (
                            buf.split(b"\0", 1)[0]
                            .split(b"\n", 1)[0]
                            .decode("utf-8", "replace")
                            .strip()
                        )
                        if not line:
                            raise ValueError("empty clamd response")

                        # Typical responses:
                        #   "stream: OK"
                        #   "stream: Eicar-Test-Signature FOUND"
                        #   "stream: <reason> ERROR"
                        if line.endswith(" OK"):
                            return "clean", {"clamav": {"result": "OK"}}
                        if line.endswith(" FOUND"):
                            signature = line.split(": ", 1)[1].rsplit(" FOUND", 1)[0]
                            return "malicious", {
                                "clamav": {"result": "FOUND", "signature": signature}
                            }
                        if line.endswith(" ERROR") or " ERROR" in line:
                            raise ValueError(f"clamd error: {line}")

                        # Unexpected response; fail closed.
                        raise ValueError(f"unexpected clamd response: {line}")
                except (OSError, ValueError) as e:
                    last_err = RuntimeError(f"{host}:{CLAMAV_PORT}: {e}")

        if attempt >= CLAMAV_MAX_RETRIES or time.monotonic() >= deadline:
            break
        time.sleep(min(0.5 * (2**attempt), 10.0))

    raise ValueError(f"clamav scan failed: {last_err}")


def _get_clamav_hosts() -> List[str]:
    hosts: List[str] = []
    if CLAMAV_HOSTS:
        hosts.extend([h.strip() for h in CLAMAV_HOSTS.split(",") if h.strip()])
    if CLAMAV_HOST:
        hosts.append(CLAMAV_HOST.strip())

    unique_hosts: List[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            continue
        seen.add(host)
        unique_hosts.append(host)
    return unique_hosts


def _save_result(
    job_id: str,
    status: str,
    verdict: str,
    details: Optional[dict] = None,
    size_bytes: Optional[int] = None,
    correlation_id: Optional[str] = None,
    duration_ms: Optional[int] = None,
    submitted_at: Optional[str] = None,
    error: Optional[str] = None,
    url: Optional[str] = None,
):
    scanned_at = datetime.now(timezone.utc).isoformat()

    extra = {
        "size_bytes": size_bytes or 0,
        "correlation_id": correlation_id or "",
        "duration_ms": duration_ms or 0,
        "scanned_at": scanned_at,
        "submitted_at": submitted_at or "",
    }
    if url:
        extra["url"] = url

    details_out: dict = dict(details or {})
    if url and "url" not in details_out:
        details_out["url"] = url
    try:
        upsert_result_sync(
            backend=RESULT_BACKEND,
            partition_key=RESULT_PARTITION,
            job_id=job_id,
            status=status,
            verdict=verdict,
            error=error,
            details=details_out,
            extra=extra,
            table_client=table_client,
            redis_client=redis_client,
            redis_prefix=REDIS_RESULT_PREFIX,
            redis_ttl_seconds=REDIS_RESULT_TTL_SECONDS,
        )
    except HttpResponseError as e:
        logging.error("[worker] Failed to persist result: %s", e)


def main():
    if QUEUE_BACKEND not in ("servicebus", "redis"):
        raise RuntimeError("QUEUE_BACKEND must be 'servicebus' or 'redis'")
    if RESULT_BACKEND not in ("table", "redis"):
        raise RuntimeError("RESULT_BACKEND must be 'table' or 'redis'")

    global table_client, redis_client

    if QUEUE_BACKEND == "servicebus" and not SERVICEBUS_CONN:
        raise RuntimeError("SERVICEBUS_CONN env var is required when QUEUE_BACKEND=servicebus")
    if RESULT_BACKEND == "table" and not RESULT_STORE_CONN:
        raise RuntimeError("RESULT_STORE_CONN env var is required when RESULT_BACKEND=table")
    if (QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis") and not REDIS_URL:
        raise RuntimeError("REDIS_URL env var is required when using Redis backends")

    if QUEUE_BACKEND == "redis" or RESULT_BACKEND == "redis":
        try:
            import redis
        except Exception as e:
            raise RuntimeError(
                "Redis backends require the 'redis' package (pip install redis)"
            ) from e
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()

    if RESULT_BACKEND == "table":
        table_service = TableServiceClient.from_connection_string(
            conn_str=RESULT_STORE_CONN
        )
        table_service.create_table_if_not_exists(table_name=RESULT_TABLE)
        table_client = table_service.get_table_client(table_name=RESULT_TABLE)

    engines = _get_scan_engines()
    logging.info("[worker] Scan engines: %s", engines)

    if "clamav" in engines:
        hosts = _get_clamav_hosts()
        if not hosts:
            raise RuntimeError(
                "SCAN_ENGINE includes 'clamav' but CLAMAV_HOST/CLAMAV_HOSTS is not set"
            )
        logging.info("[worker] ClamAV configured: hosts=%s port=%s", hosts, CLAMAV_PORT)

    if "yara" in engines:
        rules_path = (YARA_RULES_PATH or "").strip()
        if not rules_path:
            raise RuntimeError(
                "SCAN_ENGINE includes 'yara' but YARA_RULES_PATH is not set"
            )
        if not os.path.exists(rules_path):
            raise RuntimeError(f"YARA_RULES_PATH not found: {rules_path}")
        yara_bin = (YARA_BINARY or "yara").strip()
        if not shutil.which(yara_bin):
            raise RuntimeError(f"YARA binary not found on PATH: {yara_bin}")
        logging.info("[worker] YARA configured: rules=%s", rules_path)

    logging.info("[worker] started; waiting for messages...")

    if QUEUE_BACKEND == "redis":
        if not redis_client:
            raise RuntimeError("Redis client not initialized")
        logging.info("[worker] redis queue=%s dlq=%s", REDIS_QUEUE_KEY, REDIS_DLQ_KEY)
        while not shutdown:
            item = redis_client.blpop(REDIS_QUEUE_KEY, timeout=MAX_WAIT)
            if not item:
                continue

            _queue, raw = item
            started_at = time.time()
            task: Optional[dict] = None
            envelope: Optional[dict] = None
            delivery_count = 1
            try:
                decoded = json.loads(raw)
                if isinstance(decoded, dict) and isinstance(decoded.get("payload"), dict):
                    envelope = decoded
                    task = decoded["payload"]
                    delivery_count = int(decoded.get("delivery_count") or 1)
                elif isinstance(decoded, dict):
                    task = decoded
                    envelope = {"schema": "unknown", "delivery_count": 1, "payload": decoded}
                    delivery_count = 1
                else:
                    raise ValueError("invalid message payload (expected JSON object)")

                process(task)
            except Exception as e:
                duration_ms = int((time.time() - started_at) * 1000)
                job_id = task.get("job_id") if isinstance(task, dict) else None
                correlation_id = (
                    task.get("correlation_id") if isinstance(task, dict) else None
                )
                submitted_at = task.get("submitted_at") if isinstance(task, dict) else None

                retrying = delivery_count < MAX_RETRIES
                status = "retrying" if retrying else "error"

                if job_id:
                    _save_result(
                        job_id=job_id,
                        status=status,
                        verdict="" if retrying else "error",
                        error=str(e),
                        details={
                            "reason": str(e),
                            "delivery_count": delivery_count,
                            "max_retries": MAX_RETRIES,
                        },
                        correlation_id=correlation_id,
                        duration_ms=duration_ms,
                        submitted_at=submitted_at,
                        url=task.get("url") if isinstance(task, dict) else None,
                    )

                if retrying:
                    next_envelope = envelope or {"delivery_count": delivery_count, "payload": task or {}}
                    next_envelope["delivery_count"] = delivery_count + 1
                    redis_client.rpush(REDIS_QUEUE_KEY, json.dumps(next_envelope))
                    logging.warning(
                        "[worker] Requeued message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )
                else:
                    dlq_envelope = envelope or {"delivery_count": delivery_count, "payload": task or {}}
                    dlq_envelope["last_error"] = str(e)
                    redis_client.rpush(REDIS_DLQ_KEY, json.dumps(dlq_envelope))
                    logging.error(
                        "[worker] DLQ'd message (delivery_count=%s): %s",
                        delivery_count,
                        e,
                    )

    else:
        client = ServiceBusClient.from_connection_string(
            SERVICEBUS_CONN, logging_enable=True
        )
        with client:
            receiver = client.get_queue_receiver(
                queue_name=QUEUE_NAME,
                max_wait_time=MAX_WAIT,
                prefetch_count=PREFETCH,
            )
            with receiver:
                while not shutdown:
                    try:
                        messages = receiver.receive_messages(
                            max_message_count=BATCH_SIZE,
                            max_wait_time=MAX_WAIT,
                        )
                        if not messages:
                            continue

                        for msg in messages:
                            task = None
                            started_at = time.time()
                            try:
                                task = _decode_body(msg)
                                process(task)
                                receiver.complete_message(msg)
                            except Exception as e:
                                duration_ms = int((time.time() - started_at) * 1000)
                                job_id = (
                                    task.get("job_id") if isinstance(task, dict) else None
                                )
                                correlation_id = (
                                    task.get("correlation_id")
                                    if isinstance(task, dict)
                                    else None
                                )
                                submitted_at = (
                                    task.get("submitted_at")
                                    if isinstance(task, dict)
                                    else None
                                )

                                if job_id:
                                    retrying = msg.delivery_count < MAX_RETRIES
                                    status = "retrying" if retrying else "error"
                                    _save_result(
                                        job_id=job_id,
                                        status=status,
                                        verdict="" if retrying else "error",
                                        error=str(e),
                                        details={
                                            "reason": str(e),
                                            "delivery_count": msg.delivery_count,
                                            "max_retries": MAX_RETRIES,
                                        },
                                        correlation_id=correlation_id,
                                        duration_ms=duration_ms,
                                        submitted_at=submitted_at,
                                        url=task.get("url") if isinstance(task, dict) else None,
                                    )

                                # DLQ if too many deliveries, else make it available again
                                if msg.delivery_count >= MAX_RETRIES:
                                    receiver.dead_letter_message(
                                        msg,
                                        reason="max-retries-exceeded",
                                        error_description=str(e),
                                    )
                                    logging.error(
                                        "[worker] DLQ'd message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                                else:
                                    receiver.abandon_message(msg)
                                    logging.warning(
                                        "[worker] Abandoned message (delivery_count=%s): %s",
                                        msg.delivery_count,
                                        e,
                                    )
                    except OperationTimeoutError:
                        # no messages within wait window
                        continue
                    except ServiceBusError as e:
                        logging.error(f"[worker] ServiceBusError: {e}")
                        time.sleep(2)  # brief backoff

    logging.info("[worker] shutdown complete.")


if __name__ == "__main__":
    main()
