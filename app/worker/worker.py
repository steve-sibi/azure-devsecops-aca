import json
import logging
import os
import re
import signal as os_signal
import time
import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin

import requests
from azure.servicebus import ServiceBusClient
from azure.servicebus.exceptions import OperationTimeoutError, ServiceBusError
from azure.data.tables import TableClient, TableServiceClient

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

# ---- Artifact handoff (fetcher -> analyzer) ----
ARTIFACT_DIR = os.getenv("ARTIFACT_DIR", "/artifacts").strip() or "/artifacts"
ARTIFACT_DELETE_ON_SUCCESS = os.getenv("ARTIFACT_DELETE_ON_SUCCESS", "false").lower() in (
    "1",
    "true",
    "yes",
)

# ---- Scan engines (URL safety) ----
# - reputation: URL/domain heuristics + allow/block lists
# - urlscan: optional external scan via urlscan.io
# - urlhaus: optional external known-bad lookup via URLhaus (abuse.ch)
# - content: lightweight content heuristics on the fetched response body
SCAN_ENGINE = os.getenv("SCAN_ENGINE", "reputation,content").strip().lower()

# Content heuristics tuning (keep conservative to reduce false positives)
CONTENT_MAX_TEXT_BYTES = int(os.getenv("CONTENT_MAX_TEXT_BYTES", str(200_000)))
CONTENT_MAX_BASE64_MATCH = int(os.getenv("CONTENT_MAX_BASE64_MATCH", str(50_000)))

# ---- External scan engine (urlscan.io) ----
URLSCAN_API_KEY = (os.getenv("URLSCAN_API_KEY") or "").strip()
URLSCAN_BASE_URL = (
    os.getenv("URLSCAN_BASE_URL", "https://urlscan.io/api/v1").strip().rstrip("/")
)
URLSCAN_VISIBILITY = (os.getenv("URLSCAN_VISIBILITY", "public") or "public").strip().lower()
URLSCAN_TIMEOUT_SECONDS = int(os.getenv("URLSCAN_TIMEOUT_SECONDS", "10"))
URLSCAN_MAX_WAIT_SECONDS = int(os.getenv("URLSCAN_MAX_WAIT_SECONDS", "25"))
URLSCAN_POLL_INTERVAL_SECONDS = int(os.getenv("URLSCAN_POLL_INTERVAL_SECONDS", "2"))
URLSCAN_SUSPICIOUS_SCORE = int(os.getenv("URLSCAN_SUSPICIOUS_SCORE", "50"))
URLSCAN_MALICIOUS_SCORE = int(os.getenv("URLSCAN_MALICIOUS_SCORE", "80"))

# ---- External known-bad source (URLhaus) ----
URLHAUS_BASE_URL = (
    os.getenv("URLHAUS_BASE_URL", "https://urlhaus-api.abuse.ch/v1").strip().rstrip("/")
)
URLHAUS_API_KEY = (os.getenv("URLHAUS_API_KEY") or "").strip()
URLHAUS_API_KEY_HEADER = (
    os.getenv("URLHAUS_API_KEY_HEADER", "Auth-Key") or "Auth-Key"
).strip() or "Auth-Key"
URLHAUS_TIMEOUT_SECONDS = int(os.getenv("URLHAUS_TIMEOUT_SECONDS", "10"))
URLHAUS_MATCH_WEIGHT = int(os.getenv("URLHAUS_MATCH_WEIGHT", "90"))

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
        artifact_path = task.get("artifact_path")
        if isinstance(artifact_path, str) and artifact_path.strip():
            artifact_name = Path(artifact_path).name
            full_path = Path(ARTIFACT_DIR) / artifact_name
            content = full_path.read_bytes()
            size_bytes = len(content)

            expected_size = task.get("artifact_size_bytes")
            if expected_size is not None:
                try:
                    if int(expected_size) != size_bytes:
                        raise ValueError(
                            f"artifact size mismatch (expected={expected_size} actual={size_bytes})"
                        )
                except Exception:
                    pass

            expected_sha = task.get("artifact_sha256")
            if isinstance(expected_sha, str) and expected_sha:
                actual_sha = hashlib.sha256(content).hexdigest()
                if not secrets.compare_digest(actual_sha, expected_sha.lower()):
                    raise ValueError("artifact sha256 mismatch")

            download = task.get("download") if isinstance(task.get("download"), dict) else {}
            url_evaluations = (
                task.get("url_evaluations")
                if isinstance(task.get("url_evaluations"), list)
                else []
            )
            url_signals_raw = task.get("url_signals")
            url_signals = []
            if isinstance(url_signals_raw, list):
                for item in url_signals_raw:
                    if not isinstance(item, dict):
                        continue
                    url_signals.append(
                        signal(
                            source=str(item.get("source") or "unknown"),
                            verdict=str(item.get("verdict") or "error"),
                            severity=str(item.get("severity") or "info"),
                            weight=int(item.get("weight") or 0),
                            evidence=item.get("evidence")
                            if isinstance(item.get("evidence"), dict)
                            else None,
                            ttl=int(item.get("ttl") or 0),
                        )
                    )

            reputation_summary = (
                task.get("reputation_summary")
                if isinstance(task.get("reputation_summary"), dict)
                else None
            )
        else:
            (
                content,
                size_bytes,
                download,
                url_evaluations,
                url_signals,
                reputation_summary,
            ) = _download(url, engines=engines)
    except DownloadBlockedError as e:
        duration_ms = int((time.time() - start) * 1000)
        verdict = str(e.decision.get("final_verdict") or "malicious").lower()
        details = dict(e.details or {})
        details.setdefault("engine", engines[0] if len(engines) == 1 else "multi")
        details.setdefault("engines", engines)
        details.setdefault("download_blocked", True)
        details.setdefault("url", url)
        if not _save_result(
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
        ):
            raise RuntimeError("failed to persist blocked scan result")
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
    if not _save_result(
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
    ):
        raise RuntimeError("failed to persist scan result")
    if ARTIFACT_DELETE_ON_SUCCESS:
        artifact_path = task.get("artifact_path")
        if isinstance(artifact_path, str) and artifact_path.strip():
            try:
                (Path(ARTIFACT_DIR) / Path(artifact_path).name).unlink(missing_ok=True)
            except Exception:
                pass
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


_SUPPORTED_SCAN_ENGINES = {"content", "reputation", "urlscan", "urlhaus"}


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
    if not engines:
        engines = ["reputation", "content"]
    if "reputation" not in engines:
        engines.insert(0, "reputation")
    return engines


_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{1000,}={0,2})")
_PASSWORD_RE = re.compile(r"type\s*=\s*['\"]?password['\"]?", re.IGNORECASE)
_FORM_RE = re.compile(r"<\s*form\b", re.IGNORECASE)
_META_REFRESH_RE = re.compile(r"http-equiv\s*=\s*['\"]refresh['\"]", re.IGNORECASE)


def _content_scan(
    content: bytes, *, url: str, download: Optional[dict] = None
) -> tuple[dict, list[Signal]]:
    content_type = ""
    if isinstance(download, dict):
        ct = download.get("content_type")
        if isinstance(ct, str) and ct:
            content_type = ct.strip().lower()

    sample = content[: max(0, CONTENT_MAX_TEXT_BYTES)]
    text = ""
    try:
        text = sample.decode("utf-8", "replace")
    except Exception:
        try:
            text = sample.decode("latin-1", "replace")
        except Exception:
            text = ""

    has_form = bool(text and _FORM_RE.search(text))
    has_password = bool(text and _PASSWORD_RE.search(text))
    has_meta_refresh = bool(text and _META_REFRESH_RE.search(text))

    primitives = [
        "eval(",
        "unescape(",
        "fromcharcode",
        "atob(",
        "btoa(",
    ]
    primitive_hits = [p for p in primitives if text and p in text.lower()]

    b64_max_len = 0
    if text:
        m = _B64_RE.search(text)
        if m:
            b64_max_len = min(len(m.group(0)), CONTENT_MAX_BASE64_MATCH)

    features = {
        "content_type": content_type,
        "text_bytes_scanned": len(sample),
        "has_form": has_form,
        "has_password_field": has_password,
        "has_meta_refresh": has_meta_refresh,
        "js_obfuscation_primitives": primitive_hits[:10],
        "base64_blob_max_len": b64_max_len,
    }

    signals: list[Signal] = []

    if has_form and has_password:
        signals.append(
            signal(
                source="content.password_form",
                verdict="suspicious",
                severity="high",
                weight=80,
                evidence={
                    "reason": "HTML contains a password form (possible phishing/login capture)",
                    "url": url,
                },
            )
        )

    if has_meta_refresh:
        signals.append(
            signal(
                source="content.meta_refresh",
                verdict="suspicious",
                severity="medium",
                weight=50,
                evidence={"reason": "HTML contains a meta refresh redirect", "url": url},
            )
        )

    if len(primitive_hits) >= 2:
        signals.append(
            signal(
                source="content.js_obfuscation",
                verdict="suspicious",
                severity="medium",
                weight=60,
                evidence={
                    "reason": "JavaScript contains common obfuscation primitives",
                    "matches": primitive_hits[:10],
                    "url": url,
                },
            )
        )

    if b64_max_len >= 5000:
        signals.append(
            signal(
                source="content.large_base64",
                verdict="suspicious",
                severity="low",
                weight=40,
                evidence={
                    "reason": "Response contains a large base64 blob (possible obfuscation/embedding)",
                    "max_len": b64_max_len,
                    "url": url,
                },
            )
        )

    if not signals:
        signals.append(
            signal(
                source="content.ok",
                verdict="benign",
                severity="info",
                weight=10,
                evidence={"reason": "No suspicious content indicators found", "url": url},
            )
        )

    return {"content": features}, signals


def _urlscan_scan(target_url: str) -> tuple[dict, list[Signal]]:
    # urlscan.io is an external service; avoid failing the whole scan if it's misconfigured.
    if not URLSCAN_API_KEY:
        return (
            {"status": "skipped", "reason": "URLSCAN_API_KEY not configured"},
            [
                signal(
                    source="urlscan.skipped",
                    verdict="benign",
                    severity="info",
                    weight=0,
                    evidence={"reason": "urlscan.io skipped (missing URLSCAN_API_KEY)"},
                )
            ],
        )

    if not URLSCAN_BASE_URL:
        return (
            {"status": "skipped", "reason": "URLSCAN_BASE_URL not configured"},
            [
                signal(
                    source="urlscan.skipped",
                    verdict="benign",
                    severity="info",
                    weight=0,
                    evidence={"reason": "urlscan.io skipped (missing URLSCAN_BASE_URL)"},
                )
            ],
        )

    def _headers() -> dict:
        return {
            "Accept": "application/json",
            "User-Agent": "aca-url-scanner/1.0",
            "API-Key": URLSCAN_API_KEY,
        }

    def _safe_json(resp: requests.Response) -> dict:
        try:
            doc = resp.json()
        except Exception:
            return {}
        return doc if isinstance(doc, dict) else {"value": doc}

    summary: dict = {
        "status": "error",
        "visibility": URLSCAN_VISIBILITY,
    }
    sigs: list[Signal] = []

    session = requests.Session()
    try:
        submit_url = f"{URLSCAN_BASE_URL}/scan/"
        payload = {"url": target_url, "visibility": URLSCAN_VISIBILITY}
        submit = session.post(
            submit_url,
            json=payload,
            headers=_headers(),
            timeout=max(1, int(URLSCAN_TIMEOUT_SECONDS or 10)),
        )
        if submit.status_code == 429:
            raise RuntimeError("rate_limited")
        submit.raise_for_status()
        submit_doc = _safe_json(submit)

        uuid = submit_doc.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            task = submit_doc.get("task") if isinstance(submit_doc.get("task"), dict) else {}
            uuid = task.get("uuid") if isinstance(task.get("uuid"), str) else ""
        uuid = str(uuid or "").strip()
        if not uuid:
            raise RuntimeError("missing_uuid")

        result_url = submit_doc.get("result")
        api_url = submit_doc.get("api")
        if isinstance(result_url, str) and result_url.strip():
            summary["result_url"] = result_url.strip()
        if isinstance(api_url, str) and api_url.strip():
            summary["api_url"] = api_url.strip()
        summary["uuid"] = uuid

        result_endpoint = f"{URLSCAN_BASE_URL}/result/{uuid}/"
        started = time.monotonic()
        last_status = None
        while True:
            resp = session.get(
                result_endpoint,
                headers=_headers(),
                timeout=max(1, int(URLSCAN_TIMEOUT_SECONDS or 10)),
            )
            last_status = resp.status_code
            if resp.status_code == 200:
                result_doc = _safe_json(resp)
                verdicts = (
                    result_doc.get("verdicts")
                    if isinstance(result_doc.get("verdicts"), dict)
                    else {}
                )
                overall = (
                    verdicts.get("overall")
                    if isinstance(verdicts.get("overall"), dict)
                    else {}
                )

                malicious_flag = overall.get("malicious")
                malicious = (
                    bool(malicious_flag)
                    if isinstance(malicious_flag, bool)
                    else None
                )
                raw_score = overall.get("score")
                score: Optional[int] = None
                if isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool):
                    score = int(raw_score)
                elif isinstance(raw_score, str) and raw_score.strip().lstrip("-").isdigit():
                    score = int(raw_score)

                raw_categories = overall.get("categories")
                categories: list[str] = []
                if isinstance(raw_categories, list):
                    for c in raw_categories:
                        if isinstance(c, str) and c.strip():
                            categories.append(c.strip())
                        if len(categories) >= 10:
                            break

                verdict = "benign"
                if malicious is True:
                    verdict = "malicious"
                elif score is not None and score >= int(URLSCAN_MALICIOUS_SCORE):
                    verdict = "malicious"
                elif categories:
                    verdict = "suspicious"
                elif score is not None and score >= int(URLSCAN_SUSPICIOUS_SCORE):
                    verdict = "suspicious"

                summary["status"] = "ok"
                summary["verdict"] = verdict
                if malicious is not None:
                    summary["malicious"] = malicious
                if score is not None:
                    summary["score"] = score
                if categories:
                    summary["categories"] = categories

                if verdict == "malicious":
                    sev, weight = "high", 80
                elif verdict == "suspicious":
                    sev, weight = "medium", 40
                else:
                    sev, weight = "info", 10

                sigs.append(
                    signal(
                        source="urlscan.verdict",
                        verdict=verdict,
                        severity=sev,
                        weight=weight,
                        evidence={
                            "reason": "urlscan.io verdict",
                            "verdict": verdict,
                            "score": score,
                            "categories": categories,
                            "result_url": summary.get("result_url"),
                            "uuid": uuid,
                        },
                    )
                )
                break

            if resp.status_code in (404, 202):
                if int(time.monotonic() - started) >= int(URLSCAN_MAX_WAIT_SECONDS):
                    raise TimeoutError("urlscan_result_timeout")
                time.sleep(max(1, int(URLSCAN_POLL_INTERVAL_SECONDS or 2)))
                continue

            if resp.status_code == 429:
                raise RuntimeError("rate_limited")

            # Other non-200 responses are treated as non-fatal engine errors.
            raise RuntimeError(f"result_http_{resp.status_code}")

        return summary, sigs
    except Exception as e:
        summary["status"] = "error"
        summary["error"] = str(e)
        if last_status is not None:
            summary["last_status_code"] = int(last_status)
        sigs.append(
            signal(
                source="urlscan.error",
                verdict="benign",
                severity="info",
                weight=0,
                evidence={
                    "reason": "urlscan.io scan failed (non-fatal)",
                    "error": str(e),
                },
            )
        )
        return summary, sigs
    finally:
        try:
            session.close()
        except Exception:
            pass


def _urlhaus_scan(target_url: str) -> tuple[dict, list[Signal]]:
    if not URLHAUS_BASE_URL:
        return (
            {"status": "skipped", "reason": "URLHAUS_BASE_URL not configured"},
            [
                signal(
                    source="urlhaus.skipped",
                    verdict="benign",
                    severity="info",
                    weight=0,
                    evidence={"reason": "URLhaus lookup skipped (missing URLHAUS_BASE_URL)"},
                )
            ],
        )

    def _safe_json(resp: requests.Response) -> dict:
        try:
            doc = resp.json()
        except Exception:
            return {}
        return doc if isinstance(doc, dict) else {"value": doc}

    session = requests.Session()
    try:
        endpoint = f"{URLHAUS_BASE_URL}/url/"
        headers = {"Accept": "application/json", "User-Agent": "aca-url-scanner/1.0"}
        if URLHAUS_API_KEY:
            headers[URLHAUS_API_KEY_HEADER] = URLHAUS_API_KEY
        resp = session.post(
            endpoint,
            data={"url": target_url},
            headers=headers,
            timeout=max(1, int(URLHAUS_TIMEOUT_SECONDS or 10)),
        )
        resp.raise_for_status()
        doc = _safe_json(resp)
        query_status = str(doc.get("query_status") or "").strip().lower()

        summary: dict = {
            "status": "ok",
            "query_status": query_status,
        }

        if query_status == "no_results":
            summary["verdict"] = "benign"
            return summary, [
                signal(
                    source="urlhaus.no_results",
                    verdict="benign",
                    severity="info",
                    weight=0,
                    evidence={
                        "reason": "No match in URLhaus (not proof of safety)",
                        "url": target_url,
                    },
                )
            ]

        if query_status != "ok":
            summary["status"] = "error"
            summary["error"] = query_status or "unknown"
            return summary, [
                signal(
                    source="urlhaus.error",
                    verdict="benign",
                    severity="info",
                    weight=0,
                    evidence={
                        "reason": "URLhaus lookup failed (non-fatal)",
                        "query_status": query_status or None,
                        "url": target_url,
                    },
                )
            ]

        # query_status == ok -> treat as known-bad evidence
        reference = doc.get("urlhaus_reference")
        threat = doc.get("threat")
        url_status = doc.get("url_status")
        tags_raw = doc.get("tags")
        tags: list[str] = []
        if isinstance(tags_raw, list):
            for item in tags_raw:
                if isinstance(item, str) and item.strip():
                    tags.append(item.strip())
                if len(tags) >= 15:
                    break

        summary["verdict"] = "malicious"
        if isinstance(reference, str) and reference.strip():
            summary["reference"] = reference.strip()
        if isinstance(threat, str) and threat.strip():
            summary["threat"] = threat.strip()
        if isinstance(url_status, str) and url_status.strip():
            summary["url_status"] = url_status.strip()
        if tags:
            summary["tags"] = tags

        return summary, [
            signal(
                source="urlhaus.match",
                verdict="malicious",
                severity="high",
                weight=max(0, int(URLHAUS_MATCH_WEIGHT)),
                evidence={
                    "reason": "URL found in URLhaus (known bad)",
                    "reference": summary.get("reference"),
                    "threat": summary.get("threat"),
                    "url_status": summary.get("url_status"),
                    "tags": tags,
                    "url": target_url,
                },
            )
        ]
    except requests.HTTPError as e:
        resp = getattr(e, "response", None)
        status_code = getattr(resp, "status_code", None)
        snippet = ""
        try:
            body = getattr(resp, "text", "")
            if isinstance(body, str) and body.strip():
                snippet = body.strip()[:500]
        except Exception:
            snippet = ""

        details: dict = {"status": "error", "error": str(e)}
        if isinstance(status_code, int):
            details["status_code"] = status_code
        if snippet:
            details["response_snippet"] = snippet
        if status_code == 401 and not URLHAUS_API_KEY:
            details["hint"] = (
                "401 from URLhaus; if this endpoint requires auth in your environment, set URLHAUS_API_KEY and URLHAUS_API_KEY_HEADER"
            )
        return details, [
            signal(
                source="urlhaus.error",
                verdict="benign",
                severity="info",
                weight=0,
                evidence={
                    "reason": "URLhaus lookup failed (non-fatal)",
                    "error": str(e),
                    "status_code": status_code,
                    "url": target_url,
                },
            )
        ]
    except Exception as e:
        return {"status": "error", "error": str(e)}, [
            signal(
                source="urlhaus.error",
                verdict="benign",
                severity="info",
                weight=0,
                evidence={
                    "reason": "URLhaus lookup failed (non-fatal)",
                    "error": str(e),
                    "url": target_url,
                },
            )
        ]
    finally:
        try:
            session.close()
        except Exception:
            pass


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
        elif engine == "urlscan":
            scan_url = url
            if isinstance(download, dict):
                final_url = download.get("final_url")
                if isinstance(final_url, str) and final_url.strip():
                    scan_url = final_url.strip()
            urlscan_out, urlscan_signals = _urlscan_scan(scan_url)
            results["urlscan"] = urlscan_out
            signals.extend(urlscan_signals)
        elif engine == "urlhaus":
            scan_url = url
            if isinstance(download, dict):
                final_url = download.get("final_url")
                if isinstance(final_url, str) and final_url.strip():
                    scan_url = final_url.strip()
            urlhaus_out, urlhaus_signals = _urlhaus_scan(scan_url)
            results["urlhaus"] = urlhaus_out
            signals.extend(urlhaus_signals)
        elif engine == "content":
            content_results, content_signals = _content_scan(
                content, url=url, download=download
            )
            results.update(content_results)
            signals.extend(content_signals)
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
) -> bool:
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
        if RESULT_BACKEND == "table" and not table_client:
            raise RuntimeError("Result store not initialized (table_client)")
        if RESULT_BACKEND == "redis" and not redis_client:
            raise RuntimeError("Result store not initialized (redis_client)")
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
        return True
    except Exception:
        logging.exception(
            "[worker] Failed to persist result (job_id=%s status=%s)", job_id, status
        )
        return False


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
