from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal, Optional

Verdict = Literal["malicious", "suspicious", "benign", "error"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Action = Literal["block_download", "allow_download", "reputation_only"]


_SEVERITY_RANK: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _clamp_int(value: int, *, low: int, high: int) -> int:
    return max(low, min(high, int(value)))


def _normalize_verdict(value: str) -> Verdict:
    v = (value or "").strip().lower()
    if v in ("malicious", "suspicious", "benign", "error"):
        return v  # type: ignore[return-value]
    return "error"


def _normalize_severity(value: str) -> Severity:
    v = (value or "").strip().lower()
    if v in ("info", "low", "medium", "high", "critical"):
        return v  # type: ignore[return-value]
    return "info"


@dataclass(frozen=True)
class Signal:
    source: str
    verdict: Verdict
    severity: Severity
    weight: int
    evidence: Optional[dict[str, Any]] = None
    ttl: int = 0

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "source": self.source,
            "verdict": self.verdict,
            "severity": self.severity,
            "weight": int(self.weight),
            "ttl": int(self.ttl),
        }
        if self.evidence:
            out["evidence"] = self.evidence
        return out


@dataclass(frozen=True)
class Decision:
    final_verdict: Verdict
    confidence: int
    action: Action
    reasons: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "final_verdict": self.final_verdict,
            "confidence": int(self.confidence),
            "action": self.action,
            "reasons": list(self.reasons),
        }


def aggregate_signals(signals: Iterable[Signal]) -> Decision:
    sigs = list(signals)

    malicious = [s for s in sigs if s.verdict == "malicious"]
    suspicious = [s for s in sigs if s.verdict == "suspicious"]
    errors = [s for s in sigs if s.verdict == "error"]

    if malicious:
        final: Verdict = "malicious"
        contributing = malicious
    elif errors:
        final = "error"
        contributing = errors
    elif suspicious:
        final = "suspicious"
        contributing = suspicious
    else:
        final = "benign"
        contributing = [s for s in sigs if s.verdict == "benign"]

    # Deterministic confidence from the top 2 contributing weights.
    weights = sorted((max(0, int(s.weight)) for s in contributing), reverse=True)
    top = weights[0] if weights else 0
    second = weights[1] if len(weights) > 1 else 0
    confidence = _clamp_int(int(30 + 0.7 * top + 0.3 * second), low=0, high=100)
    if final == "error":
        confidence = _clamp_int(min(confidence, 30), low=0, high=100)
    if final == "benign" and not contributing:
        confidence = 70

    action: Action
    if final == "malicious":
        action = "block_download"
    elif final == "suspicious":
        action = "reputation_only"
    elif final == "benign":
        action = "allow_download"
    else:
        action = "block_download"

    def reason_for(sig: Signal) -> str:
        ev = sig.evidence or {}
        msg = ev.get("reason") or ev.get("description")
        if isinstance(msg, str) and msg:
            return msg
        if sig.source:
            return sig.source
        return "signal"

    # Explainability: include highest-severity/weight reasons first, de-duped.
    sorted_for_reasons = sorted(
        sigs,
        key=lambda s: (
            _SEVERITY_RANK.get(s.severity, 0),
            int(s.weight),
            s.source,
        ),
        reverse=True,
    )
    reasons: list[str] = []
    seen: set[str] = set()
    for sig in sorted_for_reasons:
        if sig.verdict == "benign" and final in ("malicious", "suspicious"):
            continue
        r = reason_for(sig)
        if r in seen:
            continue
        seen.add(r)
        reasons.append(r)
        if len(reasons) >= 12:
            break

    return Decision(final_verdict=final, confidence=confidence, action=action, reasons=reasons)


def signal(
    *,
    source: str,
    verdict: str,
    severity: str,
    weight: int,
    evidence: Optional[dict[str, Any]] = None,
    ttl: Optional[int] = None,
) -> Signal:
    return Signal(
        source=str(source or "").strip() or "unknown",
        verdict=_normalize_verdict(verdict),
        severity=_normalize_severity(severity),
        weight=int(weight),
        evidence=evidence,
        ttl=int(ttl) if ttl is not None else 0,
    )
