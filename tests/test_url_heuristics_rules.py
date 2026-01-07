from __future__ import annotations

import sys
from pathlib import Path

import pytest

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.url_canonicalization import canonicalize_url  # noqa: E402
from common.url_heuristics import evaluate_url_heuristics, load_rules  # noqa: E402


def _matched_rule_names(result) -> set[str]:
    return {
        str(r.get("name"))
        for r in (result.matched_rules or [])
        if isinstance(r, dict) and r.get("name")
    }


def test_rules_file_loads():
    rules = load_rules()
    assert rules
    names = [r.get("name") for r in rules if isinstance(r, dict)]
    assert len(names) == len(set(names))


@pytest.mark.parametrize(
    ("url", "rule_name", "env"),
    [
        ("https://user:pass@example.com/", "userinfo_in_url", {}),
        ("https://8.8.8.8/", "ip_literal_host", {}),
        ("https://0x7f000001/", "ip_encoded_host", {}),
        ("https://a.b.c.d.e.f.example.com/", "many_subdomains", {}),
        ("https://xn--pple-43d.com/", "punycode_label", {}),
        ("https://mіcrosoft.com/", "mixed_script_host", {}),  # cyrillic "і"
        ("https://x1y2z3a4b5c6d7e8f9t0.example/", "high_entropy_host", {}),
        ("https://example.com/AbCdEfGhIjKlMnOpQrStUvWxYz/", "high_entropy_path", {}),
        ("https://microsoft-login.example.com/", "brand_mismatch_microsoft", {}),
        ("https://example.zip/", "suspicious_tld", {"REPUTATION_SUSPICIOUS_TLDS": "zip,top"}),
        ("https://example.com/?redirect=https%3A%2F%2Fevil.test%2F", "open_redirect_params", {}),
        ("https://example.com/" + ("a" * 220), "very_long_url", {}),
        ("https://example.com/?" + ("q=" + ("a" * 200)), "very_long_query", {}),
        ("https://example.com/file.exe", "download_extension", {}),
    ],
)
def test_each_rule_matches(url: str, rule_name: str, env: dict):
    canon = canonicalize_url(url)
    result = evaluate_url_heuristics(
        canon,
        env={
            "REPUTATION_MIN_SCORE": "60",
            "REPUTATION_SUSPICIOUS_SCORE": "30",
            "REPUTATION_SUSPICIOUS_TLDS": env.get("REPUTATION_SUSPICIOUS_TLDS", ""),
        },
    )
    assert rule_name in _matched_rule_names(result)

