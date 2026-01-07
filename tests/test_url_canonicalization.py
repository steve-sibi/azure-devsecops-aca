from __future__ import annotations

import sys
from pathlib import Path

# The application code is built/run from within ./app in Docker; add it to sys.path for tests.
REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from common.url_canonicalization import canonicalize_url  # noqa: E402


def test_canonicalization_normalizes_and_strips_fragment_and_default_port():
    canon = canonicalize_url("HTTPS://ExAmple.COM:443/A/../B#Frag")
    assert canon.scheme == "https"
    assert canon.host_punycode == "example.com"
    assert canon.port is None
    assert canon.removed_fragment == "Frag"
    assert canon.canonical == "https://example.com/B"


def test_canonicalization_records_unicode_and_punycode():
    canon = canonicalize_url("https://bücher.example.com/")
    assert canon.host_unicode == "bücher.example.com"
    assert canon.host_punycode == "xn--bcher-kva.example.com"
    assert canon.canonical.startswith("https://xn--bcher-kva.example.com/")

