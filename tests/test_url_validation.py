from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from common.url_validation import (  # noqa: E402
    UrlValidationError,
    validate_public_https_url,
    validate_public_https_url_async,
)


def test_allows_https_public_ip_literal():
    validate_public_https_url("https://8.8.8.8")


def test_requires_https():
    with pytest.raises(UrlValidationError) as exc:
        validate_public_https_url("http://8.8.8.8")
    assert exc.value.code == "https_only"


def test_blocks_userinfo():
    with pytest.raises(UrlValidationError) as exc:
        validate_public_https_url("https://user:pass@8.8.8.8")
    assert exc.value.code == "userinfo_not_allowed"


def test_blocks_non_443_port():
    with pytest.raises(UrlValidationError) as exc:
        validate_public_https_url("https://8.8.8.8:8443")
    assert exc.value.code == "port_not_allowed"


def test_blocks_localhost_hostname():
    with pytest.raises(UrlValidationError) as exc:
        validate_public_https_url("https://localhost")
    assert exc.value.code == "localhost_not_allowed"


def test_blocks_loopback_ip_literal_when_private_networks_blocked():
    with pytest.raises(UrlValidationError) as exc:
        validate_public_https_url("https://127.0.0.1")
    assert exc.value.code == "direct_ip_not_public"


def test_allows_loopback_ip_literal_when_private_networks_not_blocked():
    validate_public_https_url("https://127.0.0.1", block_private_networks=False)


def test_async_variant_allows_https_public_ip_literal():
    asyncio.run(validate_public_https_url_async("https://8.8.8.8"))

