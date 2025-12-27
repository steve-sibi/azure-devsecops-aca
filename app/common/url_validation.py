from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlsplit


@dataclass
class UrlValidationError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


def _validate_https_url_shape(url: str) -> str:
    parsed = urlsplit(url)

    if parsed.scheme.lower() != "https" or not parsed.netloc:
        raise UrlValidationError(code="https_only", message="only https is allowed")

    host = parsed.hostname
    if not host:
        raise UrlValidationError(code="host_required", message="url host is required")

    if parsed.username or parsed.password:
        raise UrlValidationError(
            code="userinfo_not_allowed", message="userinfo in url is not allowed"
        )

    if parsed.port and parsed.port != 443:
        raise UrlValidationError(
            code="port_not_allowed", message="only default https port 443 is allowed"
        )

    if host.lower() == "localhost":
        raise UrlValidationError(code="localhost_not_allowed", message="localhost is not allowed")

    return host


def _validate_ips_are_public(
    ips: Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    if any(not ip.is_global for ip in ips):
        raise UrlValidationError(
            code="non_public_ip",
            message="destination resolves to a non-public ip address (blocked)",
        )


def validate_public_https_url(url: str, *, block_private_networks: bool = True) -> None:
    host = _validate_https_url_shape(url)

    if not block_private_networks:
        return

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        try:
            infos = socket.getaddrinfo(
                host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except socket.gaierror as e:
            raise UrlValidationError(code="dns_failed", message=f"dns resolution failed: {e}") from e

        ips = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not ips:
            raise UrlValidationError(code="no_records", message="no a/aaaa records found")
        _validate_ips_are_public(ips)
        return

    if not ip_literal.is_global:
        raise UrlValidationError(
            code="direct_ip_not_public",
            message="direct ip destinations must be publicly routable",
        )


async def validate_public_https_url_async(
    url: str, *, block_private_networks: bool = True
) -> None:
    host = _validate_https_url_shape(url)

    if not block_private_networks:
        return

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(
                host, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            )
        except socket.gaierror as e:
            raise UrlValidationError(code="dns_failed", message=f"dns resolution failed: {e}") from e

        ips = {ipaddress.ip_address(info[4][0]) for info in infos}
        if not ips:
            raise UrlValidationError(code="no_records", message="no a/aaaa records found")
        _validate_ips_are_public(ips)
        return

    if not ip_literal.is_global:
        raise UrlValidationError(
            code="direct_ip_not_public",
            message="direct ip destinations must be publicly routable",
        )
