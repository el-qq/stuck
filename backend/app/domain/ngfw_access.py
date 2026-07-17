"""Validation and enforcement for operator-configured NGFW destinations."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Iterable

from ..errors import StuckError

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def normalize_server(raw: str) -> str:
    """Validate a bare IPv4/hostname and normalize it for policy matching."""

    text = (raw or "").strip()
    if not text:
        raise StuckError("invalid_server_address", "Server address is empty")

    def reject(reason: str) -> StuckError:
        return StuckError(
            "invalid_server_address",
            f"Server must be a bare IP or domain without port/scheme/path: {reason}",
            details={"value": raw},
        )

    if "://" in text:
        raise reject("scheme is not allowed")
    if ":" in text:
        raise reject("port is not allowed")
    if "/" in text:
        raise reject("path is not allowed")
    if any(ch.isspace() for ch in text):
        raise reject("whitespace is not allowed")

    host = text.lower().rstrip(".")
    if not host:
        raise reject("empty host")
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", host):
        raise reject("not a valid IPv4 address")
    if not _HOSTNAME_RE.match(host):
        raise reject("not a valid hostname")
    return host


def parse_allowed_hosts(raw: str) -> frozenset[str]:
    """Parse and validate a comma-separated exact host allowlist."""

    hosts: set[str] = set()
    for value in raw.split(","):
        if not value.strip():
            continue
        try:
            host = normalize_server(value)
        except StuckError as exc:
            raise ValueError(f"invalid STUCK_ALLOWED_NGFW_HOSTS entry: {value!r}") from exc
        if host == "localhost" or host.endswith(".localhost"):
            raise ValueError("loopback hostnames are not allowed")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            reason = unsafe_address_reason(address)
            if reason:
                raise ValueError(f"unsafe allowed NGFW host {host}: {reason}")
        hosts.add(host)
    return frozenset(hosts)


def parse_allowed_networks(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse and validate comma-separated IPv4/IPv6 CIDRs."""

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid STUCK_ALLOWED_NGFW_CIDRS entry: {candidate!r}") from exc
        reason = unsafe_address_reason(network.network_address)
        if reason:
            raise ValueError(f"unsafe allowed NGFW network {network}: {reason}")
        networks.append(network)
    return tuple(networks)


def unsafe_address_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address.is_loopback:
        return "loopback addresses are forbidden"
    if address.is_link_local:
        return "link-local addresses are forbidden"
    if address.is_multicast:
        return "multicast addresses are forbidden"
    if address.is_unspecified:
        return "unspecified addresses are forbidden"
    return None


def _in_allowed_networks(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _denied(server: str, reason: str) -> StuckError:
    return StuckError(
        "ngfw_host_not_allowed",
        "The NGFW host is not allowed by this STUCK installation",
        details={"server": server, "reason": reason},
    )


async def resolve_host_addresses(server: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname once for policy evaluation."""

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(server, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise StuckError(
            "server_unreachable",
            "Could not resolve the NGFW hostname",
            details={"server": server},
        ) from exc
    addresses = {ipaddress.ip_address(info[4][0]) for info in infos if info[4] and info[4][0]}
    if not addresses:
        raise StuckError(
            "server_unreachable",
            "The NGFW hostname resolved to no addresses",
            details={"server": server},
        )
    return addresses


async def enforce_ngfw_access(
    server: str,
    *,
    port: int,
    allow_any: bool,
    allowed_hosts: frozenset[str],
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> None:
    """Reject a destination before any NGFW HTTP request is attempted."""

    try:
        literal = ipaddress.ip_address(server)
    except ValueError:
        literal = None

    if literal is not None:
        reason = unsafe_address_reason(literal)
        if reason:
            raise _denied(server, reason)
        if allow_any or server in allowed_hosts or _in_allowed_networks(literal, allowed_networks):
            return
        raise _denied(server, "address is outside the configured allowlist")

    if server == "localhost" or server.endswith(".localhost"):
        raise _denied(server, "loopback hostnames are forbidden")
    exact_allowed = server in allowed_hosts
    if not allow_any and not exact_allowed and not allowed_networks:
        raise _denied(server, "hostname is absent from STUCK_ALLOWED_NGFW_HOSTS")

    addresses = await resolve_host_addresses(server, port)
    for address in addresses:
        reason = unsafe_address_reason(address)
        if reason:
            raise _denied(server, reason)
    if allow_any or exact_allowed:
        return
    for address in addresses:
        if not _in_allowed_networks(address, allowed_networks):
            raise _denied(server, f"resolved address {address} is outside the configured CIDRs")
